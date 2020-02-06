// SPDX-License-Identifier: GPL-2.0-or-later
/* Read helper.
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL OPERATION
#include <linux/module.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/fscache-cache.h>
#include "internal.h"
#define CREATE_TRACE_POINTS
#include <trace/events/fscache_support.h>

#define FSCACHE_RHLP_NOTE_READ_FROM_CACHE	FSCACHE_READ_FROM_CACHE
#define FSCACHE_RHLP_NOTE_WRITE_TO_CACHE	FSCACHE_WRITE_TO_CACHE
#define FSCACHE_RHLP_NOTE_FILL_WITH_ZERO	FSCACHE_FILL_WITH_ZERO
#define FSCACHE_RHLP_NOTE_READ_FOR_WRITE	0x00000100 /* Type: FSCACHE_READ_FOR_WRITE */
#define FSCACHE_RHLP_NOTE_READ_LOCKED_PAGE	0x00000200 /* Type: FSCACHE_READ_LOCKED_PAGE */
#define FSCACHE_RHLP_NOTE_READ_PAGE_LIST	0x00000300 /* Type: FSCACHE_READ_PAGE_LIST */
#define FSCACHE_RHLP_NOTE_LIST_NOMEM		0x00001000 /* Page list: ENOMEM */
#define FSCACHE_RHLP_NOTE_LIST_U2D		0x00002000 /* Page list: page uptodate */
#define FSCACHE_RHLP_NOTE_LIST_ERROR		0x00004000 /* Page list: add error */
#define FSCACHE_RHLP_NOTE_TRAILER_ADD		0x00010000 /* Trailer: Creating */
#define FSCACHE_RHLP_NOTE_TRAILER_NOMEM		0x00020000 /* Trailer: ENOMEM */
#define FSCACHE_RHLP_NOTE_TRAILER_U2D		0x00040000 /* Trailer: Uptodate */
#define FSCACHE_RHLP_NOTE_U2D_IN_PREFACE	0x00100000 /* Uptodate page in preface */
#define FSCACHE_RHLP_NOTE_UNDERSIZED		0x00200000 /* Undersized block */
#define FSCACHE_RHLP_NOTE_AFTER_EOF		0x00400000 /* After EOF */
#define FSCACHE_RHLP_NOTE_DO_WRITE_TO_CACHE	0x00800000 /* Actually write to the cache */
#define FSCACHE_RHLP_NOTE_CANCELLED		0x80000000 /* Operation cancelled by netfs */

enum fscache_read_type {
	FSCACHE_READ_PAGE_LIST,		/* Read the list of pages (readpages) */
	FSCACHE_READ_LOCKED_PAGE,	/* requested_page is added and locked */
	FSCACHE_READ_FOR_WRITE,		/* This read is a prelude to write_begin */
};

static void fscache_read_from_server(struct fscache_io_request *req)
{
	req->ops->issue_op(req);
}

/*
 * Issue a read against the cache.
 */
static void fscache_read_from_cache(struct fscache_io_request *req)
{
	struct iov_iter iter;

	iov_iter_mapping(&iter, READ, req->mapping, req->pos, req->len);
	fscache_read(req, &iter);
}

/*
 * Deal with the completion of writing the data to the cache.  We have to clear
 * the PG_fscache bits on the pages involved and releases the caller's ref.
 */
static void fscache_read_copy_done(struct fscache_io_request *req)
{
	struct page *page;
	pgoff_t index = req->pos >> PAGE_SHIFT;
	pgoff_t last = index + req->nr_pages - 1;

	XA_STATE(xas, &req->mapping->i_pages, index);

	_enter("%lx,%x,%llx", index, req->nr_pages, req->transferred);

	if (req->error == 0)
		fscache_stat(&fscache_n_read_helper_copy_done);
	else
		fscache_stat(&fscache_n_read_helper_copy_failed);

	/* Clear PG_fscache on the pages that were being written out. */
	rcu_read_lock();
	xas_for_each(&xas, page, last) {
		BUG_ON(xa_is_value(page));
		BUG_ON(PageCompound(page));

		unlock_page_fscache(page);
	}
	rcu_read_unlock();
}

/*
 * Write a completed read request to the cache.
 */
static void fscache_do_read_copy_to_cache(struct work_struct *work)
{
	struct fscache_io_request *req =
		container_of(work, struct fscache_io_request, work);
	struct iov_iter iter;

	_enter("");

	fscache_stat(&fscache_n_read_helper_copy);

	iov_iter_mapping(&iter, WRITE, req->mapping, req->pos,
			 round_up(req->len, req->dio_block_size));

	req->io_done = fscache_read_copy_done;
	fscache_write(req, &iter);
	fscache_put_io_request(req);
}

static void fscache_read_copy_to_cache(struct fscache_io_request *req)
{
	fscache_get_io_request(req);

	if (!in_softirq())
		return fscache_do_read_copy_to_cache(&req->work);

	BUG_ON(work_pending(&req->work));
	INIT_WORK(&req->work, fscache_do_read_copy_to_cache);
	if (!queue_work(fscache_op_wq, &req->work))
		BUG();
}

/*
 * Clear the unread part of the file on a short read.
 */
static void fscache_clear_unread(struct fscache_io_request *req)
{
	struct iov_iter iter;

	iov_iter_mapping(&iter, WRITE, req->mapping,
			 req->pos + req->transferred,
			 req->len - req->transferred);

	_debug("clear %zx @%llx", iov_iter_count(&iter), iter.mapping_start);

	iov_iter_zero(iov_iter_count(&iter), &iter);
}

/*
 * Handle completion of a read operation.  This may be called in softirq
 * context.
 */
static void fscache_read_done(struct fscache_io_request *req)
{
	struct page *page;
	pgoff_t start = req->pos >> PAGE_SHIFT;
	pgoff_t last = start + req->nr_pages - 1;

	XA_STATE(xas, &req->mapping->i_pages, start);

	_enter("%lx,%x,%llx,%d",
	       start, req->nr_pages, req->transferred, req->error);

	if (req->error == 0)
		fscache_stat(&fscache_n_read_helper_read_done);
	else
		fscache_stat(&fscache_n_read_helper_read_failed);

	if (req->transferred < req->len)
		fscache_clear_unread(req);

	if (!test_bit(FSCACHE_IO_DONT_UNLOCK_PAGES, &req->flags)) {
		rcu_read_lock();
		xas_for_each(&xas, page, last) {
			if (test_bit(FSCACHE_IO_WRITE_TO_CACHE, &req->flags))
				SetPageFsCache(page);
			if (page == req->no_unlock_page)
				SetPageUptodate(page);
			else
				page_endio(page, false, 0);
			put_page(page);
		}
		rcu_read_unlock();
	}

	task_io_account_read(req->transferred);
	req->ops->done(req);
	if (test_and_clear_bit(FSCACHE_IO_READ_IN_PROGRESS, &req->flags))
		wake_up_bit(&req->flags, FSCACHE_IO_READ_IN_PROGRESS);

	if (test_bit(FSCACHE_IO_WRITE_TO_CACHE, &req->flags))
		fscache_read_copy_to_cache(req);
}

/*
 * Reissue the read against the server.
 */
static void fscache_reissue_read(struct work_struct *work)
{
	struct fscache_io_request *req =
		container_of(work, struct fscache_io_request, work);
	pgoff_t start = req->pos >> PAGE_SHIFT;

	_enter("%llu,%llu/%llu", req->pos, req->transferred, req->len);

	if (test_and_clear_bit(FSCACHE_IO_SHORT_READ, &req->flags)) {
		set_bit(FSCACHE_IO_SEEK_DATA_READ, &req->flags);
		trace_fscache_read_helper(req->cookie, start, start + req->nr_pages - 1,
					  req->error, fscache_read_helper_reissue_read);
		/* We're about to get another ref on the object */
		if (req->object)
			req->object->cache->ops->put_object(req->object,
							    fscache_obj_put_ioreq);
		fscache_read_from_cache(req);
		goto out;
	}

	if (req->pos >= req->cookie->zero_point) {
		trace_fscache_read_helper(req->cookie, start, start + req->nr_pages - 1,
					  req->error, fscache_read_helper_reissue_zero);
		fscache_read_done(req);
	} else {
		trace_fscache_read_helper(req->cookie, start, start + req->nr_pages - 1,
					  req->error, fscache_read_helper_reissue_down);
		req->io_done = fscache_read_done;
		fscache_read_from_server(req);
	}

out:
	fscache_put_io_request(req);
}

/*
 * Handle completion of a read from cache operation.  If the read failed, we
 * need to reissue the request against the server.  We might, however, be
 * called in softirq mode and need to punt.
 */
static void fscache_file_read_maybe_reissue(struct fscache_io_request *req)
{
	_enter("%d", req->error);

	if (req->error == 0 && !test_bit(FSCACHE_IO_SHORT_READ, &req->flags)) {
		fscache_read_done(req);
	} else {
		fscache_stat(&fscache_n_read_helper_reissue);
		INIT_WORK(&req->work, fscache_reissue_read);
		fscache_get_io_request(req);
		if (!queue_work(fscache_op_wq, &req->work)) {
			WARN_ON(1);
			fscache_put_io_request(req);
		}
	}
}

/*
 * Discard the locks and page refs that we obtained on a sequence of pages.
 */
static void fscache_ignore_pages(struct address_space *mapping,
				  pgoff_t start, pgoff_t end)
{
	struct page *page;

	_enter("%lx,%lx", start, end);

	if (end > start) {
		XA_STATE(xas, &mapping->i_pages, start);

		rcu_read_lock();
		xas_for_each(&xas, page, end - 1) {
			_debug("- ignore %lx", page->index);
			BUG_ON(xa_is_value(page));
			BUG_ON(PageCompound(page));

			unlock_page(page);
			put_page(page);
		}
		rcu_read_unlock();
	}
}

/**
 * fscache_read_helper - Helper to manage a read request
 * @req: The initialised request structure to use
 * @requested_page: Singular page to include (LOCKED_PAGE/FOR_WRITE)
 * @pages: Unattached pages to include (PAGE_LIST)
 * @page_to_be_written: The index of the primary page (FOR_WRITE)
 * @max_pages: The maximum number of pages to read in one transaction
 * @type: FSCACHE_READ_*
 * @aop_flags: AOP_FLAG_*
 *
 * Read a sequence of pages appropriately sized for an fscache allocation
 * block.  Pages are added at both ends and to fill in the gaps as appropriate
 * to make it the right size.
 *
 * req->mapping should indicate the mapping to which the pages will be attached.
 *
 * The operations pointed to by req->ops will be used to issue or reissue a
 * read against the server in case the cache is unavailable, incomplete or
 * generates an error.  req->iter will be set up to point to the iterator
 * representing the buffer to be filled in.
 *
 * A ref on @req is consumed eventually by this function or one of its
 * eventually-dispatched callees.
 */
static int fscache_read_helper(struct fscache_io_request *req,
			       struct page **requested_page,
			       struct list_head *pages,
			       pgoff_t page_to_be_written,
			       pgoff_t max_pages,
			       enum fscache_read_type type,
			       unsigned int aop_flags)
{
	struct fscache_request_shape shape;
	struct address_space *mapping = req->mapping;
	struct page *page;
	enum fscache_read_helper_trace what;
	unsigned int notes;
	pgoff_t eof, cursor, start;
	int ret;

	fscache_stat(&fscache_n_read_helper);

	shape.granularity	= 1;
	shape.max_io_pages	= max_pages;
	shape.i_size		= i_size_read(mapping->host);
	shape.for_write		= false;

	switch (type) {
	case FSCACHE_READ_PAGE_LIST:
		shape.proposed_start = lru_to_page(pages)->index;
		shape.proposed_nr_pages =
			lru_to_last_page(pages)->index - shape.proposed_start + 1;
		break;

	case FSCACHE_READ_LOCKED_PAGE:
		shape.proposed_start = (*requested_page)->index;
		shape.proposed_nr_pages = 1;
		break;

	case FSCACHE_READ_FOR_WRITE:
		shape.proposed_start = page_to_be_written;
		shape.proposed_nr_pages = 1;
		break;

	default:
		BUG();
	}

	_enter("%lx,%x", shape.proposed_start, shape.proposed_nr_pages);

	eof = (shape.i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	fscache_shape_request(req->cookie, &shape);
	if (req->ops->reshape)
		req->ops->reshape(req, &shape);
	notes = shape.to_be_done;

	req->dio_block_size = shape.dio_block_size;

	start = cursor = shape.actual_start;

	/* Add pages to the pagecache.  We keep the pages ref'd and locked
	 * until the read is complete.  We may also need to add pages to both
	 * sides of the request to make it up to the cache allocation granule
	 * alignment and size.
	 *
	 * Note that it's possible for the file size to change whilst we're
	 * doing this, but we rely on the server returning less than we asked
	 * for if the file shrank.  We also rely on this to deal with a partial
	 * page at the end of the file.
	 *
	 * If we're going to end up loading from the server and writing to the
	 * cache, we start by inserting blank pages before the first page being
	 * examined.  If we can fetch from the cache or we're not going to
	 * write to the cache, it's unnecessary.
	 */
	if (notes & FSCACHE_RHLP_NOTE_WRITE_TO_CACHE) {
		notes |= FSCACHE_RHLP_NOTE_DO_WRITE_TO_CACHE;
		while (cursor < shape.proposed_start) {
			page = find_or_create_page(mapping, cursor,
						   readahead_gfp_mask(mapping));
			if (!page) {
				fscache_stat(&fscache_n_read_helper_stop_nomem);
				goto nomem;
			}
			if (!PageUptodate(page)) {
				req->nr_pages++; /* Add to the reading list */
				cursor++;
				continue;
			}

			/* There's an up-to-date page in the preface - just
			 * fetch the requested pages and skip saving to the
			 * cache.
			 */
			notes |= FSCACHE_RHLP_NOTE_U2D_IN_PREFACE;
			notes &= ~FSCACHE_RHLP_NOTE_DO_WRITE_TO_CACHE;
			fscache_stat(&fscache_n_read_helper_stop_uptodate);
			fscache_ignore_pages(mapping, start, cursor + 1);
			start = cursor = shape.proposed_start;
			req->nr_pages = 0;
			break;
		}
		page = NULL;
	} else {
		notes &= ~FSCACHE_RHLP_NOTE_DO_WRITE_TO_CACHE;
		start = cursor = shape.proposed_start;
		req->nr_pages = 0;
	}

	switch (type) {
	case FSCACHE_READ_FOR_WRITE:
		/* We're doing a prefetch for a write on a single page.  We get
		 * or create the requested page if we weren't given it and lock
		 * it.
		 */
		notes |= FSCACHE_RHLP_NOTE_READ_FOR_WRITE;
		if (*requested_page) {
			_debug("prewrite req %lx", cursor);
			page = *requested_page;
			ret = -ERESTARTSYS;
			if (lock_page_killable(page) < 0) {
				fscache_stat(&fscache_n_read_helper_stop_kill);
				goto dont;
			}
		} else {
			_debug("prewrite new %lx %lx", cursor, eof);
			page = grab_cache_page_write_begin(mapping, shape.proposed_start,
							   aop_flags);
			if (!page) {
				fscache_stat(&fscache_n_read_helper_stop_nomem);
				goto nomem;
			}
			*requested_page = page;
		}

		if (PageUptodate(page)) {
			fscache_stat(&fscache_n_read_helper_stop_uptodate);
			notes |= FSCACHE_RHLP_NOTE_LIST_U2D;

			trace_fscache_read_helper(req->cookie,
						  start, start + req->nr_pages,
						  notes, fscache_read_helper_race);
			req->ops->done(req);
			ret = 0;
			goto cancelled;
		}

		get_page(page);
		req->no_unlock_page = page;
		req->nr_pages++;
		cursor++;
		page = NULL;
		ret = 0;
		break;

	case FSCACHE_READ_LOCKED_PAGE:
		/* We've got a single page preattached to the inode and locked.
		 * Get our own ref on it.
		 */
		_debug("locked");
		notes |= FSCACHE_RHLP_NOTE_READ_LOCKED_PAGE;
		get_page(*requested_page);
		req->nr_pages++;
		cursor++;
		ret = 0;
		break;

	case FSCACHE_READ_PAGE_LIST:
		/* We've been given a contiguous list of pages to add. */
		notes |= FSCACHE_RHLP_NOTE_READ_PAGE_LIST;
		do {
			_debug("given %lx", cursor);

			page = lru_to_page(pages);
			if (WARN_ON(page->index != cursor))
				break;

			list_del(&page->lru);

			ret = add_to_page_cache_lru(page, mapping, cursor,
						    readahead_gfp_mask(mapping));
			switch (ret) {
			case 0:
				/* Add to the reading list */
				req->nr_pages++;
				cursor++;
				page = NULL;
				break;

			case -EEXIST:
				put_page(page);

				_debug("conflict %lx %d", cursor, ret);
				page = find_or_create_page(mapping, cursor,
							   readahead_gfp_mask(mapping));
				if (!page) {
					notes |= FSCACHE_RHLP_NOTE_LIST_NOMEM;
					fscache_stat(&fscache_n_read_helper_stop_nomem);
					goto stop;
				}

				if (PageUptodate(page)) {
					unlock_page(page);
					put_page(page); /* Avoid overwriting */
					fscache_stat(&fscache_n_read_helper_stop_exist);
					ret = 0;
					notes |= FSCACHE_RHLP_NOTE_LIST_U2D;
					goto stop;
				}

				req->nr_pages++; /* Add to the reading list */
				cursor++;
				break;

			default:
				_debug("add fail %lx %d", cursor, ret);
				put_page(page);
				fscache_stat(&fscache_n_read_helper_stop_nomem);
				page = NULL;
				notes |= FSCACHE_RHLP_NOTE_LIST_ERROR;
				goto stop;
			}

			/* Trim the fetch to the cache granularity so we don't
			 * get a chain-failure of blocks being unable to be
			 * used because the previous uncached read spilt over.
			 */
			if ((notes & FSCACHE_RHLP_NOTE_U2D_IN_PREFACE) &&
			    cursor == shape.actual_start + shape.granularity)
				break;

		} while (!list_empty(pages) && req->nr_pages < shape.actual_nr_pages);
		ret = 0;
		break;

	default:
		BUG();
	}

	/* If we're going to be writing to the cache, insert pages after the
	 * requested block to make up the numbers.
	 */
	if (notes & FSCACHE_RHLP_NOTE_DO_WRITE_TO_CACHE) {
		notes |= FSCACHE_RHLP_NOTE_TRAILER_ADD;
		while (req->nr_pages < shape.actual_nr_pages) {
			_debug("after %lx", cursor);
			page = find_or_create_page(mapping, cursor,
						   readahead_gfp_mask(mapping));
			if (!page) {
				notes |= FSCACHE_RHLP_NOTE_TRAILER_NOMEM;
				fscache_stat(&fscache_n_read_helper_stop_nomem);
				goto stop;
			}
			if (PageUptodate(page)) {
				unlock_page(page);
				put_page(page); /* Avoid overwriting */
				notes |= FSCACHE_RHLP_NOTE_TRAILER_U2D;
				fscache_stat(&fscache_n_read_helper_stop_uptodate);
				goto stop;
			}

			req->nr_pages++; /* Add to the reading list */
			cursor++;
		}
	}

stop:
	_debug("have %u", req->nr_pages);
	if (req->nr_pages == 0)
		goto dont;

	if (cursor <= shape.proposed_start) {
		_debug("v.short");
		goto nomem_unlock; /* We wouldn't've included the first page */
	}

submit_anyway:
	if ((notes & FSCACHE_RHLP_NOTE_DO_WRITE_TO_CACHE) &&
	    req->nr_pages < shape.actual_nr_pages) {
		/* The request is short of what we need to be able to cache the
		 * entire set of pages and the trailer, so trim it to cache
		 * granularity if we can without reducing it to nothing.
		 */
		unsigned int down_to = round_down(req->nr_pages, shape.granularity);
		_debug("short %u", down_to);

		notes |= FSCACHE_RHLP_NOTE_UNDERSIZED;

		if (down_to > 0) {
			fscache_ignore_pages(mapping, shape.actual_start + down_to, cursor);
			req->nr_pages = down_to;
		} else {
			notes &= ~FSCACHE_RHLP_NOTE_DO_WRITE_TO_CACHE;
		}
	}

	req->len = req->nr_pages * PAGE_SIZE;
	req->pos = start;
	req->pos <<= PAGE_SHIFT;

	if (start >= eof) {
		notes |= FSCACHE_RHLP_NOTE_AFTER_EOF;
		what = fscache_read_helper_skip;
	} else if (notes & FSCACHE_RHLP_NOTE_FILL_WITH_ZERO) {
		what = fscache_read_helper_zero;
	} else if (notes & FSCACHE_RHLP_NOTE_READ_FROM_CACHE) {
		what = fscache_read_helper_read;
	} else {
		what = fscache_read_helper_download;
	}

	ret = 0;
	if (req->ops->is_req_valid) {
		/* Allow the netfs to decide if the request is still valid
		 * after all the pages are locked.
		 */
		ret = req->ops->is_req_valid(req);
		if (ret < 0)
			notes |= FSCACHE_RHLP_NOTE_CANCELLED;
	}

	trace_fscache_read_helper(req->cookie, start, start + req->nr_pages - 1,
				  notes, what);

	if (notes & FSCACHE_RHLP_NOTE_CANCELLED)
		goto cancelled;

	if (notes & FSCACHE_RHLP_NOTE_DO_WRITE_TO_CACHE)
		__set_bit(FSCACHE_IO_WRITE_TO_CACHE, &req->flags);

	__set_bit(FSCACHE_IO_READ_IN_PROGRESS, &req->flags);

	switch (what) {
	case fscache_read_helper_skip:
		/* The read is entirely beyond the end of the file, so skip the
		 * actual operation and let the done handler deal with clearing
		 * the pages.
		 */
		_debug("SKIP READ: %llu", req->len);
		fscache_stat(&fscache_n_read_helper_beyond_eof);
		fscache_read_done(req);
		break;
	case fscache_read_helper_zero:
		_debug("ZERO READ: %llu", req->len);
		fscache_stat(&fscache_n_read_helper_zero);
		fscache_read_done(req);
		break;
	case fscache_read_helper_read:
		fscache_stat(&fscache_n_read_helper_read);
		req->io_done = fscache_file_read_maybe_reissue;
		fscache_read_from_cache(req);
		break;
	case fscache_read_helper_download:
		_debug("DOWNLOAD: %llu", req->len);
		fscache_stat(&fscache_n_read_helper_download);
		req->io_done = fscache_read_done;
		fscache_read_from_server(req);
		break;
	default:
		BUG();
	}

	_leave(" = 0");
	return 0;

nomem:
	if (cursor > shape.proposed_start)
		goto submit_anyway;
nomem_unlock:
	ret = -ENOMEM;
cancelled:
	fscache_ignore_pages(mapping, start, cursor);
dont:
	_leave(" = %d", ret);
	return ret;
}

int fscache_read_helper_page_list(struct fscache_io_request *req,
				  struct list_head *pages,
				  pgoff_t max_pages)
{
	ASSERT(pages);
	ASSERT(!list_empty(pages));
	return fscache_read_helper(req, NULL, pages, 0, max_pages,
				   FSCACHE_READ_PAGE_LIST, 0);
}
EXPORT_SYMBOL(fscache_read_helper_page_list);

int fscache_read_helper_locked_page(struct fscache_io_request *req,
				    struct page *page,
				    pgoff_t max_pages)
{
	ASSERT(page);
	return fscache_read_helper(req, &page, NULL, 0, max_pages,
				   FSCACHE_READ_LOCKED_PAGE, 0);
}
EXPORT_SYMBOL(fscache_read_helper_locked_page);

int fscache_read_helper_for_write(struct fscache_io_request *req,
				  struct page **page,
				  pgoff_t index,
				  pgoff_t max_pages,
				  unsigned int aop_flags)
{
	ASSERT(page);
	ASSERTIF(*page, (*page)->index == index);
	return fscache_read_helper(req, page, NULL, index, max_pages,
				   FSCACHE_READ_FOR_WRITE, aop_flags);
}
EXPORT_SYMBOL(fscache_read_helper_for_write);
