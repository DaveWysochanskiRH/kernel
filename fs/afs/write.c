// SPDX-License-Identifier: GPL-2.0-or-later
/* handling of writes to regular files and writing back to the server
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/backing-dev.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include "internal.h"

static void afs_write_to_cache(struct afs_vnode *vnode,
			       pgoff_t start, pgoff_t end, loff_t a, loff_t b);

/*
 * mark a page as having been made dirty and thus needing writeback
 */
int afs_set_page_dirty(struct page *page)
{
	_enter("");
	return __set_page_dirty_nobuffers(page);
}

/*
 * prepare to perform part of a write to a page
 */
int afs_write_begin(struct file *file, struct address_space *mapping,
		    loff_t pos, unsigned len, unsigned flags,
		    struct page **pagep, void **fsdata)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	struct page *page;
	unsigned long priv;
	unsigned f, from = pos & (PAGE_SIZE - 1);
	unsigned t, to = from + len;
	pgoff_t index = pos >> PAGE_SHIFT;
	int ret;

	_enter("{%llx:%llu},{%lx},%u,%u",
	       vnode->fid.vid, vnode->fid.vnode, index, from, to);

	/* We want to store information about how much of a page is altered in
	 * page->private.
	 */
	BUILD_BUG_ON(PAGE_SIZE > 32768 && sizeof(page->private) < 8);

	/* Prefetch area to be written into the cache if we're caching this
	 * file.  We need to do this before we get a lock on the page in case
	 * there's more than one writer competing for the same cache block.
	 */
	page = afs_prefetch_for_write(file, mapping, index, flags);
	if (IS_ERR(page))
		return PTR_ERR(page);

	ASSERT(PageUptodate(page));

#ifdef CONFIG_AFS_FSCACHE
	wait_on_page_fscache(page);
#endif

	/* page won't leak in error case: it eventually gets cleaned off LRU */
	*pagep = page;

try_again:
	/* See if this page is already partially written in a way that we can
	 * merge the new write with.
	 */
	t = f = 0;
	if (PagePrivate(page)) {
		priv = page_private(page);
		f = priv & AFS_PRIV_MAX;
		t = priv >> AFS_PRIV_SHIFT;
		ASSERTCMP(f, <=, t);
	}

	if (f != t) {
		if (PageWriteback(page)) {
			trace_afs_page_dirty(vnode, tracepoint_string("alrdy"),
					     page->index, priv);
			goto flush_conflicting_write;
		}
		/* If the file is being filled locally, allow inter-write
		 * spaces to be merged into writes.  If it's not, only write
		 * back what the user gives us.
		 */
		if (!test_bit(AFS_VNODE_NEW_CONTENT, &vnode->flags) &&
		    (to < f || from > t))
			goto flush_conflicting_write;
		if (from < f)
			f = from;
		if (to > t)
			t = to;
	} else {
		f = from;
		t = to;
	}

	priv = (unsigned long)t << AFS_PRIV_SHIFT;
	priv |= f;
	trace_afs_page_dirty(vnode, tracepoint_string("begin"),
			     page->index, priv);
	SetPagePrivate(page);
	set_page_private(page, priv);
	_leave(" = 0");
	return 0;

	/* The previous write and this write aren't adjacent or overlapping, so
	 * flush the page out.
	 */
flush_conflicting_write:
	_debug("flush conflict");
	ret = write_one_page(page);
	if (ret < 0) {
		_leave(" = %d", ret);
		return ret;
	}

	ret = lock_page_killable(page);
	if (ret < 0) {
		_leave(" = %d", ret);
		return ret;
	}
	goto try_again;
}

/*
 * finalise part of a write to a page
 */
int afs_write_end(struct file *file, struct address_space *mapping,
		  loff_t pos, unsigned len, unsigned copied,
		  struct page *page, void *fsdata)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	loff_t i_size, write_end_pos;

	_enter("{%llx:%llu},{%lx}",
	       vnode->fid.vid, vnode->fid.vnode, page->index);

	write_end_pos = pos + copied;

	i_size = i_size_read(&vnode->vfs_inode);
	if (write_end_pos > i_size) {
		write_seqlock(&vnode->cb_lock);
		i_size = i_size_read(&vnode->vfs_inode);
		if (write_end_pos > i_size)
			i_size_write(&vnode->vfs_inode, write_end_pos);
		write_sequnlock(&vnode->cb_lock);
		fscache_update_cookie(afs_vnode_cache(vnode), NULL, &write_end_pos);
	}

	ASSERT(PageUptodate(page));

	set_page_dirty(page);
	if (PageDirty(page))
		_debug("dirtied");

	unlock_page(page);
	put_page(page);
	return copied;
}

/*
 * kill all the pages in the given range
 */
static void afs_kill_pages(struct address_space *mapping,
			   pgoff_t first, pgoff_t last)
{
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct pagevec pv;
	unsigned count, loop;

	_enter("{%llx:%llu},%lx-%lx",
	       vnode->fid.vid, vnode->fid.vnode, first, last);

	pagevec_init(&pv);

	do {
		_debug("kill %lx-%lx", first, last);

		count = last - first + 1;
		if (count > PAGEVEC_SIZE)
			count = PAGEVEC_SIZE;
		pv.nr = find_get_pages_contig(mapping, first, count, pv.pages);
		ASSERTCMP(pv.nr, ==, count);

		for (loop = 0; loop < count; loop++) {
			struct page *page = pv.pages[loop];
			ClearPageUptodate(page);
			SetPageError(page);
			end_page_writeback(page);
			if (page->index >= first)
				first = page->index + 1;
			lock_page(page);
			generic_error_remove_page(mapping, page);
			unlock_page(page);
		}

		__pagevec_release(&pv);
	} while (first <= last);

	_leave("");
}

/*
 * Redirty all the pages in a given range.
 */
static void afs_redirty_pages(struct writeback_control *wbc,
			      struct address_space *mapping,
			      pgoff_t first, pgoff_t last)
{
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct pagevec pv;
	unsigned count, loop;

	_enter("{%llx:%llu},%lx-%lx",
	       vnode->fid.vid, vnode->fid.vnode, first, last);

	pagevec_init(&pv);

	do {
		_debug("redirty %lx-%lx", first, last);

		count = last - first + 1;
		if (count > PAGEVEC_SIZE)
			count = PAGEVEC_SIZE;
		pv.nr = find_get_pages_contig(mapping, first, count, pv.pages);
		ASSERTCMP(pv.nr, ==, count);

		for (loop = 0; loop < count; loop++) {
			struct page *page = pv.pages[loop];

			redirty_page_for_writepage(wbc, page);
			end_page_writeback(page);
			if (page->index >= first)
				first = page->index + 1;
		}

		__pagevec_release(&pv);
	} while (first <= last);

	_leave("");
}

/*
 * completion of write to server
 */
static void afs_pages_written_back(struct afs_vnode *vnode, pgoff_t start, pgoff_t last)
{
	struct address_space *mapping = vnode->vfs_inode.i_mapping;
	struct page *page;
	unsigned long priv;

	XA_STATE(xas, &mapping->i_pages, start);

	_enter("{%llx:%llu},{%lx-%lx}",
	       vnode->fid.vid, vnode->fid.vnode, start, last);

	rcu_read_lock();

	xas_for_each(&xas, page, last) {
		ASSERT(PageWriteback(page));

		priv = page_private(page);
		trace_afs_page_dirty(vnode, tracepoint_string("clear"),
				     page->index, priv);
		set_page_private(page, 0);
		page_endio(page, true, 0);
	}

	rcu_read_unlock();

	afs_prune_wb_keys(vnode);
	_leave("");
}

/*
 * Find a key to use for the writeback.  We cached the keys used to author the
 * writes on the vnode.  *_wbk will contain the last writeback key used or NULL
 * and we need to start from there if it's set.
 */
static int afs_get_writeback_key(struct afs_vnode *vnode,
				 struct afs_wb_key **_wbk)
{
	struct afs_wb_key *wbk = NULL;
	struct list_head *p;
	int ret = -ENOKEY, ret2;

	spin_lock(&vnode->wb_lock);
	if (*_wbk)
		p = (*_wbk)->vnode_link.next;
	else
		p = vnode->wb_keys.next;

	while (p != &vnode->wb_keys) {
		wbk = list_entry(p, struct afs_wb_key, vnode_link);
		_debug("wbk %u", key_serial(wbk->key));
		ret2 = key_validate(wbk->key);
		if (ret2 == 0) {
			refcount_inc(&wbk->usage);
			_debug("USE WB KEY %u", key_serial(wbk->key));
			break;
		}

		wbk = NULL;
		if (ret == -ENOKEY)
			ret = ret2;
		p = p->next;
	}

	spin_unlock(&vnode->wb_lock);
	if (*_wbk)
		afs_put_wb_key(*_wbk);
	*_wbk = wbk;
	return 0;
}

static void afs_store_data_success(struct afs_operation *op)
{
	struct afs_vnode *vnode = op->file[0].vnode;

	op->ctime = op->file[0].scb.status.mtime_client;
	afs_vnode_commit_status(op, &op->file[0]);
	if (op->error == 0) {
		afs_pages_written_back(vnode, op->store.first, op->store.last);
		afs_stat_v(vnode, n_stores);
		atomic_long_add(op->store.size, &afs_v2net(vnode)->n_store_bytes);
	}
}

static const struct afs_operation_ops afs_store_data_operation = {
	.issue_afs_rpc	= afs_fs_store_data,
	.issue_yfs_rpc	= yfs_fs_store_data,
	.success	= afs_store_data_success,
};

/*
 * write to a file
 */
static int afs_store_data(struct afs_vnode *vnode, struct iov_iter *iter,
			  loff_t pos, pgoff_t first, pgoff_t last)
{
	struct afs_operation *op;
	struct afs_wb_key *wbk = NULL;
	loff_t size = iov_iter_count(iter), i_size;
	int ret = -ENOKEY;

	_enter("%s{%llx:%llu.%u},%llx,%llx",
	       vnode->volume->name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       size, pos);

	ret = afs_get_writeback_key(vnode, &wbk);
	if (ret) {
		_leave(" = %d [no keys]", ret);
		return ret;
	}

	op = afs_alloc_operation(wbk->key, vnode->volume);
	if (IS_ERR(op)) {
		afs_put_wb_key(wbk);
		return -ENOMEM;
	}

	i_size = i_size_read(&vnode->vfs_inode);

	afs_op_set_vnode(op, 0, vnode);
	op->file[0].dv_delta = 1;
	op->store.write_iter = iter;
	op->store.pos = pos;
	op->store.first = first;
	op->store.last = last;
	op->store.size = size;
	op->store.i_size = max(pos + size, i_size);
	op->mtime = vnode->vfs_inode.i_mtime;
	op->flags |= AFS_OPERATION_SET_MTIME | AFS_OPERATION_UNINTR;
	op->ops = &afs_store_data_operation;

try_next_key:
	afs_begin_vnode_operation(op);
	afs_wait_for_operation(op);

	switch (op->error) {
	case -EACCES:
	case -EPERM:
	case -ENOKEY:
	case -EKEYEXPIRED:
	case -EKEYREJECTED:
	case -EKEYREVOKED:
		_debug("next");

		ret = afs_get_writeback_key(vnode, &wbk);
		if (ret == 0) {
			key_put(op->key);
			op->key = key_get(wbk->key);
			goto try_next_key;
		}
		break;
	}

	afs_put_wb_key(wbk);
	_leave(" = %d", op->error);
	return afs_put_operation(op);
}

/*
 * Synchronously write back the locked page and any subsequent non-locked dirty
 * pages.
 */
static int afs_write_back_from_locked_page(struct address_space *mapping,
					   struct writeback_control *wbc,
					   struct page *primary_page,
					   pgoff_t final_page)
{
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct iov_iter iter;
	struct page *pages[8], *page;
	unsigned long count, priv;
	unsigned n, offset, to, f, t;
	pgoff_t start, first, last;
	loff_t i_size, pos, end;
	int loop, ret;

	_enter(",%lx", primary_page->index);

	count = 1;
	if (test_set_page_writeback(primary_page))
		BUG();
	if (TestSetPageFsCache(primary_page))
		BUG();

	/* Find all consecutive lockable dirty pages that have contiguous
	 * written regions, stopping when we find a page that is not
	 * immediately lockable, is not dirty or is missing, or we reach the
	 * end of the range.
	 */
	start = primary_page->index;
	priv = page_private(primary_page);
	offset = priv & AFS_PRIV_MAX;
	to = priv >> AFS_PRIV_SHIFT;
	trace_afs_page_dirty(vnode, tracepoint_string("store"),
			     primary_page->index, priv);

	WARN_ON(offset == to);
	if (offset == to)
		trace_afs_page_dirty(vnode, tracepoint_string("WARN"),
				     primary_page->index, priv);

	if (start >= final_page ||
	    (to < PAGE_SIZE && !test_bit(AFS_VNODE_NEW_CONTENT, &vnode->flags)))
		goto no_more;

	start++;
	do {
		_debug("more %lx [%lx]", start, count);
		n = final_page - start + 1;
		if (n > ARRAY_SIZE(pages))
			n = ARRAY_SIZE(pages);
		n = find_get_pages_contig(mapping, start, ARRAY_SIZE(pages), pages);
		_debug("fgpc %u", n);
		if (n == 0)
			goto no_more;
		if (pages[0]->index != start) {
			do {
				put_page(pages[--n]);
			} while (n > 0);
			goto no_more;
		}

		for (loop = 0; loop < n; loop++) {
			page = pages[loop];
			if (to != PAGE_SIZE &&
			    !test_bit(AFS_VNODE_NEW_CONTENT, &vnode->flags))
				break;
			if (page->index > final_page)
				break;
			if (!trylock_page(page))
				break;
			if (!PageDirty(page) || PageWriteback(page) ||
			    PageFsCache(page)) {
				unlock_page(page);
				break;
			}

			priv = page_private(page);
			f = priv & AFS_PRIV_MAX;
			t = priv >> AFS_PRIV_SHIFT;
			if (f != 0 &&
			    !test_bit(AFS_VNODE_NEW_CONTENT, &vnode->flags)) {
				unlock_page(page);
				break;
			}
			to = t;

			trace_afs_page_dirty(vnode, tracepoint_string("store+"),
					     page->index, priv);

			if (!clear_page_dirty_for_io(page))
				BUG();
			if (test_set_page_writeback(page))
				BUG();
			if (TestSetPageFsCache(page))
				BUG();
			unlock_page(page);
			put_page(page);
		}
		count += loop;
		if (loop < n) {
			for (; loop < n; loop++)
				put_page(pages[loop]);
			goto no_more;
		}

		start += loop;
	} while (start <= final_page && count < 65536);

no_more:
	/* We now have a contiguous set of dirty pages, each with writeback
	 * set; the first page is still locked at this point, but all the rest
	 * have been unlocked.
	 */
	unlock_page(primary_page);

	first = primary_page->index;
	last = first + count - 1;
	_debug("write back %lx[%u..] to %lx[..%u]", first, offset, last, to);

	pos = first;
	pos <<= PAGE_SHIFT;
	pos += offset;
	end = last;
	end <<= PAGE_SHIFT;
	end += to;

	/* Trim the actual write down to the EOF */
	i_size = i_size_read(&vnode->vfs_inode);
	if (end > i_size)
		end = i_size;

	if (pos < i_size) {
		/* Speculatively write to the cache.  We have to fix this up
		 * later if the store fails.
		 */
		afs_write_to_cache(vnode, first, last, pos, end);

		iov_iter_mapping(&iter, WRITE, mapping, pos, end - pos);
		ret = afs_store_data(vnode, &iter, pos, first, last);
	} else {
		/* The dirty region was entirely beyond the EOF. */
		ret = 0;
	}

	switch (ret) {
	case 0:
		ret = count;
		break;

	default:
		pr_notice("kAFS: Unexpected error from FS.StoreData %d\n", ret);
		/* Fall through */
	case -EACCES:
	case -EPERM:
	case -ENOKEY:
	case -EKEYEXPIRED:
	case -EKEYREJECTED:
	case -EKEYREVOKED:
		afs_redirty_pages(wbc, mapping, first, last);
		mapping_set_error(mapping, ret);
		break;

	case -EDQUOT:
	case -ENOSPC:
		afs_redirty_pages(wbc, mapping, first, last);
		mapping_set_error(mapping, -ENOSPC);
		break;

	case -EROFS:
	case -EIO:
	case -EREMOTEIO:
	case -EFBIG:
	case -ENOENT:
	case -ENOMEDIUM:
	case -ENXIO:
		trace_afs_file_error(vnode, ret, afs_file_error_writeback_fail);
		afs_kill_pages(mapping, first, last);
		mapping_set_error(mapping, ret);
		break;
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * write a page back to the server
 * - the caller locked the page for us
 */
int afs_writepage(struct page *page, struct writeback_control *wbc)
{
	int ret;

	_enter("{%lx},", page->index);

#ifdef CONFIG_AFS_FSCACHE
	wait_on_page_fscache(page);
#endif

	ret = afs_write_back_from_locked_page(page->mapping, wbc, page,
					      wbc->range_end >> PAGE_SHIFT);
	if (ret < 0) {
		_leave(" = %d", ret);
		return 0;
	}

	wbc->nr_to_write -= ret;

	_leave(" = 0");
	return 0;
}

/*
 * write a region of pages back to the server
 */
static int afs_writepages_region(struct address_space *mapping,
				 struct writeback_control *wbc,
				 pgoff_t index, pgoff_t end, pgoff_t *_next)
{
	struct page *page;
	int ret, n;

	_enter(",,%lx,%lx,", index, end);

	do {
		n = find_get_pages_range_tag(mapping, &index, end,
					     PAGECACHE_TAG_DIRTY, 1, &page);
		if (!n)
			break;

		_debug("wback %lx", page->index);

		/*
		 * at this point we hold neither the i_pages lock nor the
		 * page lock: the page may be truncated or invalidated
		 * (changing page->mapping to NULL), or even swizzled
		 * back from swapper_space to tmpfs file mapping
		 */
		ret = lock_page_killable(page);
		if (ret < 0) {
			put_page(page);
			_leave(" = %d", ret);
			return ret;
		}

		if (page->mapping != mapping || !PageDirty(page)) {
			unlock_page(page);
			put_page(page);
			continue;
		}

		if (PageWriteback(page) || PageFsCache(page)) {
			unlock_page(page);
			if (wbc->sync_mode != WB_SYNC_NONE) {
				wait_on_page_writeback(page);
#ifdef CONFIG_AFS_FSCACHE
				wait_on_page_fscache(page);
#endif
			}
			put_page(page);
			continue;
		}

		if (!clear_page_dirty_for_io(page))
			BUG();
		ret = afs_write_back_from_locked_page(mapping, wbc, page, end);
		put_page(page);
		if (ret < 0) {
			_leave(" = %d", ret);
			return ret;
		}

		wbc->nr_to_write -= ret;

		cond_resched();
	} while (index < end && wbc->nr_to_write > 0);

	*_next = index;
	_leave(" = 0 [%lx]", *_next);
	return 0;
}

/*
 * write some of the pending data back to the server
 */
int afs_writepages(struct address_space *mapping,
		   struct writeback_control *wbc)
{
	pgoff_t start, end, next;
	int ret;

	_enter("");

	if (wbc->range_cyclic) {
		start = mapping->writeback_index;
		end = -1;
		ret = afs_writepages_region(mapping, wbc, start, end, &next);
		if (start > 0 && wbc->nr_to_write > 0 && ret == 0)
			ret = afs_writepages_region(mapping, wbc, 0, start,
						    &next);
		mapping->writeback_index = next;
	} else if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX) {
		end = (pgoff_t)(LLONG_MAX >> PAGE_SHIFT);
		ret = afs_writepages_region(mapping, wbc, 0, end, &next);
		if (wbc->nr_to_write > 0)
			mapping->writeback_index = next;
	} else {
		start = wbc->range_start >> PAGE_SHIFT;
		end = wbc->range_end >> PAGE_SHIFT;
		ret = afs_writepages_region(mapping, wbc, start, end, &next);
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * write to an AFS file
 */
ssize_t afs_file_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(iocb->ki_filp));
	size_t count = iov_iter_count(from);

	_enter("{%llx:%llu},{%zu},",
	       vnode->fid.vid, vnode->fid.vnode, count);

	if (IS_SWAPFILE(&vnode->vfs_inode)) {
		printk(KERN_INFO
		       "AFS: Attempt to write to active swap file!\n");
		return -EBUSY;
	}

	return generic_file_write_iter(iocb, from);
}

/*
 * flush any dirty pages for this process, and check for write errors.
 * - the return status from this call provides a reliable indication of
 *   whether any write errors occurred for this process.
 */
int afs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file_inode(file);
	struct afs_vnode *vnode = AFS_FS_I(inode);

	_enter("{%llx:%llu},{n=%pD},%d",
	       vnode->fid.vid, vnode->fid.vnode, file,
	       datasync);

	return file_write_and_wait_range(file, start, end);
}

/*
 * notification that a previously read-only page is about to become writable
 * - if it returns an error, the caller will deliver a bus error signal
 */
vm_fault_t afs_page_mkwrite(struct vm_fault *vmf)
{
	struct file *file = vmf->vma->vm_file;
	struct inode *inode = file_inode(file);
	struct afs_vnode *vnode = AFS_FS_I(inode);
	unsigned long priv;

	_enter("{{%llx:%llu}},{%lx}",
	       vnode->fid.vid, vnode->fid.vnode, vmf->page->index);

	sb_start_pagefault(inode->i_sb);

	/* Wait for the page to be written to the cache before we allow it to
	 * be modified.  We then assume the entire page will need writing back.
	 */
#ifdef CONFIG_AFS_FSCACHE
	if (PageFsCache(vmf->page) &&
	    wait_on_page_bit_killable(vmf->page, PG_fscache) < 0)
		return VM_FAULT_RETRY;
#endif

	if (PageWriteback(vmf->page) &&
	    wait_on_page_bit_killable(vmf->page, PG_writeback) < 0)
		return VM_FAULT_RETRY;

	if (lock_page_killable(vmf->page) < 0)
		return VM_FAULT_RETRY;

	/* We mustn't change page->private until writeback is complete as that
	 * details the portion of the page we need to write back and we might
	 * need to redirty the page if there's a problem.
	 */
	wait_on_page_writeback(vmf->page);

	priv = (unsigned long)PAGE_SIZE << AFS_PRIV_SHIFT; /* To */
	priv |= 0; /* From */
	trace_afs_page_dirty(vnode, tracepoint_string("mkwrite"),
			     vmf->page->index, priv);
	SetPagePrivate(vmf->page);
	set_page_private(vmf->page, priv);
	file_update_time(file);

	sb_end_pagefault(inode->i_sb);
	return VM_FAULT_LOCKED;
}

/*
 * Prune the keys cached for writeback.  The caller must hold vnode->wb_lock.
 */
void afs_prune_wb_keys(struct afs_vnode *vnode)
{
	LIST_HEAD(graveyard);
	struct afs_wb_key *wbk, *tmp;

	/* Discard unused keys */
	spin_lock(&vnode->wb_lock);

	if (!mapping_tagged(&vnode->vfs_inode.i_data, PAGECACHE_TAG_WRITEBACK) &&
	    !mapping_tagged(&vnode->vfs_inode.i_data, PAGECACHE_TAG_DIRTY)) {
		list_for_each_entry_safe(wbk, tmp, &vnode->wb_keys, vnode_link) {
			if (refcount_read(&wbk->usage) == 1)
				list_move(&wbk->vnode_link, &graveyard);
		}
	}

	spin_unlock(&vnode->wb_lock);

	while (!list_empty(&graveyard)) {
		wbk = list_entry(graveyard.next, struct afs_wb_key, vnode_link);
		list_del(&wbk->vnode_link);
		afs_put_wb_key(wbk);
	}
}

/*
 * Clean up a page during invalidation.
 */
int afs_launder_page(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct iov_iter iter;
	struct bio_vec bv[1];
	unsigned long priv;
	unsigned int f, t;
	int ret = 0;

	_enter("{%lx}", page->index);

	priv = page_private(page);
	if (clear_page_dirty_for_io(page)) {
		f = 0;
		t = PAGE_SIZE;
		if (PagePrivate(page)) {
			f = priv & AFS_PRIV_MAX;
			t = priv >> AFS_PRIV_SHIFT;
		}

		bv[0].bv_page = page;
		bv[0].bv_offset = f;
		bv[0].bv_len = t - f;
		iov_iter_bvec(&iter, WRITE, bv, 1, bv[0].bv_len);

		trace_afs_page_dirty(vnode, tracepoint_string("launder"),
				     page->index, priv);
		ret = afs_store_data(vnode, &iter, (loff_t)page->index << PAGE_SHIFT,
				     page->index, page->index);
	}

	trace_afs_page_dirty(vnode, tracepoint_string("laundered"),
			     page->index, priv);
	wait_on_page_fscache(page);
	set_page_private(page, 0);
	ClearPagePrivate(page);
	return ret;
}

/*
 * Clear the PG_fscache flag from a sequence of pages and wake up anyone who's
 * waiting.  The last page is included in the sequence.
 */
static void afs_clear_fscache_bits(struct address_space *mapping,
				   pgoff_t start, pgoff_t last)
{
	struct page *page;

	XA_STATE(xas, &mapping->i_pages, start);

	rcu_read_lock();
	xas_for_each(&xas, page, last) {
		unlock_page_fscache(page);
	}
	rcu_read_unlock();
}

/*
 * Deal with the completion of writing the data to the cache.
 */
static void afs_write_to_cache_done(struct fscache_io_request *_req)
{
	struct afs_read *req = container_of(_req, struct afs_read, cache);
	pgoff_t index = req->cache.pos >> PAGE_SHIFT;
	pgoff_t last = index + req->cache.nr_pages - 1;

	_enter("%lx,%x,%llx", index, req->cache.nr_pages, req->cache.transferred);

	afs_clear_fscache_bits(req->cache.mapping, index, last);

	if (req->cache.error && req->cache.error != -ENOBUFS) {
		struct afs_vnode *vnode = req->vnode;
		struct afs_vnode_cache_aux aux = {
			.data_version = vnode->status.data_version,
		};
		_debug("inval wr %d", req->cache.error);
		fscache_invalidate(req->cache.cookie, &aux,
				   i_size_read(&vnode->vfs_inode), 0);
	}
}

static const struct fscache_io_request_ops afs_write_req_ops = {
	.get		= afs_req_get,
	.put		= afs_req_put,
};

/*
 * Save the write to the cache also.
 */
static void afs_write_to_cache(struct afs_vnode *vnode,
			       pgoff_t start, pgoff_t last, loff_t a, loff_t b)
{
	struct afs_read *req;
	struct iov_iter iter;

	struct fscache_request_shape shape = {
		.proposed_start		= start,
		.proposed_nr_pages	= last - start + 1,
		.max_io_pages		= UINT_MAX,
		.i_size			= i_size_read(&vnode->vfs_inode),
		.for_write		= true,
	};

	_enter("%lx,%lx,%llx,%llx", start, last, a, b);

	fscache_shape_request(afs_vnode_cache(vnode), &shape);
	if (!(shape.to_be_done & FSCACHE_WRITE_TO_CACHE) ||
	    shape.actual_nr_pages == 0 ||
	    shape.actual_start != start)
		goto abandon;

	if (shape.actual_nr_pages < shape.proposed_nr_pages) {
		afs_clear_fscache_bits(vnode->vfs_inode.i_mapping,
				       start + shape.actual_nr_pages,
				       start + shape.proposed_nr_pages - 1);
		last = start + shape.actual_nr_pages - 1;
		b = (loff_t)(last + 1) << PAGE_SHIFT;
	}

	req = afs_alloc_read(GFP_NOFS);
	if (!req)
		goto abandon;

	fscache_init_io_request(&req->cache, afs_vnode_cache(vnode),
				&afs_write_req_ops);
	req->vnode		= vnode;
	req->cache.pos		= round_down(a, shape.dio_block_size);
	req->cache.len		= round_up(b, shape.dio_block_size) - req->cache.pos;
	req->cache.nr_pages	= shape.actual_nr_pages;
	req->cache.mapping	= vnode->vfs_inode.i_mapping;
	req->cache.io_done	= &afs_write_to_cache_done;

	iov_iter_mapping(&iter, WRITE, req->cache.mapping,
			 req->cache.pos, req->cache.len);
	fscache_write(&req->cache, &iter);
	afs_put_read(req);
	return;

abandon:
	afs_clear_fscache_bits(vnode->vfs_inode.i_mapping, start, last);
}

static void afs_dio_store_data_success(struct afs_operation *op)
{
	struct afs_vnode *vnode = op->file[0].vnode;

	op->ctime = op->file[0].scb.status.mtime_client;
	afs_vnode_commit_status(op, &op->file[0]);
	if (op->error == 0) {
		afs_stat_v(vnode, n_stores);
		atomic_long_add(op->store.size, &afs_v2net(vnode)->n_store_bytes);
	}
}

static const struct afs_operation_ops afs_dio_store_data_operation = {
	.issue_afs_rpc	= afs_fs_store_data,
	.issue_yfs_rpc	= yfs_fs_store_data,
	.success	= afs_dio_store_data_success,
};

/*
 * Direct file write operation for an AFS file.
 *
 * TODO: To support AIO, the pages in the iterator have to be copied and
 * refs taken on them.  Then -EIOCBQUEUED needs to be returned.
 * iocb->ki_complete must then be called upon completion of the operation.
 */
ssize_t afs_file_direct_write(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	struct afs_operation *op;
	loff_t size = iov_iter_count(iter), i_size;
	ssize_t ret;

	_enter("%s{%llx:%llu.%u},%llx,%llx",
	       vnode->volume->name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       size, iocb->ki_pos);

	op = afs_alloc_operation(afs_file_key(file), vnode->volume);
	if (IS_ERR(op))
		return -ENOMEM;

	i_size = i_size_read(&vnode->vfs_inode);

	afs_op_set_vnode(op, 0, vnode);
	op->file[0].dv_delta	= 1;
	op->file[0].set_size	= true;
	op->store.write_iter	= iter;
	op->store.pos		= iocb->ki_pos;
	op->store.size		= size;
	op->store.i_size	= max(iocb->ki_pos + size, i_size);
	op->ops			= &afs_dio_store_data_operation;

	//if (!is_sync_kiocb(iocb)) {

	ret = afs_do_sync_operation(op);
	if (ret == 0)
		ret = size;

	{
		struct afs_vnode_cache_aux aux = {
			.data_version = vnode->status.data_version,
		};
		fscache_invalidate(afs_vnode_cache(vnode), &aux,
				   i_size_read(&vnode->vfs_inode),
				   FSCACHE_INVAL_DIO_WRITE);
	}

	//if (iocb->ki_complete)
	//	iocb->ki_complete(iocb, ret, 0); // only if ret == -EIOCBQUEUED

	_leave(" = %zd", ret);
	return ret;
}
