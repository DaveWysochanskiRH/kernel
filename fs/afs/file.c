// SPDX-License-Identifier: GPL-2.0-or-later
/* AFS filesystem file handling
 *
 * Copyright (C) 2002, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/gfp.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/mm.h>
#include "internal.h"

static int afs_file_mmap(struct file *file, struct vm_area_struct *vma);
static int afs_readpage(struct file *file, struct page *page);
static void afs_invalidatepage(struct page *page, unsigned int offset,
			       unsigned int length);
static int afs_releasepage(struct page *page, gfp_t gfp_flags);

static int afs_readpages(struct file *filp, struct address_space *mapping,
			 struct list_head *pages, unsigned nr_pages);
static ssize_t afs_direct_IO(struct kiocb *iocb, struct iov_iter *iter);

const struct file_operations afs_file_operations = {
	.open		= afs_open,
	.release	= afs_release,
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= afs_file_write,
	.mmap		= afs_file_mmap,
	.splice_read	= generic_file_splice_read,
	.fsync		= afs_fsync,
	.lock		= afs_lock,
	.flock		= afs_flock,
};

const struct inode_operations afs_file_inode_operations = {
	.getattr	= afs_getattr,
	.setattr	= afs_setattr,
	.permission	= afs_permission,
	.listxattr	= afs_listxattr,
};

const struct address_space_operations afs_fs_aops = {
	.readpage	= afs_readpage,
	.readpages	= afs_readpages,
	.set_page_dirty	= afs_set_page_dirty,
	.launder_page	= afs_launder_page,
	.releasepage	= afs_releasepage,
	.invalidatepage	= afs_invalidatepage,
	.direct_IO	= afs_direct_IO,
	.write_begin	= afs_write_begin,
	.write_end	= afs_write_end,
	.writepage	= afs_writepage,
	.writepages	= afs_writepages,
};

static const struct vm_operations_struct afs_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= afs_page_mkwrite,
};

/*
 * Discard a pin on a writeback key.
 */
void afs_put_wb_key(struct afs_wb_key *wbk)
{
	if (wbk && refcount_dec_and_test(&wbk->usage)) {
		key_put(wbk->key);
		kfree(wbk);
	}
}

/*
 * Cache key for writeback.
 */
int afs_cache_wb_key(struct afs_vnode *vnode, struct afs_file *af)
{
	struct afs_wb_key *wbk, *p;

	wbk = kzalloc(sizeof(struct afs_wb_key), GFP_KERNEL);
	if (!wbk)
		return -ENOMEM;
	refcount_set(&wbk->usage, 2);
	wbk->key = af->key;

	spin_lock(&vnode->wb_lock);
	list_for_each_entry(p, &vnode->wb_keys, vnode_link) {
		if (p->key == wbk->key)
			goto found;
	}

	key_get(wbk->key);
	list_add_tail(&wbk->vnode_link, &vnode->wb_keys);
	spin_unlock(&vnode->wb_lock);
	af->wb = wbk;
	return 0;

found:
	refcount_inc(&p->usage);
	spin_unlock(&vnode->wb_lock);
	af->wb = p;
	kfree(wbk);
	return 0;
}

/*
 * open an AFS file or directory and attach a key to it
 */
int afs_open(struct inode *inode, struct file *file)
{
	struct afs_vnode *vnode = AFS_FS_I(inode);
	struct afs_file *af;
	struct key *key;
	int ret;

	_enter("{%llx:%llu},", vnode->fid.vid, vnode->fid.vnode);

	key = afs_request_key(vnode->volume->cell);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto error;
	}

	af = kzalloc(sizeof(*af), GFP_KERNEL);
	if (!af) {
		ret = -ENOMEM;
		goto error_key;
	}
	af->key = key;

	ret = afs_validate(vnode, key);
	if (ret < 0)
		goto error_af;

	if (file->f_mode & FMODE_WRITE) {
		ret = afs_cache_wb_key(vnode, af);
		if (ret < 0)
			goto error_af;
	}

	if (file->f_flags & O_TRUNC)
		set_bit(AFS_VNODE_NEW_CONTENT, &vnode->flags);

	fscache_use_cookie(afs_vnode_cache(vnode), file->f_mode & FMODE_WRITE);

	file->private_data = af;
	_leave(" = 0");
	return 0;

error_af:
	kfree(af);
error_key:
	key_put(key);
error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * release an AFS file or directory and discard its key
 */
int afs_release(struct inode *inode, struct file *file)
{
	struct afs_vnode_cache_aux aux;
	struct afs_vnode *vnode = AFS_FS_I(inode);
	struct afs_file *af = file->private_data;
	loff_t i_size;
	int ret = 0;

	_enter("{%llx:%llu},", vnode->fid.vid, vnode->fid.vnode);

	if ((file->f_mode & FMODE_WRITE))
		ret = vfs_fsync(file, 0);

	file->private_data = NULL;
	if (af->wb)
		afs_put_wb_key(af->wb);

	if ((file->f_mode & FMODE_WRITE)) {
		i_size = i_size_read(&vnode->vfs_inode);
		aux.data_version = vnode->status.data_version;
		fscache_unuse_cookie(afs_vnode_cache(vnode), &aux, &i_size);
	} else {
		fscache_unuse_cookie(afs_vnode_cache(vnode), NULL, NULL);
	}

	key_put(af->key);
	kfree(af);
	afs_prune_wb_keys(vnode);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Dispose of our locks and refs on the pages if the read failed.
 */
static void afs_file_read_cleanup(struct afs_read *req)
{
	struct afs_vnode *vnode = req->vnode;
	struct page *page;
	pgoff_t index = req->cache.pos >> PAGE_SHIFT;
	pgoff_t last = index + req->cache.nr_pages - 1;

	_enter("%lx,%x,%llx", index, req->cache.nr_pages, req->cache.len);

	if (req->cache.nr_pages > 0) {
		XA_STATE(xas, &vnode->vfs_inode.i_mapping->i_pages, index);

		rcu_read_lock();
		xas_for_each(&xas, page, last) {
			BUG_ON(xa_is_value(page));
			BUG_ON(PageCompound(page));

			if (req->cache.error)
				page_endio(page, false, req->cache.error);
			else
				unlock_page(page);
			put_page(page);
		}
		rcu_read_unlock();
	}
}

/*
 * Allocate a new read record.
 */
struct afs_read *afs_alloc_read(gfp_t gfp)
{
	static atomic_t debug_ids;
	struct afs_read *req;

	req = kzalloc(sizeof(struct afs_read), gfp);
	if (req) {
		refcount_set(&req->usage, 1);
		req->debug_id = atomic_inc_return(&debug_ids);
	}

	return req;
}

/*
 *
 */
static void __afs_put_read(struct work_struct *work)
{
	struct afs_read *req = container_of(work, struct afs_read, cache.work);

	if (req->cleanup)
		req->cleanup(req);
	fscache_free_io_request(&req->cache);
	key_put(req->key);
	kfree(req);
}

/*
 * Dispose of a ref to a read record.
 */
void afs_put_read(struct afs_read *req)
{
	if (refcount_dec_and_test(&req->usage)) {
		_debug("dead %u", req->debug_id);
		if (in_softirq()) {
			INIT_WORK(&req->cache.work, __afs_put_read);
			queue_work(afs_wq, &req->cache.work);
		} else {
			__afs_put_read(&req->cache.work);
		}
	}
}

static void afs_fetch_data_success(struct afs_operation *op)
{
	struct afs_vnode *vnode = op->file[0].vnode;

	_enter("op=%08x", op->debug_id);
	afs_vnode_commit_status(op, &op->file[0]);
	afs_stat_v(vnode, n_fetches);
	atomic_long_add(op->fetch.req->actual_len, &op->net->n_fetch_bytes);
}

static void afs_fetch_data_put(struct afs_operation *op)
{
	op->fetch.req->cache.error = op->error;
	afs_put_read(op->fetch.req);
}

static const struct afs_operation_ops afs_fetch_data_operation = {
	.issue_afs_rpc	= afs_fs_fetch_data,
	.issue_yfs_rpc	= yfs_fs_fetch_data,
	.success	= afs_fetch_data_success,
	.aborted	= afs_check_for_remote_deletion,
	.put		= afs_fetch_data_put,
};

/*
 * Fetch file data from the volume.
 */
int afs_fetch_data(struct afs_vnode *vnode, struct afs_read *req)
{
	struct afs_operation *op;

	_enter("%s{%llx:%llu.%u},%x,,,",
	       vnode->volume->name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(req->key));

	op = afs_alloc_operation(req->key, vnode->volume);
	if (IS_ERR(op))
		return PTR_ERR(op);

	afs_op_set_vnode(op, 0, vnode);

	op->fetch.req	= afs_get_read(req);
	op->ops		= &afs_fetch_data_operation;
	return afs_do_sync_operation(op);
}

void afs_req_issue_op(struct fscache_io_request *fsreq)
{
	struct afs_read *req = container_of(fsreq, struct afs_read, cache);
	int ret;

	iov_iter_mapping(&req->def_iter, READ, req->cache.mapping,
			 req->cache.pos, req->cache.len);
	req->iter = &req->def_iter;

	ret = afs_fetch_data(req->vnode, req);
	if (ret < 0)
		req->cache.error = ret;
}

void afs_req_done(struct fscache_io_request *fsreq)
{
	struct afs_read *req = container_of(fsreq, struct afs_read, cache);

	req->cleanup = NULL;
}

void afs_req_get(struct fscache_io_request *fsreq)
{
	struct afs_read *req = container_of(fsreq, struct afs_read, cache);

	afs_get_read(req);
}

void afs_req_put(struct fscache_io_request *fsreq)
{
	struct afs_read *req = container_of(fsreq, struct afs_read, cache);

	afs_put_read(req);
}

const struct fscache_io_request_ops afs_req_ops = {
	.issue_op	= afs_req_issue_op,
	.done		= afs_req_done,
	.get		= afs_req_get,
	.put		= afs_req_put,
};

/*
 * read page from file, directory or symlink, given a file to nominate the key
 * to be used
 */
static int afs_readpage(struct file *file, struct page *page)
{
	struct afs_vnode *vnode = AFS_FS_I(page->mapping->host);
	struct afs_read *req;
	struct key *key;
	int ret = -ENOMEM;

	_enter(",%lx", page->index);

	if (file) {
		key = key_get(afs_file_key(file));
		ASSERT(key != NULL);
	} else {
		key = afs_request_key(vnode->volume->cell);
		if (IS_ERR(key)) {
			ret = PTR_ERR(key);
			goto out;
		}
	}

	req = afs_alloc_read(GFP_NOFS);
	if (!req)
		goto out_key;

	fscache_init_io_request(&req->cache, afs_vnode_cache(vnode), &afs_req_ops);
	req->vnode = vnode;
	req->key = key;
	req->cleanup = afs_file_read_cleanup;
	req->cache.mapping = page->mapping;

	ret = fscache_read_helper_locked_page(&req->cache, page, ULONG_MAX);
	afs_put_read(req);
	return ret;

out_key:
	key_put(key);
out:
	return ret;
}

/*
 * read a set of pages
 */
static int afs_readpages(struct file *file, struct address_space *mapping,
			 struct list_head *pages, unsigned nr_pages)
{
	struct afs_vnode *vnode;
	struct afs_read *req;
	int ret = 0;

	_enter(",{%lu},,%x", mapping->host->i_ino, nr_pages);

	vnode = AFS_FS_I(mapping->host);
	if (test_bit(AFS_VNODE_DELETED, &vnode->flags)) {
		_leave(" = -ESTALE");
		return -ESTALE;
	}

	while (!list_empty(pages)) {
		req = afs_alloc_read(GFP_NOFS);
		if (!req)
			return -ENOMEM;

		fscache_init_io_request(&req->cache, afs_vnode_cache(vnode),
					&afs_req_ops);
		req->vnode	= AFS_FS_I(mapping->host);
		req->key	= key_get(afs_file_key(file));
		req->cleanup	= afs_file_read_cleanup;
		req->cache.mapping = mapping;

		ret = fscache_read_helper_page_list(&req->cache, pages,
						    ULONG_MAX);
		afs_put_read(req);
		if (ret < 0)
			break;
	}

	_leave(" = %d [netting]", ret);
	return ret;
}

/*
 * Prefetch data into the cache prior to writing, returning the requested page
 * to the caller, with the lock held, upon completion of the write.
 */
struct page *afs_prefetch_for_write(struct file *file,
				    struct address_space *mapping,
				    pgoff_t index,
				    unsigned int aop_flags)
{
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	struct afs_read *req;
	struct page *page;
	int ret = 0;

	_enter("{%lu},%lx", mapping->host->i_ino, index);

	if (test_bit(AFS_VNODE_DELETED, &vnode->flags)) {
		_leave(" = -ESTALE");
		return ERR_PTR(-ESTALE);
	}

	page = pagecache_get_page(mapping, index, FGP_WRITE, 0);
	if (page) {
		if (PageUptodate(page)) {
			lock_page(page);
			if (PageUptodate(page))
				goto have_page;
			unlock_page(page);
		}
	}

	req = afs_alloc_read(GFP_NOFS);
	if (!req)
		return ERR_PTR(-ENOMEM);

	fscache_init_io_request(&req->cache, afs_vnode_cache(vnode), &afs_req_ops);
	req->vnode	= AFS_FS_I(mapping->host);
	req->key	= key_get(afs_file_key(file));
	req->cleanup	= afs_file_read_cleanup;
	req->cache.mapping = mapping;

	ret = fscache_read_helper_for_write(&req->cache, &page, index,
					    ULONG_MAX, aop_flags);
	if (ret == 0)
		/* Synchronicity required */
		ret = wait_on_bit(&req->cache.flags, FSCACHE_IO_READ_IN_PROGRESS,
				  TASK_KILLABLE);

	afs_put_read(req);

	if (ret < 0) {
		if (page)
			put_page(page);
		return ERR_PTR(ret);
	}

have_page:
	wait_for_stable_page(page);
	return page;
}

/*
 * invalidate part or all of a page
 * - release a page and clean up its private data if offset is 0 (indicating
 *   the entire page)
 */
static void afs_invalidatepage(struct page *page, unsigned int offset,
			       unsigned int length)
{
	struct afs_vnode *vnode = AFS_FS_I(page->mapping->host);
	unsigned long priv;

	_enter("{%lu},%u,%u", page->index, offset, length);

	BUG_ON(!PageLocked(page));

	/* we clean up only if the entire page is being invalidated */
	if (offset == 0 && length == PAGE_SIZE) {
		if (PagePrivate(page)) {
			priv = page_private(page);
			trace_afs_page_dirty(vnode, tracepoint_string("inval"),
					     page->index, priv);
			set_page_private(page, 0);
			ClearPagePrivate(page);
		}
	}

	_leave("");
}

/*
 * release a page and clean up its private state if it's not busy
 * - return true if the page can now be released, false if not
 */
static int afs_releasepage(struct page *page, gfp_t gfp_flags)
{
	struct afs_vnode *vnode = AFS_FS_I(page->mapping->host);
	unsigned long priv;

	_enter("{{%llx:%llu}[%lu],%lx},%x",
	       vnode->fid.vid, vnode->fid.vnode, page->index, page->flags,
	       gfp_flags);

	/* deny if page is being written to the cache and the caller hasn't
	 * elected to wait */
#ifdef CONFIG_AFS_FSCACHE
	if (PageFsCache(page)) {
		if (!(gfp_flags & __GFP_DIRECT_RECLAIM) || !(gfp_flags & __GFP_FS))
			return false;
	}
#endif

	if (PagePrivate(page)) {
		priv = page_private(page);
		trace_afs_page_dirty(vnode, tracepoint_string("rel"),
				     page->index, priv);
		set_page_private(page, 0);
		ClearPagePrivate(page);
	}

	/* indicate that the page can be released */
	_leave(" = T");
	return 1;
}

/*
 * Handle setting up a memory mapping on an AFS file.
 */
static int afs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;

	ret = generic_file_mmap(file, vma);
	if (ret == 0)
		vma->vm_ops = &afs_vm_ops;
	return ret;
}

/*
 * Direct file read operation for an AFS file.
 *
 * TODO: To support AIO, the pages in the iterator have to be copied and
 * refs taken on them.  Then -EIOCBQUEUED needs to be returned.
 * iocb->ki_complete must then be called upon completion of the operation.
 */
static ssize_t afs_file_direct_read(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	struct afs_read *req;
	ssize_t ret, transferred;

	_enter("%llx,%zx", iocb->ki_pos, iov_iter_count(iter));

	req = afs_alloc_read(GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->vnode	= vnode;
	req->key	= key_get(afs_file_key(file));
	req->cache.pos	= iocb->ki_pos;
	req->cache.len	= iov_iter_count(iter);
	req->iter	= iter;

	task_io_account_read(req->cache.len);

	// TODO nfs_start_io_direct(inode);
	ret = afs_fetch_data(vnode, req);
	if (ret == 0)
		transferred = req->cache.transferred;
	afs_put_read(req);

	// TODO nfs_end_io_direct(inode);

	if (ret == 0)
		ret = transferred;

	BUG_ON(ret == -EIOCBQUEUED); // TODO
	//if (iocb->ki_complete)
	//	iocb->ki_complete(iocb, ret, 0); // only if ret == -EIOCBQUEUED

	_leave(" = %zu", ret);
	return ret;
}

/*
 * Do direct I/O.
 */
static ssize_t afs_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	if (iov_iter_rw(iter) == READ)
		return afs_file_direct_read(iocb, iter);
	return afs_file_direct_write(iocb, iter);
}
