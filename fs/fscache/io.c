// SPDX-License-Identifier: GPL-2.0-or-later
/* Data I/O routines
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL OPERATION
#include <linux/module.h>
#include <linux/fscache-cache.h>
#include <linux/slab.h>
#include <linux/netfs.h>
#include "internal.h"

/*
 * Wait for a cookie to reach the specified stage.
 */
void __fscache_wait_for_operation(struct fscache_op_resources *opr,
				  enum fscache_want_stage want_stage)
{
	struct fscache_cookie *cookie = opr->object->cookie;
	enum fscache_cookie_stage stage;

again:
	stage = READ_ONCE(cookie->stage);
	_enter("c=%08x{%u},%x", cookie->debug_id, stage, want_stage);

	if (fscache_cache_is_broken(opr->object)) {
		_leave(" [broken]");
		return;
	}

	switch (stage) {
	case FSCACHE_COOKIE_STAGE_INITIALISING:
	case FSCACHE_COOKIE_STAGE_LOOKING_UP:
	case FSCACHE_COOKIE_STAGE_INVALIDATING:
		wait_var_event(&cookie->stage, cookie->stage != stage);
		goto again;

	case FSCACHE_COOKIE_STAGE_NO_DATA_YET:
	case FSCACHE_COOKIE_STAGE_ACTIVE:
		return;
	case FSCACHE_COOKIE_STAGE_INDEX:
	case FSCACHE_COOKIE_STAGE_DROPPED:
	case FSCACHE_COOKIE_STAGE_RELINQUISHING:
	default:
		_leave(" [not live]");
		return;
	}
}
EXPORT_SYMBOL(__fscache_wait_for_operation);

/*
 * Release the resources needed by an operation.
 */
void __fscache_end_operation(struct fscache_op_resources *opr)
{
	struct fscache_object *object = opr->object;

	fscache_uncount_io_operation(object->cookie);
	object->cache->ops->put_object(object, fscache_obj_put_ioreq);
}
EXPORT_SYMBOL(__fscache_end_operation);

/*
 * Begin an I/O operation on the cache, waiting till we reach the right state.
 *
 * Attaches the resources required to the operation resources record.
 */
int __fscache_begin_operation(struct fscache_cookie *cookie,
			      struct fscache_op_resources *opr,
			      enum fscache_want_stage want_stage)
{
	struct fscache_object *object;
	enum fscache_cookie_stage stage;

again:
	spin_lock(&cookie->lock);

	stage = cookie->stage;
	_enter("c=%08x{%u},%x", cookie->debug_id, stage, want_stage);

	switch (stage) {
	case FSCACHE_COOKIE_STAGE_INITIALISING:
	case FSCACHE_COOKIE_STAGE_LOOKING_UP:
	case FSCACHE_COOKIE_STAGE_INVALIDATING:
		goto wait_and_validate;

	case FSCACHE_COOKIE_STAGE_NO_DATA_YET:
		if (want_stage == FSCACHE_WANT_READ)
			goto no_data_yet;
		fallthrough;
	case FSCACHE_COOKIE_STAGE_ACTIVE:
		goto ready;
	case FSCACHE_COOKIE_STAGE_INDEX:
	case FSCACHE_COOKIE_STAGE_DROPPED:
	case FSCACHE_COOKIE_STAGE_RELINQUISHING:
		WARN(1, "Can't use cookie in stage %u\n", cookie->stage);
		goto not_live;
	default:
		goto not_live;
	}

ready:
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	if (fscache_cache_is_broken(object))
		goto not_live;

	opr->object = object;
	object->cache->ops->grab_object(object, fscache_obj_get_ioreq);
	object->cache->ops->begin_operation(opr);

	fscache_count_io_operation(cookie);
	spin_unlock(&cookie->lock);
	return 0;

wait_and_validate:
	spin_unlock(&cookie->lock);
	wait_var_event(&cookie->stage, cookie->stage != stage);
	goto again;

no_data_yet:
	spin_unlock(&cookie->lock);
	opr->object = NULL;
	_leave(" = -ENODATA");
	return -ENODATA;

not_live:
	spin_unlock(&cookie->lock);
	opr->object = NULL;
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_begin_operation);

/**
 * fscache_set_page_dirty - Mark page dirty and pin a cache object for writeback
 * @page: The page being dirtied
 * @cookie: The cookie referring to the cache object
 *
 * Set the dirty flag on a page and pin an in-use cache object in memory when
 * dirtying a page so that writeback can later write to it.  This is intended
 * to be called from the filesystem's ->set_page_dirty() method.
 *
 *  Returns 1 if PG_dirty was set on the page, 0 otherwise.
 */
int fscache_set_page_dirty(struct page *page, struct fscache_cookie *cookie)
{
	struct inode *inode = page->mapping->host;
	bool need_use = false;

	_enter("");

	if (!__set_page_dirty_nobuffers(page))
		return 0;
	if (!fscache_cookie_valid(cookie))
		return 1;

	if (!(inode->i_state & I_PINNING_FSCACHE_WB)) {
		spin_lock(&inode->i_lock);
		if (!(inode->i_state & I_PINNING_FSCACHE_WB)) {
			inode->i_state |= I_PINNING_FSCACHE_WB;
			need_use = true;
		}
		spin_unlock(&inode->i_lock);

		if (need_use)
			fscache_use_cookie(cookie, true);
	}
	return 1;
}
EXPORT_SYMBOL(fscache_set_page_dirty);

/**
 * fscache_put_super - Wait for outstanding ops to complete
 * @sb: The superblock to wait on
 * @get_cookie: Function to get the cookie on an inode
 *
 * Wait for outstanding cache operations on the inodes of a superblock to
 * complete as they might be pinning an inode.  This is designed to be called
 * from ->put_super(), right before the "VFS: Busy inodes" check.
 */
void fscache_put_super(struct super_block *sb,
		       struct fscache_cookie *(*get_cookie)(struct inode *inode))
{
	struct fscache_cookie *cookie;
	struct inode *inode, *p;

	while (!list_empty(&sb->s_inodes)) {
		/* Find the first inode that we need to wait on */
		inode = NULL;
		cookie = NULL;
		spin_lock(&sb->s_inode_list_lock);
		list_for_each_entry(p, &sb->s_inodes, i_sb_list) {
			if (atomic_inc_not_zero(&p->i_count)) {
				inode = p;
				cookie = get_cookie(inode);
				if (!cookie) {
					iput(inode);
					inode = NULL;
					cookie = NULL;
					continue;
				}
				break;
			}
		}
		spin_unlock(&sb->s_inode_list_lock);

		if (inode) {
			/* n_ops is kept artificially raised to stop wakeups */
			atomic_dec(&cookie->n_ops);
			wait_var_event(&cookie->n_ops, atomic_read(&cookie->n_ops) == 0);
			atomic_inc(&cookie->n_ops);
			iput(inode);
		}

		evict_inodes(sb);
		if (!inode)
			break;
	}
}
EXPORT_SYMBOL(fscache_put_super);
