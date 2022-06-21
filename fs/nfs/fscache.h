/* SPDX-License-Identifier: GPL-2.0-or-later */
/* NFS filesystem cache interface definitions
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _NFS_FSCACHE_H
#define _NFS_FSCACHE_H

#include <linux/swap.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_mount.h>
#include <linux/nfs4_mount.h>
#include <linux/fscache.h>
#include <linux/iversion.h>

#ifdef CONFIG_NFS_FSCACHE

/*
 * Definition of the auxiliary data attached to NFS inode storage objects
 * within the cache.
 *
 * The contents of this struct are recorded in the on-disk local cache in the
 * auxiliary data attached to the data storage object backing an inode.  This
 * permits coherency to be managed when a new inode binds to an already extant
 * cache object.
 */
struct nfs_fscache_inode_auxdata {
	s64	mtime_sec;
	s64	mtime_nsec;
	s64	ctime_sec;
	s64	ctime_nsec;
	u64	change_attr;
};

struct nfs_netfs_io_data {
	refcount_t			refcount;
	struct netfs_io_subrequest	*sreq;

	/*
	 * NFS may split a netfs_io_subrequest into multiple RPCs, each
	 * with their own read completion.  In netfs, we can only call
	 * netfs_subreq_terminated() once for each subrequest.  So we
	 * must keep track of the rpcs and rpc_byte_count for what has
	 * been submitted, and only call netfs via netfs_subreq_terminated()
	 * when the final RPC has completed.
	 */
	atomic_t	rpcs;
	unsigned long	rpc_byte_count;

	/*
	 * Final dispostion of the netfs_io_subrequest, sent in
	 * netfs_subreq_terminated()
	 */
	spinlock_t	lock;
	ssize_t		transferred;
	int		error;
};

static inline void nfs_netfs_get(struct nfs_netfs_io_data *netfs)
{
	refcount_inc(&netfs->refcount);
}

static inline void nfs_netfs_put(struct nfs_netfs_io_data *netfs)
{
	if (refcount_dec_and_test(&netfs->refcount))
		kfree(netfs);
}
extern void nfs_netfs_read_initiate(struct nfs_pgio_header *hdr);
extern void nfs_netfs_read_done(struct nfs_pgio_header *hdr);
extern void nfs_netfs_read_completion(struct nfs_pgio_header *hdr);

/*
 * fscache.c
 */
extern int nfs_fscache_get_super_cookie(struct super_block *, const char *, int);
extern void nfs_fscache_release_super_cookie(struct super_block *);

extern void nfs_fscache_init_inode(struct inode *);
extern void nfs_fscache_clear_inode(struct inode *);
extern void nfs_fscache_open_file(struct inode *, struct file *);
extern void nfs_fscache_release_file(struct inode *, struct file *);

static inline bool nfs_fscache_release_folio(struct folio *folio, gfp_t gfp)
{
	if (folio_test_fscache(folio)) {
		if (current_is_kswapd() || !(gfp & __GFP_FS))
			return false;
		folio_wait_fscache(folio);
	}
	fscache_note_page_release(netfs_i_cookie(&NFS_I(folio->mapping->host)->netfs));
	return true;
}

static inline void nfs_fscache_update_auxdata(struct nfs_fscache_inode_auxdata *auxdata,
					      struct inode *inode)
{
	memset(auxdata, 0, sizeof(*auxdata));
	auxdata->mtime_sec  = inode->i_mtime.tv_sec;
	auxdata->mtime_nsec = inode->i_mtime.tv_nsec;
	auxdata->ctime_sec  = inode->i_ctime.tv_sec;
	auxdata->ctime_nsec = inode->i_ctime.tv_nsec;

	if (NFS_SERVER(inode)->nfs_client->rpc_ops->version == 4)
		auxdata->change_attr = inode_peek_iversion_raw(inode);
}

/*
 * Invalidate the contents of fscache for this inode.  This will not sleep.
 */
static inline void nfs_fscache_invalidate(struct inode *inode, int flags)
{
	struct nfs_fscache_inode_auxdata auxdata;
	struct fscache_cookie *cookie =  netfs_i_cookie(&NFS_I(inode)->netfs);

	nfs_fscache_update_auxdata(&auxdata, inode);
	fscache_invalidate(cookie, &auxdata, i_size_read(inode), flags);
}

/*
 * indicate the client caching state as readable text
 */
static inline const char *nfs_server_fscache_state(struct nfs_server *server)
{
	if (server->fscache)
		return "yes";
	return "no ";
}

#else /* CONFIG_NFS_FSCACHE */
static inline void nfs_fscache_release_super_cookie(struct super_block *sb) {}

static inline void nfs_fscache_init_inode(struct inode *inode) {}
static inline void nfs_fscache_clear_inode(struct inode *inode) {}
static inline void nfs_fscache_open_file(struct inode *inode,
					 struct file *filp) {}
static inline void nfs_fscache_release_file(struct inode *inode, struct file *file) {}

static inline bool nfs_fscache_release_folio(struct folio *folio, gfp_t gfp)
{
	return true; /* may release folio */
}
static inline void nfs_fscache_invalidate(struct inode *inode, int flags) {}

static inline const char *nfs_server_fscache_state(struct nfs_server *server)
{
	return "no ";
}

#endif /* CONFIG_NFS_FSCACHE */
#endif /* _NFS_FSCACHE_H */
