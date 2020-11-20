/* SPDX-License-Identifier: GPL-2.0-or-later */
/* NFS filesystem cache interface definitions
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _NFS_FSCACHE_H
#define _NFS_FSCACHE_H

#include <linux/nfs_fs.h>
#include <linux/nfs_mount.h>
#include <linux/nfs4_mount.h>
#include <linux/fscache.h>
#include <linux/iversion.h>

#ifdef CONFIG_NFS_FSCACHE

/*
 * set of NFS FS-Cache objects that form a superblock key
 */
struct nfs_fscache_key {
	struct rb_node		node;
	struct nfs_client	*nfs_client;	/* the server */

	/* the elements of the unique key - as used by nfs_compare_super() and
	 * nfs_compare_mount_options() to distinguish superblocks */
	struct {
		struct {
			unsigned long	s_flags;	/* various flags
							 * (& NFS_MS_MASK) */
		} super;

		struct {
			struct nfs_fsid fsid;
			int		flags;
			unsigned int	rsize;		/* read size */
			unsigned int	wsize;		/* write size */
			unsigned int	acregmin;	/* attr cache timeouts */
			unsigned int	acregmax;
			unsigned int	acdirmin;
			unsigned int	acdirmax;
		} nfs_server;

		struct {
			rpc_authflavor_t au_flavor;
		} rpc_auth;

		/* uniquifier - can be used if nfs_server.flags includes
		 * NFS_MOUNT_UNSHARED  */
		u8 uniq_len;
		char uniquifier[0];
	} key;
};

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

/*
 * fscache-index.c
 */
extern struct fscache_netfs nfs_fscache_netfs;

extern int nfs_fscache_register(void);
extern void nfs_fscache_unregister(void);

/*
 * fscache.c
 */
extern void nfs_fscache_get_client_cookie(struct nfs_client *);
extern void nfs_fscache_release_client_cookie(struct nfs_client *);

extern void nfs_fscache_get_super_cookie(struct super_block *, const char *, int);
extern void nfs_fscache_release_super_cookie(struct super_block *);

extern void nfs_fscache_init_inode(struct inode *);
extern void nfs_fscache_clear_inode(struct inode *);
extern void nfs_fscache_open_file(struct inode *, struct file *);

extern int __nfs_readpage_from_fscache(struct file *filp,
				       struct page *page,
				       struct nfs_readdesc *desc);
extern int __nfs_readahead_from_fscache(struct nfs_readdesc *desc,
					struct readahead_control *rac);
extern void __nfs_read_completion_to_fscache(struct nfs_pgio_header *hdr,
					     unsigned long bytes);

/*
 * Retrieve a page from an inode data storage object.
 */
static inline int nfs_readpage_from_fscache(struct file *filp,
					    struct page *page,
					    struct nfs_readdesc *desc)
{
	if (NFS_I(file_inode(filp))->fscache)
		return __nfs_readpage_from_fscache(filp, page, desc);
	return -ENOBUFS;
}

/*
 * Retrieve a set of pages from an inode data storage object.
 */
static inline int nfs_readahead_from_fscache(struct nfs_readdesc *desc,
					     struct readahead_control *rac)
{
	if (NFS_I(rac->mapping->host)->fscache)
		return __nfs_readahead_from_fscache(desc, rac);
	return -ENOBUFS;
}

/*
 * Store pages newly fetched from the server in an inode data storage object
 * in the cache.
 */
static inline void nfs_read_completion_to_fscache(struct nfs_pgio_header *hdr,
						  unsigned long bytes)
{
	if (NFS_I(hdr->inode)->fscache)
		__nfs_read_completion_to_fscache(hdr, bytes);
}

static inline void nfs_fscache_update_auxdata(struct nfs_fscache_inode_auxdata *auxdata,
				  struct nfs_inode *nfsi)
{
	memset(auxdata, 0, sizeof(*auxdata));
	auxdata->mtime_sec  = nfsi->vfs_inode.i_mtime.tv_sec;
	auxdata->mtime_nsec = nfsi->vfs_inode.i_mtime.tv_nsec;
	auxdata->ctime_sec  = nfsi->vfs_inode.i_ctime.tv_sec;
	auxdata->ctime_nsec = nfsi->vfs_inode.i_ctime.tv_nsec;

	if (NFS_SERVER(&nfsi->vfs_inode)->nfs_client->rpc_ops->version == 4)
		auxdata->change_attr = inode_peek_iversion_raw(&nfsi->vfs_inode);
}

/*
 * Invalidate the contents of fscache for this inode.  This will not sleep.
 */
static inline void nfs_fscache_invalidate(struct inode *inode, int flags)
{
	struct nfs_fscache_inode_auxdata auxdata;
	struct nfs_inode *nfsi = NFS_I(inode);

	if (nfsi->fscache) {
		nfs_fscache_update_auxdata(&auxdata, nfsi);
		fscache_invalidate(nfsi->fscache, &auxdata,
				   i_size_read(&nfsi->vfs_inode), flags);
	}
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
static inline int nfs_fscache_register(void) { return 0; }
static inline void nfs_fscache_unregister(void) {}

static inline void nfs_fscache_get_client_cookie(struct nfs_client *clp) {}
static inline void nfs_fscache_release_client_cookie(struct nfs_client *clp) {}

static inline void nfs_fscache_release_super_cookie(struct super_block *sb) {}

static inline void nfs_fscache_init_inode(struct inode *inode) {}
static inline void nfs_fscache_clear_inode(struct inode *inode) {}
static inline void nfs_fscache_open_file(struct inode *inode,
					 struct file *filp) {}

static inline int nfs_readpage_from_fscache(struct file *filp,
					    struct page *page,
					    struct nfs_readdesc *desc)
{
	return -ENOBUFS;
}
static inline int nfs_readahead_from_fscache(struct nfs_readdesc *desc,
					     struct readahead_control *rac)
{
	return -ENOBUFS;
}
static inline void nfs_read_completion_to_fscache(struct nfs_pgio_header *hdr,
						  unsigned long bytes) {}

static inline void nfs_fscache_invalidate(struct inode *inode, int flags) {}

static inline const char *nfs_server_fscache_state(struct nfs_server *server)
{
	return "no ";
}

#endif /* CONFIG_NFS_FSCACHE */
#endif /* _NFS_FSCACHE_H */
