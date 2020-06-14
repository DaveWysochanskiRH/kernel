// SPDX-License-Identifier: GPL-2.0-or-later
/* NFS filesystem cache interface
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_fs_sb.h>
#include <linux/in6.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/iversion.h>

#include "internal.h"
#include "iostat.h"
#include "fscache.h"

#define NFSDBG_FACILITY		NFSDBG_FSCACHE

static struct rb_root nfs_fscache_keys = RB_ROOT;
static DEFINE_SPINLOCK(nfs_fscache_keys_lock);

/*
 * Layout of the key for an NFS server cache object.
 */
struct nfs_server_key {
	struct {
		uint16_t	nfsversion;		/* NFS protocol version */
		uint32_t	minorversion;		/* NFSv4 minor version */
		uint16_t	family;			/* address family */
		__be16		port;			/* IP port */
	} hdr;
	union {
		struct in_addr	ipv4_addr;	/* IPv4 address */
		struct in6_addr ipv6_addr;	/* IPv6 address */
	};
} __packed;

/*
 * Get the per-client index cookie for an NFS client if the appropriate mount
 * flag was set
 * - We always try and get an index cookie for the client, but get filehandle
 *   cookies on a per-superblock basis, depending on the mount flags
 */
void nfs_fscache_get_client_cookie(struct nfs_client *clp)
{
	const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &clp->cl_addr;
	const struct sockaddr_in *sin = (struct sockaddr_in *) &clp->cl_addr;
	struct nfs_server_key key;
	uint16_t len = sizeof(key.hdr);

	memset(&key, 0, sizeof(key));
	key.hdr.nfsversion = clp->rpc_ops->version;
	key.hdr.minorversion = clp->cl_minorversion;
	key.hdr.family = clp->cl_addr.ss_family;

	switch (clp->cl_addr.ss_family) {
	case AF_INET:
		key.hdr.port = sin->sin_port;
		key.ipv4_addr = sin->sin_addr;
		len += sizeof(key.ipv4_addr);
		break;

	case AF_INET6:
		key.hdr.port = sin6->sin6_port;
		key.ipv6_addr = sin6->sin6_addr;
		len += sizeof(key.ipv6_addr);
		break;

	default:
		printk(KERN_WARNING "NFS: Unknown network family '%d'\n",
		       clp->cl_addr.ss_family);
		clp->fscache = NULL;
		return;
	}

	/* create a cache index for looking up filehandles */
	clp->fscache = fscache_acquire_cookie(nfs_fscache_netfs.primary_index,
					      FSCACHE_COOKIE_TYPE_INDEX,
					      "NFS.server",
					      0,    /* advice */
					      NULL, /* preferred_cache */
					      &key, /* index_key */
					      len,
					      NULL, /* aux_data */
					      0,
					      0);
	dfprintk(FSCACHE, "NFS: get client cookie (0x%p/0x%p)\n",
		 clp, clp->fscache);
}

/*
 * Dispose of a per-client cookie
 */
void nfs_fscache_release_client_cookie(struct nfs_client *clp)
{
	dfprintk(FSCACHE, "NFS: releasing client cookie (0x%p/0x%p)\n",
		 clp, clp->fscache);

	fscache_relinquish_cookie(clp->fscache, false);
	clp->fscache = NULL;
}

/*
 * Get the cache cookie for an NFS superblock.  We have to handle
 * uniquification here because the cache doesn't do it for us.
 *
 * The default uniquifier is just an empty string, but it may be overridden
 * either by the 'fsc=xxx' option to mount, or by inheriting it from the parent
 * superblock across an automount point of some nature.
 */
void nfs_fscache_get_super_cookie(struct super_block *sb, const char *uniq, int ulen)
{
	struct nfs_fscache_key *key, *xkey;
	struct nfs_server *nfss = NFS_SB(sb);
	struct rb_node **p, *parent;
	int diff;

	nfss->fscache_key = NULL;
	nfss->fscache = NULL;
	if (!uniq) {
		uniq = "";
		ulen = 1;
	}

	key = kzalloc(sizeof(*key) + ulen, GFP_KERNEL);
	if (!key)
		return;

	key->nfs_client = nfss->nfs_client;
	key->key.super.s_flags = sb->s_flags & NFS_SB_MASK;
	key->key.nfs_server.flags = nfss->flags;
	key->key.nfs_server.rsize = nfss->rsize;
	key->key.nfs_server.wsize = nfss->wsize;
	key->key.nfs_server.acregmin = nfss->acregmin;
	key->key.nfs_server.acregmax = nfss->acregmax;
	key->key.nfs_server.acdirmin = nfss->acdirmin;
	key->key.nfs_server.acdirmax = nfss->acdirmax;
	key->key.nfs_server.fsid = nfss->fsid;
	key->key.rpc_auth.au_flavor = nfss->client->cl_auth->au_flavor;

	key->key.uniq_len = ulen;
	memcpy(key->key.uniquifier, uniq, ulen);

	spin_lock(&nfs_fscache_keys_lock);
	p = &nfs_fscache_keys.rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;
		xkey = rb_entry(parent, struct nfs_fscache_key, node);

		if (key->nfs_client < xkey->nfs_client)
			goto go_left;
		if (key->nfs_client > xkey->nfs_client)
			goto go_right;

		diff = memcmp(&key->key, &xkey->key, sizeof(key->key));
		if (diff < 0)
			goto go_left;
		if (diff > 0)
			goto go_right;

		if (key->key.uniq_len == 0)
			goto non_unique;
		diff = memcmp(key->key.uniquifier,
			      xkey->key.uniquifier,
			      key->key.uniq_len);
		if (diff < 0)
			goto go_left;
		if (diff > 0)
			goto go_right;
		goto non_unique;

	go_left:
		p = &(*p)->rb_left;
		continue;
	go_right:
		p = &(*p)->rb_right;
	}

	rb_link_node(&key->node, parent, p);
	rb_insert_color(&key->node, &nfs_fscache_keys);
	spin_unlock(&nfs_fscache_keys_lock);
	nfss->fscache_key = key;

	/* create a cache index for looking up filehandles */
	nfss->fscache = fscache_acquire_cookie(nfss->nfs_client->fscache,
					       FSCACHE_COOKIE_TYPE_INDEX,
					       "NFS.super",
					       0,    /* advice */
					       NULL, /* preferred_cache */
					       &key->key,  /* index_key */
					       sizeof(key->key) + ulen,
					       NULL, /* aux_data */
					       0,
					       0);
	dfprintk(FSCACHE, "NFS: get superblock cookie (0x%p/0x%p)\n",
		 nfss, nfss->fscache);
	return;

non_unique:
	spin_unlock(&nfs_fscache_keys_lock);
	kfree(key);
	nfss->fscache_key = NULL;
	nfss->fscache = NULL;
	printk(KERN_WARNING "NFS:"
	       " Cache request denied due to non-unique superblock keys\n");
}

/*
 * release a per-superblock cookie
 */
void nfs_fscache_release_super_cookie(struct super_block *sb)
{
	struct nfs_server *nfss = NFS_SB(sb);

	dfprintk(FSCACHE, "NFS: releasing superblock cookie (0x%p/0x%p)\n",
		 nfss, nfss->fscache);

	fscache_relinquish_cookie(nfss->fscache, false);
	nfss->fscache = NULL;

	if (nfss->fscache_key) {
		spin_lock(&nfs_fscache_keys_lock);
		rb_erase(&nfss->fscache_key->node, &nfs_fscache_keys);
		spin_unlock(&nfs_fscache_keys_lock);
		kfree(nfss->fscache_key);
		nfss->fscache_key = NULL;
	}
}

static void nfs_fscache_update_auxdata(struct nfs_fscache_inode_auxdata *auxdata,
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
 * Initialise the per-inode cache cookie pointer for an NFS inode.
 */
void nfs_fscache_init_inode(struct inode *inode)
{
	struct nfs_fscache_inode_auxdata auxdata;
	struct nfs_server *nfss = NFS_SERVER(inode);
	struct nfs_inode *nfsi = NFS_I(inode);

	nfsi->fscache = NULL;
	if (!(nfss->fscache && S_ISREG(inode->i_mode)))
		return;

	nfs_fscache_update_auxdata(&auxdata, nfsi);

	nfsi->fscache = fscache_acquire_cookie(NFS_SB(inode->i_sb)->fscache,
					       FSCACHE_COOKIE_TYPE_DATAFILE,
					       "NFS.fh",
					       0,             /* advice */
					       NULL, /* preferred_cache */
					       nfsi->fh.data, /* index_key */
					       nfsi->fh.size,
					       &auxdata,      /* aux_data */
					       sizeof(auxdata),
					       i_size_read(&nfsi->vfs_inode));
}

/*
 * Release a per-inode cookie.
 */
void nfs_fscache_clear_inode(struct inode *inode)
{
	struct nfs_fscache_inode_auxdata auxdata;
	struct nfs_inode *nfsi = NFS_I(inode);
	struct fscache_cookie *cookie = nfs_i_fscache(inode);

	dfprintk(FSCACHE, "NFS: clear cookie (0x%p/0x%p)\n", nfsi, cookie);

	if (test_and_clear_bit(NFS_INO_FSCACHE, &NFS_I(inode)->flags)) {
		nfs_fscache_update_auxdata(&auxdata, nfsi);
		fscache_unuse_cookie(cookie, &auxdata, NULL);
	}
	fscache_relinquish_cookie(cookie, false);
	nfsi->fscache = NULL;
}

static bool nfs_fscache_can_enable(void *data)
{
	struct inode *inode = data;

	return !inode_is_open_for_write(inode);
}

/*
 * Enable or disable caching for a file that is being opened as appropriate.
 * The cookie is allocated when the inode is initialised, but is not enabled at
 * that time.  Enablement is deferred to file-open time to avoid stat() and
 * access() thrashing the cache.
 *
 * For now, with NFS, only regular files that are open read-only will be able
 * to use the cache.
 *
 * We enable the cache for an inode if we open it read-only and it isn't
 * currently open for writing.  We disable the cache if the inode is open
 * write-only.
 *
 * The caller uses the file struct to pin i_writecount on the inode before
 * calling us when a file is opened for writing, so we can make use of that.
 *
 * Note that this may be invoked multiple times in parallel by parallel
 * nfs_open() functions.
 */
void nfs_fscache_open_file(struct inode *inode, struct file *filp)
{
	struct nfs_inode *nfsi = NFS_I(inode);
	struct fscache_cookie *cookie = nfs_i_fscache(inode);
	struct nfs_fscache_inode_auxdata auxdata;

	if (!fscache_cookie_valid(cookie))
		return;

	if (inode_is_open_for_write(inode)) {
		if (test_and_clear_bit(NFS_INO_FSCACHE, &nfsi->flags)) {
			dfprintk(FSCACHE, "NFS: nfsi 0x%p disabling cache\n", nfsi);
			nfs_fscache_update_auxdata(&auxdata, nfsi);
			fscache_unuse_cookie(cookie, &auxdata, NULL);
		}
	} else {
		if (!test_and_set_bit(NFS_INO_FSCACHE, &nfsi->flags)) {
			dfprintk(FSCACHE, "NFS: nfsi 0x%p enabling cache\n", nfsi);
			fscache_use_cookie(cookie, false);
		}
	}
}
EXPORT_SYMBOL_GPL(nfs_fscache_open_file);

struct nfs_fscache_req {
	struct fscache_io_request	cache;
	struct nfs_readdesc             desc;
	refcount_t			usage;
};

static void nfs_done_io_request(struct fscache_io_request *fsreq)
{
	struct nfs_fscache_req *req = container_of(fsreq, struct nfs_fscache_req, cache);
	struct inode *inode = d_inode(req->desc.ctx->dentry);

	nfs_add_fscache_stats(inode, NFSIOS_FSCACHE_PAGES_READ_OK,
			      fsreq->transferred >> PAGE_SHIFT);
}

static void nfs_get_io_request(struct fscache_io_request *fsreq)
{
	struct nfs_fscache_req *req = container_of(fsreq, struct nfs_fscache_req, cache);

	refcount_inc(&req->usage);
}

static void nfs_put_io_request(struct fscache_io_request *fsreq)
{
	struct nfs_fscache_req *req = container_of(fsreq, struct nfs_fscache_req, cache);

	if (refcount_dec_and_test(&req->usage)) {
		put_nfs_open_context(req->desc.ctx);
		fscache_free_io_request(fsreq);
		kfree(req);
	}
}

static void nfs_issue_op(struct fscache_io_request *fsreq)
{
	struct nfs_fscache_req *req = container_of(fsreq, struct nfs_fscache_req, cache);
	struct inode *inode = req->cache.mapping->host;
	struct page *page;
	pgoff_t index = req->cache.pos >> PAGE_SHIFT;
	pgoff_t last = index + req->cache.nr_pages - 1;

	nfs_add_fscache_stats(inode, NFSIOS_FSCACHE_PAGES_READ_FAIL,
			      req->cache.nr_pages);
	nfs_get_io_request(fsreq);
	nfs_pageio_init_read(&req->desc.pgio, inode, false,
			     &nfs_async_read_completion_ops);

	for (; index <= last; index++) {
		page = find_get_page(req->cache.mapping, index);
		BUG_ON(!page);
		req->cache.error = readpage_async_filler(&req->desc, page);
		if (req->cache.error < 0)
			break;
	}
	nfs_pageio_complete_read(&req->desc.pgio, inode);
}

static struct fscache_io_request_ops nfs_fscache_req_ops = {
	.issue_op	= nfs_issue_op,
	.done		= nfs_done_io_request,
	.get		= nfs_get_io_request,
	.put		= nfs_put_io_request,
};

struct nfs_fscache_req *nfs_alloc_io_request(struct nfs_open_context *ctx,
					    struct address_space *mapping)
{
	struct nfs_fscache_req *req;
	struct inode *inode = mapping->host;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (req) {
		refcount_set(&req->usage, 1);
		req->cache.mapping = mapping;
		req->desc.ctx = get_nfs_open_context(ctx);

		fscache_init_io_request(&req->cache, nfs_i_fscache(inode),
					&nfs_fscache_req_ops);
		req->desc.pgio.pg_fsc_req = req;
	}

	return req;
}

/*
 * Retrieve a page from fscache
 */
int __nfs_readpage_from_fscache(struct nfs_open_context *ctx,
				struct inode *inode, struct page *page)
{
	struct nfs_fscache_req *req;
	int ret;

	dfprintk(FSCACHE,
		 "NFS: readpage_from_fscache(fsc:%p/p:%p(i:%lx f:%lx)/0x%p)\n",
		 nfs_i_fscache(inode), page, page->index, page->flags, inode);

	req = nfs_alloc_io_request(ctx, page_file_mapping(page));
	if (IS_ERR(req))
		return PTR_ERR(req);

	ret = fscache_read_helper_locked_page(&req->cache, page, ULONG_MAX);

	nfs_put_io_request(&req->cache);

	switch (ret) {
	case 0: /* read submitted */
		dfprintk(FSCACHE, "NFS:    readpage_from_fscache: submitted\n");
		nfs_inc_fscache_stats(inode, NFSIOS_FSCACHE_PAGES_READ_OK);
		return ret;

	case -ENOBUFS: /* inode not in cache */
	case -ENODATA: /* page not in cache */
		nfs_inc_fscache_stats(inode, NFSIOS_FSCACHE_PAGES_READ_FAIL);
		dfprintk(FSCACHE, "NFS:    readpage_from_fscache %d\n", ret);
		return 1;

	default:
		dfprintk(FSCACHE, "NFS:    readpage_from_fscache %d\n", ret);
		nfs_inc_fscache_stats(inode, NFSIOS_FSCACHE_PAGES_READ_FAIL);
	}

	return ret;
}

/*
 * Retrieve a set of pages from fscache
 */
int __nfs_readpages_from_fscache(struct nfs_open_context *ctx,
				 struct inode *inode,
				 struct address_space *mapping,
				 struct list_head *pages)
{
	struct nfs_fscache_req *req;
	int ret;

	dfprintk(FSCACHE, "NFS: nfs_readpages_from_fscache (0x%p/0x%p)\n",
		 nfs_i_fscache(inode), inode);

	while (!list_empty(pages)) {
		req = nfs_alloc_io_request(ctx, mapping);
		if (IS_ERR(req))
			return PTR_ERR(req);

		ret = fscache_read_helper_page_list(&req->cache, pages,
						    ULONG_MAX);
		nfs_put_io_request(&req->cache);
		if (ret < 0)
			break;
	}

	switch (ret) {
	case 0: /* read submitted to the cache for all pages */
		dfprintk(FSCACHE,
			 "NFS: nfs_readpages_from_fscache: submitted\n");

		return ret;

	case -ENOBUFS: /* some pages aren't cached and can't be */
	case -ENODATA: /* some pages aren't cached */
		dfprintk(FSCACHE,
			 "NFS: nfs_readpages_from_fscache: no page: %d\n", ret);
		return 1;

	default:
		dfprintk(FSCACHE,
			 "NFS: nfs_readpages_from_fscache: ret  %d\n", ret);
	}
	return ret;
}

/*
 * Store a newly fetched data in fscache
 */
void __nfs_read_completion_to_fscache(struct nfs_pgio_header *hdr, unsigned long bytes)
{
	struct nfs_fscache_req *fsc_req = hdr->fsc_req;

	if (fsc_req && fsc_req->cache.io_done) {
		fsc_req->cache.transferred = min_t(long long, bytes, fsc_req->cache.len);
		set_bit(FSCACHE_IO_DATA_FROM_SERVER, &fsc_req->cache.flags);
		fsc_req->cache.io_done(&fsc_req->cache);
		nfs_put_io_request(&fsc_req->cache);
	}
}
