/* SPDX-License-Identifier: GPL-2.0-or-later */
/* General filesystem caching interface
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * NOTE!!! See:
 *
 *	Documentation/filesystems/caching/netfs-api.rst
 *
 * for a description of the network filesystem interface declared here.
 */

#ifndef _LINUX_FSCACHE_H
#define _LINUX_FSCACHE_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/list_bl.h>

#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
#define fscache_available() (1)
#define fscache_cookie_valid(cookie) (cookie)
#else
#define fscache_available() (0)
#define fscache_cookie_valid(cookie) (0)
#endif


/*
 * overload PG_private_2 to give us PG_fscache - this is used to indicate that
 * a page is currently being written to the cache, possibly by direct I/O.
 */
#define PageFsCache(page)		PagePrivate2((page))
#define SetPageFsCache(page)		SetPagePrivate2((page))
#define ClearPageFsCache(page)		ClearPagePrivate2((page))
#define TestSetPageFsCache(page)	TestSetPagePrivate2((page))
#define TestClearPageFsCache(page)	TestClearPagePrivate2((page))

/* pattern used to fill dead space in an index entry */
#define FSCACHE_INDEX_DEADFILL_PATTERN 0x79

struct iov_iter;
struct fscache_cache_tag;
struct fscache_cookie;
struct fscache_netfs;
struct fscache_io_request_ops;

enum fscache_cookie_type {
	FSCACHE_COOKIE_TYPE_INDEX,
	FSCACHE_COOKIE_TYPE_DATAFILE,
};

#define FSCACHE_ADV_SINGLE_CHUNK	0x01 /* The object is a single chunk of data */
#define FSCACHE_ADV_WRITE_CACHE		0x00 /* Do cache if written to locally */
#define FSCACHE_ADV_WRITE_NOCACHE	0x02 /* Don't cache if written to locally */

#define FSCACHE_INVAL_LIGHT		0x01 /* Don't re-invalidate if temp object */
#define FSCACHE_INVAL_DIO_WRITE		0x02 /* Invalidate due to DIO write */

/*
 * fscache cached network filesystem type
 * - name, version and ops must be filled in before registration
 * - all other fields will be set during registration
 */
struct fscache_netfs {
	uint32_t			version;	/* indexing version */
	const char			*name;		/* filesystem name */
	struct fscache_cookie		*primary_index;
};

/*
 * Data object state.
 */
enum fscache_cookie_stage {
	FSCACHE_COOKIE_STAGE_INDEX,		/* The cookie is an index cookie */
	FSCACHE_COOKIE_STAGE_QUIESCENT,		/* The cookie is uncached */
	FSCACHE_COOKIE_STAGE_INITIALISING,	/* The in-memory structs are being inited */
	FSCACHE_COOKIE_STAGE_LOOKING_UP,	/* The cache object is being looked up */
	FSCACHE_COOKIE_STAGE_NO_DATA_YET,	/* The cache has no data, read to network */
	FSCACHE_COOKIE_STAGE_ACTIVE,		/* The cache is active, readable and writable */
	FSCACHE_COOKIE_STAGE_INVALIDATING,	/* The cache is being invalidated */
	FSCACHE_COOKIE_STAGE_FAILED,		/* The cache failed, withdraw to clear */
	FSCACHE_COOKIE_STAGE_WITHDRAWING,	/* The cache is being withdrawn */
	FSCACHE_COOKIE_STAGE_RELINQUISHING,	/* The cookie is being relinquished */
	FSCACHE_COOKIE_STAGE_DROPPED,		/* The cookie has been dropped */
} __attribute__((mode(byte)));

/*
 * data file or index object cookie
 * - a file will only appear in one cache
 * - a request to cache a file may or may not be honoured, subject to
 *   constraints such as disk space
 * - indices are created on disk just-in-time
 */
struct fscache_cookie {
	atomic_t			usage;		/* number of users of this cookie */
	atomic_t			n_children;	/* number of children of this cookie */
	atomic_t			n_active;	/* number of active users of cookie */
	atomic_t			n_ops;		/* Number of active ops on this cookie */
	unsigned int			debug_id;
	spinlock_t			lock;
	struct hlist_head		backing_objects; /* object(s) backing this file/index */
	struct fscache_cookie		*parent;	/* parent of this entry */
	struct fscache_cache_tag	*preferred_cache; /* The preferred cache or NULL */
	struct hlist_bl_node		hash_link;	/* Link in hash table */
	struct list_head		proc_link;	/* Link in proc list */
	char				type_name[8];	/* Cookie type name */
	loff_t				object_size;	/* Size of the netfs object */
	loff_t				zero_point;	/* Size after which no data on server */

	unsigned long			flags;
#define FSCACHE_COOKIE_RELINQUISHED	6		/* T if cookie has been relinquished */

	enum fscache_cookie_stage	stage;
	enum fscache_cookie_type	type:8;
	u8				advice;		/* FSCACHE_ADV_* */
	u8				key_len;	/* Length of index key */
	u8				aux_len;	/* Length of auxiliary data */
	u32				key_hash;	/* Hash of parent, type, key, len */
	union {
		void			*key;		/* Index key */
		u8			inline_key[16];	/* - If the key is short enough */
	};
	union {
		void			*aux;		/* Auxiliary data */
		u8			inline_aux[8];	/* - If the aux data is short enough */
	};
};

/*
 * The size and shape of a request to the cache, adjusted for cache
 * granularity, for the data available on doing a read, the page size and
 * non-contiguities and for the netfs's own I/O patterning.
 *
 * Before calling fscache_shape_request(), @proposed_start and @proposed_end
 * must be set to indicate the bounds of the request and @max_io_pages to the
 * limit the netfs is willing to accept on the size of an I/O operation.
 * @i_size should be set to the size the file should be considered to be and
 * @for_write should be set if a write request is being shaped.
 *
 * After shaping, @actual_start and @actual_end will mark out the size of the
 * shaped request.  @granularity will convey the size a the cache block, should
 * the request need to be reduced in scope, either due to memory constraints or
 * netfs I/O constraints.  @dio_block_size will be set to the direct I/O size
 * for the cache - fscache_read/write() can't be expected read/write chunks
 * smaller than this or at positions that aren't aligned to this.
 *
 * Finally, @to_be_done will be set by the shaper to indicate whether the
 * region can be read from the cache or filled with zeros and whether it should
 * be written to the cache after being read from the server or cleared.
 */
struct fscache_request_shape {
	/* Parameters */
	loff_t		i_size;		/* The file size to use in calculations */
	pgoff_t		proposed_start;	/* First page in the proposed request */
	unsigned int	proposed_nr_pages; /* Number of pages in the proposed request */
	unsigned int	max_io_pages;	/* Max pages in a netfs I/O request (or UINT_MAX) */
	bool		for_write;	/* Set if shaping a write */

	/* Result */
#define FSCACHE_READ_FROM_SERVER 0x00
#define FSCACHE_READ_FROM_CACHE	0x01
#define FSCACHE_WRITE_TO_CACHE	0x02
#define FSCACHE_FILL_WITH_ZERO	0x04
	unsigned int	to_be_done;	/* What should be done by the caller */
	unsigned int	granularity;	/* Cache granularity in pages */
	unsigned int	dio_block_size;	/* Block size required for direct I/O */
	unsigned int	actual_nr_pages; /* Number of pages in the shaped request */
	pgoff_t		actual_start;	/* First page in the shaped request */
};

/*
 * Descriptor for an fscache I/O request.
 */
struct fscache_io_request {
	const struct fscache_io_request_ops *ops;
	struct fscache_cookie	*cookie;
	struct fscache_object	*object;
	loff_t			pos;		/* Where to start the I/O */
	loff_t			len;		/* Size of the I/O */
	loff_t			transferred;	/* Amount of data transferred */
	short			error;		/* 0 or error that occurred */
	unsigned int		inval_counter;	/* object->inval_counter at begin_op */
	unsigned long		flags;
#define FSCACHE_IO_DATA_FROM_SERVER	0	/* Set if data was read from server */
#define FSCACHE_IO_DATA_FROM_CACHE	1	/* Set if data was read from the cache */
#define FSCACHE_IO_SHORT_READ		2	/* Set if there was a short read from the cache */
#define FSCACHE_IO_SEEK_DATA_READ	3	/* Set if fscache_read() should SEEK_DATA first */
#define FSCACHE_IO_DONT_UNLOCK_PAGES	4	/* Don't unlock the pages on completion */
#define FSCACHE_IO_READ_IN_PROGRESS	5	/* Cleared and woken upon completion of the read */
#define FSCACHE_IO_WRITE_TO_CACHE	6	/* Set if should write to cache */
	void (*io_done)(struct fscache_io_request *);
	struct work_struct	work;

	/* Bits for readpages helper */
	struct address_space	*mapping;	/* The mapping being accessed */
	unsigned int		nr_pages;	/* Number of pages involved in the I/O */
	unsigned int		dio_block_size;	/* Rounding for direct I/O in the cache */
	struct page		*no_unlock_page; /* Don't unlock this page after read */
};

struct fscache_io_request_ops {
	int (*is_req_valid)(struct fscache_io_request *);
	bool (*is_still_valid)(struct fscache_io_request *);
	void (*issue_op)(struct fscache_io_request *);
	void (*reshape)(struct fscache_io_request *, struct fscache_request_shape *);
	void (*done)(struct fscache_io_request *);
	void (*get)(struct fscache_io_request *);
	void (*put)(struct fscache_io_request *);
};

/*
 * slow-path functions for when there is actually caching available, and the
 * netfs does actually have a valid token
 * - these are not to be called directly
 * - these are undefined symbols when FS-Cache is not configured and the
 *   optimiser takes care of not using them
 */
extern int __fscache_register_netfs(struct fscache_netfs *);
extern void __fscache_unregister_netfs(struct fscache_netfs *);
extern struct fscache_cache_tag *__fscache_lookup_cache_tag(const char *);
extern void __fscache_release_cache_tag(struct fscache_cache_tag *);

extern struct fscache_cookie *__fscache_acquire_cookie(
	struct fscache_cookie *,
	enum fscache_cookie_type,
	const char *,
	u8,
	struct fscache_cache_tag *,
	const void *, size_t,
	const void *, size_t,
	loff_t);
extern void __fscache_use_cookie(struct fscache_cookie *, bool);
extern void __fscache_unuse_cookie(struct fscache_cookie *, const void *, const loff_t *);
extern void __fscache_relinquish_cookie(struct fscache_cookie *, bool);
extern void __fscache_update_cookie(struct fscache_cookie *, const void *, const loff_t *);
extern void __fscache_shape_request(struct fscache_cookie *, struct fscache_request_shape *);
extern void __fscache_resize_cookie(struct fscache_cookie *, loff_t);
extern void __fscache_invalidate(struct fscache_cookie *, const void *, loff_t, unsigned int);
extern void __fscache_init_io_request(struct fscache_io_request *,
				      struct fscache_cookie *);
extern void __fscache_free_io_request(struct fscache_io_request *);
extern int __fscache_read(struct fscache_io_request *, struct iov_iter *);
extern int __fscache_write(struct fscache_io_request *, struct iov_iter *);

/**
 * fscache_register_netfs - Register a filesystem as desiring caching services
 * @netfs: The description of the filesystem
 *
 * Register a filesystem as desiring caching services if they're available.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
int fscache_register_netfs(struct fscache_netfs *netfs)
{
	if (fscache_available())
		return __fscache_register_netfs(netfs);
	else
		return 0;
}

/**
 * fscache_unregister_netfs - Indicate that a filesystem no longer desires
 * caching services
 * @netfs: The description of the filesystem
 *
 * Indicate that a filesystem no longer desires caching services for the
 * moment.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_unregister_netfs(struct fscache_netfs *netfs)
{
	if (fscache_available())
		__fscache_unregister_netfs(netfs);
}

/**
 * fscache_lookup_cache_tag - Look up a cache tag
 * @name: The name of the tag to search for
 *
 * Acquire a specific cache referral tag that can be used to select a specific
 * cache in which to cache an index.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
struct fscache_cache_tag *fscache_lookup_cache_tag(const char *name)
{
	if (fscache_available())
		return __fscache_lookup_cache_tag(name);
	else
		return NULL;
}

/**
 * fscache_release_cache_tag - Release a cache tag
 * @tag: The tag to release
 *
 * Release a reference to a cache referral tag previously looked up.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_release_cache_tag(struct fscache_cache_tag *tag)
{
	if (fscache_available())
		__fscache_release_cache_tag(tag);
}

/**
 * fscache_acquire_cookie - Acquire a cookie to represent a cache object
 * @parent: The cookie that's to be the parent of this one
 * @type: Type of the cookie
 * @type_name: Name of cookie type (max 7 chars)
 * @advice: Advice flags (FSCACHE_COOKIE_ADV_*)
 * @preferred_cache: The cache to use (or NULL)
 * @index_key: The index key for this cookie
 * @index_key_len: Size of the index key
 * @aux_data: The auxiliary data for the cookie (may be NULL)
 * @aux_data_len: Size of the auxiliary data buffer
 * @netfs_data: An arbitrary piece of data to be kept in the cookie to
 * represent the cache object to the netfs
 * @object_size: The initial size of object
 *
 * This function is used to inform FS-Cache about part of an index hierarchy
 * that can be used to locate files.  This is done by requesting a cookie for
 * each index in the path to the file.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
struct fscache_cookie *fscache_acquire_cookie(
	struct fscache_cookie *parent,
	enum fscache_cookie_type type,
	const char *type_name,
	u8 advice,
	struct fscache_cache_tag *preferred_cache,
	const void *index_key,
	size_t index_key_len,
	const void *aux_data,
	size_t aux_data_len,
	loff_t object_size)
{
	if (fscache_cookie_valid(parent))
		return __fscache_acquire_cookie(parent, type, type_name, advice,
						preferred_cache,
						index_key, index_key_len,
						aux_data, aux_data_len,
						object_size);
	else
		return NULL;
}

/**
 * fscache_use_cookie - Request usage of cookie attached to an object
 * @object: Object description
 * @will_modify: If cache is expected to be modified locally
 *
 * Request usage of the cookie attached to an object.  The caller should tell
 * the cache if the object's contents are about to be modified locally and then
 * the cache can apply the policy that has been set to handle this case.
 */
static inline void fscache_use_cookie(struct fscache_cookie *cookie,
				      bool will_modify)
{
	if (fscache_cookie_valid(cookie) &&
	    cookie->type != FSCACHE_COOKIE_TYPE_INDEX)
		__fscache_use_cookie(cookie, will_modify);
}

/**
 * fscache_unuse_cookie - Cease usage of cookie attached to an object
 * @object: Object description
 * @aux_data: Updated auxiliary data (or NULL)
 * @object_size: Revised size of the object (or NULL)
 *
 * Cease usage of the cookie attached to an object.  When the users count
 * reaches zero then the cookie relinquishment will be permitted to proceed.
 */
static inline void fscache_unuse_cookie(struct fscache_cookie *cookie,
					const void *aux_data,
					const loff_t *object_size)
{
	if (fscache_cookie_valid(cookie) &&
	    cookie->type != FSCACHE_COOKIE_TYPE_INDEX)
		__fscache_unuse_cookie(cookie, aux_data, object_size);
}

/**
 * fscache_relinquish_cookie - Return the cookie to the cache, maybe discarding
 * it
 * @cookie: The cookie being returned
 * @retire: True if the cache object the cookie represents is to be discarded
 *
 * This function returns a cookie to the cache, forcibly discarding the
 * associated cache object if retire is set to true.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_relinquish_cookie(struct fscache_cookie *cookie, bool retire)
{
	if (fscache_cookie_valid(cookie))
		__fscache_relinquish_cookie(cookie, retire);
}

/**
 * fscache_update_cookie - Request that a cache object be updated
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 * @object_size: The current size of the object (may be NULL)
 *
 * Request an update of the index data for the cache object associated with the
 * cookie.  The auxiliary data on the cookie will be updated first if @aux_data
 * is set and the object size will be updated and the object possibly trimmed
 * if @object_size is set.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_update_cookie(struct fscache_cookie *cookie, const void *aux_data,
			   const loff_t *object_size)
{
	if (fscache_cookie_valid(cookie))
		__fscache_update_cookie(cookie, aux_data, object_size);
}

/**
 * fscache_resize_cookie - Request that a cache object be resized
 * @cookie: The cookie representing the cache object
 * @new_size: The new size of the object (may be NULL)
 *
 * Request that the size of an object be changed.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for a complete
 * description.
 */
static inline
void fscache_resize_cookie(struct fscache_cookie *cookie, loff_t new_size)
{
	if (fscache_cookie_valid(cookie))
		__fscache_resize_cookie(cookie, new_size);
}

/**
 * fscache_pin_cookie - Pin a data-storage cache object in its cache
 * @cookie: The cookie representing the cache object
 *
 * Permit data-storage cache objects to be pinned in the cache.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
int fscache_pin_cookie(struct fscache_cookie *cookie)
{
	return -ENOBUFS;
}

/**
 * fscache_pin_cookie - Unpin a data-storage cache object in its cache
 * @cookie: The cookie representing the cache object
 *
 * Permit data-storage cache objects to be unpinned from the cache.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_unpin_cookie(struct fscache_cookie *cookie)
{
}

/**
 * fscache_invalidate - Notify cache that an object needs invalidation
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 * @size: The revised size of the object.
 * @flags: Invalidation flags (FSCACHE_INVAL_*)
 *
 * Notify the cache that an object is needs to be invalidated and that it
 * should abort any retrievals or stores it is doing on the cache.  The object
 * is then marked non-caching until such time as the invalidation is complete.
 *
 * FSCACHE_INVAL_LIGHT indicates that if the object has been invalidated and
 * replaced by a temporary object, the temporary object need not be replaced
 * again.  This is primarily intended for use with FSCACHE_ADV_SINGLE_CHUNK.
 *
 * FSCACHE_INVAL_DIO_WRITE indicates that this is due to a direct I/O write and
 * may cause caching to be suspended on this cookie.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_invalidate(struct fscache_cookie *cookie,
			const void *aux_data, loff_t size, unsigned int flags)
{
	if (fscache_cookie_valid(cookie))
		__fscache_invalidate(cookie, aux_data, size, flags);
}

/**
 * fscache_init_io_request - Initialise an I/O request
 * @req: The I/O request to initialise
 * @cookie: The I/O cookie to access
 * @ops: The operations table to set
 */
static inline void fscache_init_io_request(struct fscache_io_request *req,
					   struct fscache_cookie *cookie,
					   const struct fscache_io_request_ops *ops)
{
	req->ops = ops;
	if (fscache_cookie_valid(cookie))
		__fscache_init_io_request(req, cookie);
}

/**
 * fscache_free_io_request - Clean up an I/O request
 * @req: The I/O request to clean
 */
static inline
void fscache_free_io_request(struct fscache_io_request *req)
{
	if (fscache_cookie_valid(req->cookie))
		__fscache_free_io_request(req);
}

/**
 * fscache_shape_request - Shape an request to fit cache granulation
 * @cookie: The cache cookie to access
 * @shape: The request proposed by the VM/filesystem (gets modified).
 *
 * Shape the size and position of a cache I/O request such that either the
 * region will entirely be read from the server or entirely read from the
 * cache.  The proposed region may be adjusted by a combination of extending
 * the front forward and/or extending or shrinking the end.  In any case, the
 * first page of the proposed request will be contained in the revised extent.
 *
 * The function sets shape->to_be_done to FSCACHE_READ_FROM_CACHE to indicate
 * that the data is resident in the cache and can be read from there,
 * FSCACHE_WRITE_TO_CACHE to indicate that the data isn't present, but the
 * netfs should write it, FSCACHE_FILL_WITH_ZERO to indicate that the data
 * should be all zeros on the server and can just be fabricated locally or
 * FSCACHE_READ_FROM_SERVER to indicate that there's no cache or an error
 * occurred and the netfs should just read from the server.
 */
static inline
void fscache_shape_request(struct fscache_cookie *cookie,
			   struct fscache_request_shape *shape)
{
	shape->to_be_done	= FSCACHE_READ_FROM_SERVER;
	shape->granularity	= 1;
	shape->dio_block_size	= 1;
	shape->actual_nr_pages	= shape->proposed_nr_pages;
	shape->actual_start	= shape->proposed_start;

	if (fscache_cookie_valid(cookie))
		__fscache_shape_request(cookie, shape);
	else if (((loff_t)shape->proposed_start << PAGE_SHIFT) >= shape->i_size)
		shape->to_be_done = FSCACHE_FILL_WITH_ZERO;
}

/**
 * fscache_read - Read data from the cache.
 * @req: The I/O request descriptor
 * @iter: The buffer to read into
 *
 * The cache will attempt to read from the object referred to by the cookie,
 * using the size and position described in the request.  The data will be
 * transferred to the buffer described by the iterator specified in the request.
 *
 * If this fails or can't be done, an error will be set in the request
 * descriptor and the netfs must reissue the read to the server.
 *
 * Note that the length and position of the request should be aligned to the DIO
 * block size returned by fscache_shape_request().
 *
 * If req->done is set, the request will be submitted as asynchronous I/O and
 * -EIOCBQUEUED may be returned to indicate that the operation is in progress.
 * The done function will be called when the operation is concluded either way.
 *
 * If req->done is not set, the request will be submitted as synchronous I/O and
 * will be completed before the function returns.
 */
static inline
int fscache_read(struct fscache_io_request *req, struct iov_iter *iter)
{
	if (fscache_cookie_valid(req->cookie))
		return __fscache_read(req, iter);
	req->error = -ENODATA;
	if (req->io_done)
		req->io_done(req);
	return -ENODATA;
}


/**
 * fscache_write - Write data to the cache.
 * @req: The I/O request description
 * @iter: The data to write
 *
 * The cache will attempt to write to the object referred to by the cookie,
 * using the size and position described in the request.  The data will be
 * transferred from the iterator specified in the request.
 *
 * If this fails or can't be done, an error will be set in the request
 * descriptor.
 *
 * Note that the length and position of the request should be aligned to the DIO
 * block size returned by fscache_shape_request().
 *
 * If req->io_done is set, the request will be submitted as asynchronous I/O and
 * -EIOCBQUEUED may be returned to indicate that the operation is in progress.
 * The done function will be called when the operation is concluded either way.
 *
 * If req->io_done is not set, the request will be submitted as synchronous I/O and
 * will be completed before the function returns.
 */
static inline
int fscache_write(struct fscache_io_request *req, struct iov_iter *iter)
{
	if (fscache_cookie_valid(req->cookie))
		return __fscache_write(req, iter);
	req->error = -ENOBUFS;
	if (req->io_done)
		req->io_done(req);
	return -ENOBUFS;
}

extern int fscache_read_helper_page_list(struct fscache_io_request *,
					 struct list_head *,
					 pgoff_t);
extern int fscache_read_helper_locked_page(struct fscache_io_request *,
					   struct page *,
					   pgoff_t);
extern int fscache_read_helper_for_write(struct fscache_io_request *,
					 struct page **,
					 pgoff_t,
					 pgoff_t,
					 unsigned int);

#endif /* _LINUX_FSCACHE_H */
