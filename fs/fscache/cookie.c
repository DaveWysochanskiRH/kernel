// SPDX-License-Identifier: GPL-2.0-or-later
/* netfs cookie management
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * See Documentation/filesystems/caching/netfs-api.rst for more information on
 * the netfs API.
 */

#define FSCACHE_DEBUG_LEVEL COOKIE
#include <linux/module.h>
#include <linux/slab.h>
#include "internal.h"

struct kmem_cache *fscache_cookie_jar;

static atomic_t fscache_object_debug_id = ATOMIC_INIT(0);

#define fscache_cookie_hash_shift 15
static struct hlist_bl_head fscache_cookie_hash[1 << fscache_cookie_hash_shift];
static LIST_HEAD(fscache_cookies);
static DEFINE_RWLOCK(fscache_cookies_lock);

static int fscache_acquire_non_index_cookie(struct fscache_cookie *cookie);
static int fscache_alloc_object(struct fscache_cache *cache,
				struct fscache_cookie *cookie);
static int fscache_attach_object(struct fscache_cookie *cookie,
				 struct fscache_object *object);

static void fscache_print_cookie(struct fscache_cookie *cookie, char prefix)
{
	struct fscache_object *object;
	struct hlist_node *o;
	const u8 *k;
	unsigned loop;

	pr_err("%c-cookie c=%08x [p=%08x fl=%lx nc=%u na=%u]\n",
	       prefix,
	       cookie->debug_id,
	       cookie->parent ? cookie->parent->debug_id : 0,
	       cookie->flags,
	       atomic_read(&cookie->n_children),
	       atomic_read(&cookie->n_active));
	pr_err("%c-cookie d=%s\n",
	       prefix,
	       cookie->type_name);

	o = READ_ONCE(cookie->backing_objects.first);
	if (o) {
		object = hlist_entry(o, struct fscache_object, cookie_link);
		pr_err("%c-cookie o=%u\n", prefix, object->debug_id);
	}

	pr_err("%c-key=[%u] '", prefix, cookie->key_len);
	k = (cookie->key_len <= sizeof(cookie->inline_key)) ?
		cookie->inline_key : cookie->key;
	for (loop = 0; loop < cookie->key_len; loop++)
		pr_cont("%02x", k[loop]);
	pr_cont("'\n");
}

void fscache_free_cookie(struct fscache_cookie *cookie)
{
	if (cookie) {
		BUG_ON(!hlist_empty(&cookie->backing_objects));
		write_lock(&fscache_cookies_lock);
		list_del(&cookie->proc_link);
		write_unlock(&fscache_cookies_lock);
		if (cookie->aux_len > sizeof(cookie->inline_aux))
			kfree(cookie->aux);
		if (cookie->key_len > sizeof(cookie->inline_key))
			kfree(cookie->key);
		fscache_put_cache_tag(cookie->preferred_cache);
		kmem_cache_free(fscache_cookie_jar, cookie);
	}
}

/*
 * Set the index key in a cookie.  The cookie struct has space for a 16-byte
 * key plus length and hash, but if that's not big enough, it's instead a
 * pointer to a buffer containing 3 bytes of hash, 1 byte of length and then
 * the key data.
 */
static int fscache_set_key(struct fscache_cookie *cookie,
			   const void *index_key, size_t index_key_len)
{
	unsigned long long h;
	u32 *buf;
	int bufs;
	int i;

	bufs = DIV_ROUND_UP(index_key_len, sizeof(*buf));

	if (index_key_len > sizeof(cookie->inline_key)) {
		buf = kcalloc(bufs, sizeof(*buf), GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		cookie->key = buf;
	} else {
		buf = (u32 *)cookie->inline_key;
	}

	memcpy(buf, index_key, index_key_len);

	/* Calculate a hash and combine this with the length in the first word
	 * or first half word
	 */
	h = (unsigned long)cookie->parent;
	h += index_key_len + cookie->type;

	for (i = 0; i < bufs; i++)
		h += buf[i];

	cookie->key_hash = h ^ (h >> 32);
	return 0;
}

static long fscache_compare_cookie(const struct fscache_cookie *a,
				   const struct fscache_cookie *b)
{
	const void *ka, *kb;

	if (a->key_hash != b->key_hash)
		return (long)a->key_hash - (long)b->key_hash;
	if (a->parent != b->parent)
		return (long)a->parent - (long)b->parent;
	if (a->key_len != b->key_len)
		return (long)a->key_len - (long)b->key_len;
	if (a->type != b->type)
		return (long)a->type - (long)b->type;

	if (a->key_len <= sizeof(a->inline_key)) {
		ka = &a->inline_key;
		kb = &b->inline_key;
	} else {
		ka = a->key;
		kb = b->key;
	}
	return memcmp(ka, kb, a->key_len);
}

static atomic_t fscache_cookie_debug_id = ATOMIC_INIT(1);

/*
 * Allocate a cookie.
 */
struct fscache_cookie *fscache_alloc_cookie(
	struct fscache_cookie *parent,
	enum fscache_cookie_type type,
	const char *type_name,
	u8 advice,
	struct fscache_cache_tag *preferred_cache,
	const void *index_key, size_t index_key_len,
	const void *aux_data, size_t aux_data_len,
	loff_t object_size)
{
	struct fscache_cookie *cookie;

	/* allocate and initialise a cookie */
	cookie = kmem_cache_zalloc(fscache_cookie_jar, GFP_KERNEL);
	if (!cookie)
		return NULL;

	cookie->type = type;
	cookie->advice = advice;
	cookie->key_len = index_key_len;
	cookie->aux_len = aux_data_len;
	cookie->object_size = object_size;
	strlcpy(cookie->type_name, type_name, sizeof(cookie->type_name));

	if (fscache_set_key(cookie, index_key, index_key_len) < 0)
		goto nomem;

	if (cookie->aux_len <= sizeof(cookie->inline_aux)) {
		memcpy(cookie->inline_aux, aux_data, cookie->aux_len);
	} else {
		cookie->aux = kmemdup(aux_data, cookie->aux_len, GFP_KERNEL);
		if (!cookie->aux)
			goto nomem;
	}

	atomic_set(&cookie->usage, 1);
	atomic_set(&cookie->n_children, 0);
	cookie->debug_id = atomic_inc_return(&fscache_cookie_debug_id);

	/* We keep the active count elevated until relinquishment to prevent an
	 * attempt to wake up every time the object operations queue quiesces.
	 */
	atomic_set(&cookie->n_active, 1);

	cookie->parent		= parent;
	cookie->preferred_cache	= fscache_get_cache_tag(preferred_cache);
	
	cookie->flags		= (1 << FSCACHE_COOKIE_NO_DATA_YET);
	spin_lock_init(&cookie->lock);
	INIT_HLIST_HEAD(&cookie->backing_objects);

	write_lock(&fscache_cookies_lock);
	list_add_tail(&cookie->proc_link, &fscache_cookies);
	write_unlock(&fscache_cookies_lock);
	return cookie;

nomem:
	fscache_free_cookie(cookie);
	return NULL;
}

/*
 * Attempt to insert the new cookie into the hash.  If there's a collision, we
 * return the old cookie if it's not in use and an error otherwise.
 */
struct fscache_cookie *fscache_hash_cookie(struct fscache_cookie *candidate)
{
	struct fscache_cookie *cursor;
	struct hlist_bl_head *h;
	struct hlist_bl_node *p;
	unsigned int bucket;

	bucket = candidate->key_hash & (ARRAY_SIZE(fscache_cookie_hash) - 1);
	h = &fscache_cookie_hash[bucket];

	hlist_bl_lock(h);
	hlist_bl_for_each_entry(cursor, p, h, hash_link) {
		if (fscache_compare_cookie(candidate, cursor) == 0)
			goto collision;
	}

	__set_bit(FSCACHE_COOKIE_ACQUIRED, &candidate->flags);
	fscache_cookie_get(candidate->parent, fscache_cookie_get_acquire_parent);
	atomic_inc(&candidate->parent->n_children);
	hlist_bl_add_head(&candidate->hash_link, h);
	hlist_bl_unlock(h);
	return candidate;

collision:
	if (test_and_set_bit(FSCACHE_COOKIE_ACQUIRED, &cursor->flags)) {
		trace_fscache_cookie(cursor, fscache_cookie_collision,
				     atomic_read(&cursor->usage));
		pr_err("Duplicate cookie detected\n");
		fscache_print_cookie(cursor, 'O');
		fscache_print_cookie(candidate, 'N');
		hlist_bl_unlock(h);
		return NULL;
	}

	fscache_cookie_get(cursor, fscache_cookie_get_reacquire);
	hlist_bl_unlock(h);
	return cursor;
}

/*
 * request a cookie to represent an object (index, datafile, xattr, etc)
 * - parent specifies the parent object
 *   - the top level index cookie for each netfs is stored in the fscache_netfs
 *     struct upon registration
 * - all attached caches will be searched to see if they contain this object
 * - index objects aren't stored on disk until there's a dependent file that
 *   needs storing
 * - other objects are stored in a selected cache immediately, and all the
 *   indices forming the path to it are instantiated if necessary
 * - we never let on to the netfs about errors
 *   - we may set a negative cookie pointer, but that's okay
 */
struct fscache_cookie *__fscache_acquire_cookie(
	struct fscache_cookie *parent,
	enum fscache_cookie_type type,
	const char *type_name,
	u8 advice,
	struct fscache_cache_tag *preferred_cache,
	const void *index_key, size_t index_key_len,
	const void *aux_data, size_t aux_data_len,
	loff_t object_size,
	bool enable)
{
	struct fscache_cookie *candidate, *cookie;

	_enter("{%s},{%s},%u",
	       parent ? parent->type_name : "<no-parent>", type_name, enable);

	if (!index_key || !index_key_len || index_key_len > 255 || aux_data_len > 255)
		return NULL;
	if (!aux_data || !aux_data_len) {
		aux_data = NULL;
		aux_data_len = 0;
	}

	fscache_stat(&fscache_n_acquires);

	/* if there's no parent cookie, then we don't create one here either */
	if (!parent) {
		fscache_stat(&fscache_n_acquires_null);
		_leave(" [no parent]");
		return NULL;
	}

	/* validate the definition */
	BUG_ON(type == FSCACHE_COOKIE_TYPE_INDEX &&
	       parent->type != FSCACHE_COOKIE_TYPE_INDEX);

	candidate = fscache_alloc_cookie(parent, type, type_name, advice,
					 preferred_cache,
					 index_key, index_key_len,
					 aux_data, aux_data_len,
					 object_size);
	if (!candidate) {
		fscache_stat(&fscache_n_acquires_oom);
		_leave(" [ENOMEM]");
		return NULL;
	}

	cookie = fscache_hash_cookie(candidate);
	if (!cookie) {
		trace_fscache_cookie(candidate, fscache_cookie_discard, 1);
		goto out;
	}

	if (cookie == candidate)
		candidate = NULL;

	switch (cookie->type) {
	case FSCACHE_COOKIE_TYPE_INDEX:
		fscache_stat(&fscache_n_cookie_index);
		break;
	case FSCACHE_COOKIE_TYPE_DATAFILE:
		fscache_stat(&fscache_n_cookie_data);
		break;
	default:
		fscache_stat(&fscache_n_cookie_special);
		break;
	}

	trace_fscache_acquire(cookie);

	if (enable) {
		/* if the object is an index then we need do nothing more here
		 * - we create indices on disk when we need them as an index
		 * may exist in multiple caches */
		if (cookie->type != FSCACHE_COOKIE_TYPE_INDEX) {
			if (fscache_acquire_non_index_cookie(cookie) == 0) {
				set_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags);
			} else {
				atomic_dec(&parent->n_children);
				fscache_cookie_put(cookie,
						   fscache_cookie_put_acquire_nobufs);
				fscache_stat(&fscache_n_acquires_nobufs);
				_leave(" = NULL");
				return NULL;
			}
		} else {
			set_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags);
		}
	}

	fscache_stat(&fscache_n_acquires_ok);

out:
	fscache_free_cookie(candidate);
	return cookie;
}
EXPORT_SYMBOL(__fscache_acquire_cookie);

/*
 * Enable a cookie to permit it to accept new operations.
 */
void __fscache_enable_cookie(struct fscache_cookie *cookie,
			     const void *aux_data,
			     loff_t object_size,
			     bool (*can_enable)(void *data),
			     void *data)
{
	_enter("%x", cookie->debug_id);

	trace_fscache_enable(cookie);

	wait_on_bit_lock(&cookie->flags, FSCACHE_COOKIE_ENABLEMENT_LOCK,
			 TASK_UNINTERRUPTIBLE);

	cookie->object_size = object_size;
	fscache_update_aux(cookie, aux_data);

	if (test_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags))
		goto out_unlock;

	if (can_enable && !can_enable(data)) {
		/* The netfs decided it didn't want to enable after all */
	} else if (cookie->type != FSCACHE_COOKIE_TYPE_INDEX) {
		/* Wait for outstanding disablement to complete */
		__fscache_wait_on_invalidate(cookie);

		if (fscache_acquire_non_index_cookie(cookie) == 0)
			set_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags);
	} else {
		set_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags);
	}

out_unlock:
	clear_bit_unlock(FSCACHE_COOKIE_ENABLEMENT_LOCK, &cookie->flags);
	wake_up_bit(&cookie->flags, FSCACHE_COOKIE_ENABLEMENT_LOCK);
}
EXPORT_SYMBOL(__fscache_enable_cookie);

/*
 * acquire a non-index cookie
 * - this must make sure the index chain is instantiated and instantiate the
 *   object representation too
 */
static int fscache_acquire_non_index_cookie(struct fscache_cookie *cookie)
{
	struct fscache_object *object;
	struct fscache_cache *cache;
	int ret;

	_enter("");

	set_bit(FSCACHE_COOKIE_UNAVAILABLE, &cookie->flags);

	/* now we need to see whether the backing objects for this cookie yet
	 * exist, if not there'll be nothing to search */
	down_read(&fscache_addremove_sem);

	if (list_empty(&fscache_cache_list)) {
		up_read(&fscache_addremove_sem);
		_leave(" = 0 [no caches]");
		return 0;
	}

	/* select a cache in which to store the object */
	cache = fscache_select_cache_for_object(cookie->parent);
	if (!cache) {
		up_read(&fscache_addremove_sem);
		fscache_stat(&fscache_n_acquires_no_cache);
		_leave(" = -ENOMEDIUM [no cache]");
		return -ENOMEDIUM;
	}

	_debug("cache %s", cache->tag->name);

	set_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags);

	/* ask the cache to allocate objects for this cookie and its parent
	 * chain */
	ret = fscache_alloc_object(cache, cookie);
	if (ret < 0) {
		up_read(&fscache_addremove_sem);
		_leave(" = %d", ret);
		return ret;
	}

	spin_lock(&cookie->lock);
	if (hlist_empty(&cookie->backing_objects)) {
		spin_unlock(&cookie->lock);
		goto unavailable;
	}

	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	/* initiate the process of looking up all the objects in the chain
	 * (done by fscache_initialise_object()) */
	fscache_raise_event(object, FSCACHE_OBJECT_EV_NEW_CHILD);

	spin_unlock(&cookie->lock);

	/* we may be required to wait for lookup to complete at this point */
	if (!fscache_defer_lookup) {
		wait_on_bit(&cookie->flags, FSCACHE_COOKIE_LOOKING_UP,
			    TASK_UNINTERRUPTIBLE);
		if (test_bit(FSCACHE_COOKIE_UNAVAILABLE, &cookie->flags))
			goto unavailable;
	}

	up_read(&fscache_addremove_sem);
	_leave(" = 0 [deferred]");
	return 0;

unavailable:
	up_read(&fscache_addremove_sem);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}

/*
 * recursively allocate cache object records for a cookie/cache combination
 * - caller must be holding the addremove sem
 */
static int fscache_alloc_object(struct fscache_cache *cache,
				struct fscache_cookie *cookie)
{
	struct fscache_object *object;
	int ret;

	_enter("%s,%x{%s}", cache->tag->name, cookie->debug_id, cookie->type_name);

	spin_lock(&cookie->lock);
	hlist_for_each_entry(object, &cookie->backing_objects,
			     cookie_link) {
		if (object->cache == cache)
			goto object_already_extant;
	}
	spin_unlock(&cookie->lock);

	/* ask the cache to allocate an object (we may end up with duplicate
	 * objects at this stage, but we sort that out later) */
	fscache_stat(&fscache_n_cop_alloc_object);
	object = cache->ops->alloc_object(cache, cookie);
	fscache_stat_d(&fscache_n_cop_alloc_object);
	if (IS_ERR(object)) {
		fscache_stat(&fscache_n_object_no_alloc);
		ret = PTR_ERR(object);
		goto error;
	}

	ASSERTCMP(object->cookie, ==, cookie);
	fscache_stat(&fscache_n_object_alloc);

	object->debug_id = atomic_inc_return(&fscache_object_debug_id);

	_debug("ALLOC OBJ%x: %s {%lx}",
	       object->debug_id, cookie->type_name, object->events);

	ret = fscache_alloc_object(cache, cookie->parent);
	if (ret < 0)
		goto error_put;

	/* only attach if we managed to allocate all we needed, otherwise
	 * discard the object we just allocated and instead use the one
	 * attached to the cookie */
	if (fscache_attach_object(cookie, object) < 0) {
		fscache_stat(&fscache_n_cop_put_object);
		cache->ops->put_object(object, fscache_obj_put_attach_fail);
		fscache_stat_d(&fscache_n_cop_put_object);
	}

	_leave(" = 0");
	return 0;

object_already_extant:
	ret = -ENOBUFS;
	if (fscache_object_is_dying(object) ||
	    fscache_cache_is_broken(object)) {
		spin_unlock(&cookie->lock);
		goto error;
	}
	spin_unlock(&cookie->lock);
	_leave(" = 0 [found]");
	return 0;

error_put:
	fscache_stat(&fscache_n_cop_put_object);
	cache->ops->put_object(object, fscache_obj_put_alloc_fail);
	fscache_stat_d(&fscache_n_cop_put_object);
error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * attach a cache object to a cookie
 */
static int fscache_attach_object(struct fscache_cookie *cookie,
				 struct fscache_object *object)
{
	struct fscache_object *p;
	struct fscache_cache *cache = object->cache;
	int ret;

	_enter("{%s},{OBJ%x}", cookie->type_name, object->debug_id);

	ASSERTCMP(object->cookie, ==, cookie);

	spin_lock(&cookie->lock);

	/* there may be multiple initial creations of this object, but we only
	 * want one */
	ret = -EEXIST;
	hlist_for_each_entry(p, &cookie->backing_objects, cookie_link) {
		if (p->cache == object->cache) {
			if (fscache_object_is_dying(p))
				ret = -ENOBUFS;
			goto cant_attach_object;
		}
	}

	/* pin the parent object */
	spin_lock_nested(&cookie->parent->lock, 1);
	hlist_for_each_entry(p, &cookie->parent->backing_objects,
			     cookie_link) {
		if (p->cache == object->cache) {
			if (fscache_object_is_dying(p)) {
				ret = -ENOBUFS;
				spin_unlock(&cookie->parent->lock);
				goto cant_attach_object;
			}
			object->parent = p;
			spin_lock(&p->lock);
			p->n_children++;
			spin_unlock(&p->lock);
			break;
		}
	}
	spin_unlock(&cookie->parent->lock);

	/* attach to the cache's object list */
	if (list_empty(&object->cache_link)) {
		spin_lock(&cache->object_list_lock);
		list_add(&object->cache_link, &cache->object_list);
		spin_unlock(&cache->object_list_lock);
	}

	/* Attach to the cookie.  The object already has a ref on it. */
	hlist_add_head(&object->cookie_link, &cookie->backing_objects);

	fscache_objlist_add(object);
	ret = 0;

cant_attach_object:
	spin_unlock(&cookie->lock);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Invalidate an object.  Callable with spinlocks held.
 */
void __fscache_invalidate(struct fscache_cookie *cookie)
{
	struct fscache_object *object;

	_enter("{%s}", cookie->type_name);

	fscache_stat(&fscache_n_invalidates);

	/* Only permit invalidation of data files.  Invalidating an index will
	 * require the caller to release all its attachments to the tree rooted
	 * there, and if it's doing that, it may as well just retire the
	 * cookie.
	 */
	ASSERTCMP(cookie->type, ==, FSCACHE_COOKIE_TYPE_DATAFILE);

	/* If there's an object, we tell the object state machine to handle the
	 * invalidation on our behalf, otherwise there's nothing to do.
	 */
	if (!hlist_empty(&cookie->backing_objects)) {
		spin_lock(&cookie->lock);

		if (fscache_cookie_enabled(cookie) &&
		    !hlist_empty(&cookie->backing_objects) &&
		    !test_and_set_bit(FSCACHE_COOKIE_INVALIDATING,
				      &cookie->flags)) {
			object = hlist_entry(cookie->backing_objects.first,
					     struct fscache_object,
					     cookie_link);
			/* TODO: Do invalidation */
		}

		spin_unlock(&cookie->lock);
	}

	_leave("");
}
EXPORT_SYMBOL(__fscache_invalidate);

/*
 * Wait for object invalidation to complete.
 */
void __fscache_wait_on_invalidate(struct fscache_cookie *cookie)
{
	_enter("%x", cookie->debug_id);

	wait_on_bit(&cookie->flags, FSCACHE_COOKIE_INVALIDATING,
		    TASK_UNINTERRUPTIBLE);

	_leave("");
}
EXPORT_SYMBOL(__fscache_wait_on_invalidate);

/*
 * update the index entries backing a cookie
 */
void __fscache_update_cookie(struct fscache_cookie *cookie, const void *aux_data)
{
	struct fscache_object *object;

	fscache_stat(&fscache_n_updates);

	if (!cookie) {
		fscache_stat(&fscache_n_updates_null);
		_leave(" [no cookie]");
		return;
	}

	_enter("{%s}", cookie->type_name);

	spin_lock(&cookie->lock);

	fscache_update_aux(cookie, aux_data);

	if (fscache_cookie_enabled(cookie)) {
		/* update the index entry on disk in each cache backing this
		 * cookie.
		 */
		hlist_for_each_entry(object,
				     &cookie->backing_objects, cookie_link) {
			fscache_raise_event(object, FSCACHE_OBJECT_EV_UPDATE);
		}
	}

	spin_unlock(&cookie->lock);
	_leave("");
}
EXPORT_SYMBOL(__fscache_update_cookie);

/*
 * Disable a cookie to stop it from accepting new requests from the netfs.
 */
void __fscache_disable_cookie(struct fscache_cookie *cookie,
			      const void *aux_data,
			      bool invalidate)
{
	struct fscache_object *object;
	bool awaken = false;

	_enter("%x,%u", cookie->debug_id, invalidate);

	trace_fscache_disable(cookie);

	ASSERTCMP(atomic_read(&cookie->n_active), >, 0);

	if (atomic_read(&cookie->n_children) != 0) {
		pr_err("Cookie '%s' still has children\n",
		       cookie->type_name);
		BUG();
	}

	wait_on_bit_lock(&cookie->flags, FSCACHE_COOKIE_ENABLEMENT_LOCK,
			 TASK_UNINTERRUPTIBLE);

	fscache_update_aux(cookie, aux_data);

	if (!test_and_clear_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags))
		goto out_unlock_enable;

	/* If the cookie is being invalidated, wait for that to complete first
	 * so that we can reuse the flag.
	 */
	__fscache_wait_on_invalidate(cookie);

	/* Dispose of the backing objects */
	set_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags);

	spin_lock(&cookie->lock);
	if (!hlist_empty(&cookie->backing_objects)) {
		hlist_for_each_entry(object, &cookie->backing_objects, cookie_link) {
			if (invalidate)
				set_bit(FSCACHE_OBJECT_RETIRED, &object->flags);
			fscache_raise_event(object, FSCACHE_OBJECT_EV_KILL);
		}
	} else {
		if (test_and_clear_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags))
			awaken = true;
	}
	spin_unlock(&cookie->lock);
	if (awaken)
		wake_up_bit(&cookie->flags, FSCACHE_COOKIE_INVALIDATING);

	/* Wait for cessation of activity requiring access to the netfs (when
	 * n_active reaches 0).  This makes sure outstanding reads and writes
	 * have completed.
	 */
	if (!atomic_dec_and_test(&cookie->n_active)) {
		wait_var_event(&cookie->n_active,
			       !atomic_read(&cookie->n_active));
	}

	/* Reset the cookie state if it wasn't relinquished */
	if (!test_bit(FSCACHE_COOKIE_RELINQUISHED, &cookie->flags)) {
		atomic_inc(&cookie->n_active);
		set_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);
	}

out_unlock_enable:
	clear_bit_unlock(FSCACHE_COOKIE_ENABLEMENT_LOCK, &cookie->flags);
	wake_up_bit(&cookie->flags, FSCACHE_COOKIE_ENABLEMENT_LOCK);
	_leave("");
}
EXPORT_SYMBOL(__fscache_disable_cookie);

/*
 * release a cookie back to the cache
 * - the object will be marked as recyclable on disk if retire is true
 * - all dependents of this cookie must have already been unregistered
 *   (indices/files/pages)
 */
void __fscache_relinquish_cookie(struct fscache_cookie *cookie,
				 const void *aux_data,
				 bool retire)
{
	fscache_stat(&fscache_n_relinquishes);
	if (retire)
		fscache_stat(&fscache_n_relinquishes_retire);

	if (!cookie) {
		fscache_stat(&fscache_n_relinquishes_null);
		_leave(" [no cookie]");
		return;
	}

	_enter("%x{%s,%d},%d",
	       cookie->debug_id, cookie->type_name,
	       atomic_read(&cookie->n_active), retire);

	trace_fscache_relinquish(cookie, retire);

	/* No further netfs-accessing operations on this cookie permitted */
	if (test_and_set_bit(FSCACHE_COOKIE_RELINQUISHED, &cookie->flags))
		BUG();

	__fscache_disable_cookie(cookie, aux_data, retire);

	if (cookie->parent) {
		ASSERTCMP(atomic_read(&cookie->parent->usage), >, 0);
		ASSERTCMP(atomic_read(&cookie->parent->n_children), >, 0);
		atomic_dec(&cookie->parent->n_children);
	}

	/* Dispose of the netfs's link to the cookie */
	ASSERTCMP(atomic_read(&cookie->usage), >, 0);
	fscache_cookie_put(cookie, fscache_cookie_put_relinquish);

	_leave("");
}
EXPORT_SYMBOL(__fscache_relinquish_cookie);

/*
 * Remove a cookie from the hash table.
 */
static void fscache_unhash_cookie(struct fscache_cookie *cookie)
{
	struct hlist_bl_head *h;
	unsigned int bucket;

	bucket = cookie->key_hash & (ARRAY_SIZE(fscache_cookie_hash) - 1);
	h = &fscache_cookie_hash[bucket];

	hlist_bl_lock(h);
	hlist_bl_del(&cookie->hash_link);
	hlist_bl_unlock(h);
}

/*
 * Drop a reference to a cookie.
 */
void fscache_cookie_put(struct fscache_cookie *cookie,
			enum fscache_cookie_trace where)
{
	struct fscache_cookie *parent;
	int usage;

	_enter("%x", cookie->debug_id);

	do {
		usage = atomic_dec_return(&cookie->usage);
		trace_fscache_cookie(cookie, where, usage);

		if (usage > 0)
			return;
		BUG_ON(usage < 0);

		parent = cookie->parent;
		fscache_unhash_cookie(cookie);
		fscache_free_cookie(cookie);

		cookie = parent;
		where = fscache_cookie_put_parent;
	} while (cookie);

	_leave("");
}

/*
 * Generate a list of extant cookies in /proc/fs/fscache/cookies
 */
static int fscache_cookies_seq_show(struct seq_file *m, void *v)
{
	struct fscache_cookie *cookie;
	unsigned int keylen = 0, auxlen = 0;
	char _type[3], *type;
	u8 *p;

	if (v == &fscache_cookies) {
		seq_puts(m,
			 "COOKIE   PARENT   USAGE CHILD ACT TY FL  DEF             \n"
			 "======== ======== ===== ===== === == === ================\n"
			 );
		return 0;
	}

	cookie = list_entry(v, struct fscache_cookie, proc_link);

	switch (cookie->type) {
	case 0:
		type = "IX";
		break;
	case 1:
		type = "DT";
		break;
	default:
		snprintf(_type, sizeof(_type), "%02u",
			 cookie->type);
		type = _type;
		break;
	}

	seq_printf(m,
		   "%08x %08x %5u %5u %3u %s %03lx %-16s",
		   cookie->debug_id,
		   cookie->parent ? cookie->parent->debug_id : 0,
		   atomic_read(&cookie->usage),
		   atomic_read(&cookie->n_children),
		   atomic_read(&cookie->n_active),
		   type,
		   cookie->flags,
		   cookie->type_name);

	keylen = cookie->key_len;
	auxlen = cookie->aux_len;

	if (keylen > 0 || auxlen > 0) {
		seq_puts(m, " ");
		p = keylen <= sizeof(cookie->inline_key) ?
			cookie->inline_key : cookie->key;
		for (; keylen > 0; keylen--)
			seq_printf(m, "%02x", *p++);
		if (auxlen > 0) {
			seq_puts(m, ", ");
			p = auxlen <= sizeof(cookie->inline_aux) ?
				cookie->inline_aux : cookie->aux;
			for (; auxlen > 0; auxlen--)
				seq_printf(m, "%02x", *p++);
		}
	}

	seq_puts(m, "\n");
	return 0;
}

static void *fscache_cookies_seq_start(struct seq_file *m, loff_t *_pos)
	__acquires(fscache_cookies_lock)
{
	read_lock(&fscache_cookies_lock);
	return seq_list_start_head(&fscache_cookies, *_pos);
}

static void *fscache_cookies_seq_next(struct seq_file *m, void *v, loff_t *_pos)
{
	return seq_list_next(v, &fscache_cookies, _pos);
}

static void fscache_cookies_seq_stop(struct seq_file *m, void *v)
	__releases(rcu)
{
	read_unlock(&fscache_cookies_lock);
}


const struct seq_operations fscache_cookies_seq_ops = {
	.start  = fscache_cookies_seq_start,
	.next   = fscache_cookies_seq_next,
	.stop   = fscache_cookies_seq_stop,
	.show   = fscache_cookies_seq_show,
};
