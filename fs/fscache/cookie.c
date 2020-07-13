// SPDX-License-Identifier: GPL-2.0-or-later
/* netfs cookie management
 *
 * Copyright (C) 2004-2007, 2019 Red Hat, Inc. All Rights Reserved.
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

#define fscache_cookie_hash_shift 15
static struct hlist_bl_head fscache_cookie_hash[1 << fscache_cookie_hash_shift];
static LIST_HEAD(fscache_cookies);
static DEFINE_RWLOCK(fscache_cookies_lock);

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

	cookie->type	= type;
	cookie->advice	= advice;
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

	cookie->parent = parent;
	atomic_set(&cookie->usage, 1);
	atomic_set(&cookie->n_children, 0);
	atomic_set(&cookie->n_ops, 1);
	cookie->debug_id = atomic_inc_return(&fscache_cookie_debug_id);

	cookie->stage = FSCACHE_COOKIE_STAGE_QUIESCENT;

	/* We keep the active count elevated until relinquishment to prevent an
	 * attempt to wake up every time the object operations queue quiesces.
	 */
	atomic_set(&cookie->n_active, 1);

	cookie->preferred_cache	= fscache_get_cache_tag(preferred_cache);

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
	loff_t object_size)
{
	struct fscache_cookie *candidate, *cookie;

	_enter("{%s},{%s}",
	       parent ? parent->type_name : "<no-parent>", type_name);

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
	trace_fscache_cookie(candidate, fscache_cookie_new_acquire, 1);

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
	fscache_stat(&fscache_n_acquires_ok);
	_leave(" = c=%08x", cookie->debug_id);

out:
	fscache_free_cookie(candidate);
	return cookie;
}
EXPORT_SYMBOL(__fscache_acquire_cookie);

/*
 * Start using the cookie for I/O.  This prevents the backing object from being
 * reaped by VM pressure.
 */
void __fscache_use_cookie(struct fscache_cookie *cookie, bool will_modify)
{
	enum fscache_cookie_stage stage;

	_enter("c=%08x", cookie->debug_id);

	ASSERT(cookie->type != FSCACHE_COOKIE_TYPE_INDEX);

	spin_lock(&cookie->lock);

	atomic_inc(&cookie->n_active);

again:
	stage = cookie->stage;
	switch (stage) {
	case FSCACHE_COOKIE_STAGE_QUIESCENT:
		cookie->stage = FSCACHE_COOKIE_STAGE_INITIALISING;
		spin_unlock(&cookie->lock);

		/* The lookup job holds its own active increment */
		atomic_inc(&cookie->n_active);
		fscache_dispatch(cookie, NULL, 0, fscache_lookup_object);
		break;

	case FSCACHE_COOKIE_STAGE_INITIALISING:
	case FSCACHE_COOKIE_STAGE_LOOKING_UP:
		spin_unlock(&cookie->lock);
		wait_var_event(&cookie->stage, cookie->stage != stage);
		spin_lock(&cookie->lock);
		goto again;

	case FSCACHE_COOKIE_STAGE_NO_DATA_YET:
	case FSCACHE_COOKIE_STAGE_ACTIVE:
	case FSCACHE_COOKIE_STAGE_INVALIDATING:
		// TODO: Handle will_modify
		spin_unlock(&cookie->lock);
		break;

	case FSCACHE_COOKIE_STAGE_DEAD:
		spin_unlock(&cookie->lock);
		kdebug("dead");
		break;
	}

	_leave("");
}
EXPORT_SYMBOL(__fscache_use_cookie);

/*
 * Stop using the cookie for I/O.
 */
void __fscache_unuse_cookie(struct fscache_cookie *cookie,
			    const void *aux_data, const loff_t *object_size)
{
	if (aux_data || object_size)
		__fscache_update_cookie(cookie, aux_data, object_size);
	if (atomic_dec_and_test(&cookie->n_active))
		wake_up_var(&cookie->n_active);
}
EXPORT_SYMBOL(__fscache_unuse_cookie);

/*
 * Attempt to attach the object to the list on the cookie or, if there's an
 * object already attached, then that is used instead and a ref is taken on it
 * for the caller.  Returns a pointer to whichever object is selected.
 */
struct fscache_object *fscache_attach_object(struct fscache_cookie *cookie,
					     struct fscache_object *object)
{
	struct fscache_object *parent, *p, *ret = NULL;
	struct fscache_cache *cache = object->cache;

	_enter("{%s},{OBJ%x}", cookie->type_name, object->debug_id);

	ASSERTCMP(object->cookie, ==, cookie);

	spin_lock(&cookie->lock);

	/* there may be multiple initial creations of this object, but we only
	 * want one */
	hlist_for_each_entry(p, &cookie->backing_objects, cookie_link) {
		if (p->cache == object->cache)
			goto exists;
	}

	/* pin the parent object */
	spin_lock_nested(&cookie->parent->lock, 1);

	parent = object->parent;

	spin_lock(&parent->lock);
	parent->n_children++;
	spin_unlock(&parent->lock);

	spin_unlock(&cookie->parent->lock);

	/* attach to the cache's object list */
	if (list_empty(&object->cache_link)) {
		spin_lock(&cache->object_list_lock);
		list_add_tail(&object->cache_link, &cache->object_list);
		spin_unlock(&cache->object_list_lock);
	}

	/* Attach to the cookie.  The object already has a ref on it. */
	hlist_add_head(&object->cookie_link, &cookie->backing_objects);

	fscache_objlist_add(object);
	cookie->stage = FSCACHE_COOKIE_STAGE_LOOKING_UP;
	wake_up_var(&cookie->stage);

out_grab:
	ret = cache->ops->grab_object(object, fscache_obj_get_attach);
	spin_unlock(&cookie->lock);
	_leave(" = %p", ret);
	return ret;

exists:
	object = p;
	goto out_grab;
}

void fscache_set_cookie_stage(struct fscache_cookie *cookie,
			      enum fscache_cookie_stage stage)
{
	if (cookie->stage != stage) {
		spin_lock(&cookie->lock);
		cookie->stage = stage;
		spin_unlock(&cookie->lock);
		wake_up_var(&cookie->stage);
	}
}

/*
 * Invalidate an object.  Callable with spinlocks held.
 */
void __fscache_invalidate(struct fscache_cookie *cookie)
{
	_enter("{%s}", cookie->type_name);

	fscache_stat(&fscache_n_invalidates);

	/* Only permit invalidation of data files.  Invalidating an index will
	 * require the caller to release all its attachments to the tree rooted
	 * there, and if it's doing that, it may as well just retire the
	 * cookie.
	 */
	ASSERTCMP(cookie->type, ==, FSCACHE_COOKIE_TYPE_DATAFILE);

	if (!hlist_empty(&cookie->backing_objects) &&
	    test_and_set_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags))
		fscache_dispatch(cookie, NULL, 0, fscache_invalidate_object);
}
EXPORT_SYMBOL(__fscache_invalidate);

/*
 * Update the index entries backing a cookie.  The writeback is done lazily.
 */
void __fscache_update_cookie(struct fscache_cookie *cookie,
			     const void *aux_data, const loff_t *object_size)
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

	fscache_update_aux(cookie, aux_data, object_size);
	hlist_for_each_entry(object, &cookie->backing_objects, cookie_link) {
		set_bit(FSCACHE_OBJECT_NEEDS_UPDATE, &object->flags);
	}

	spin_unlock(&cookie->lock);
	_leave("");
}
EXPORT_SYMBOL(__fscache_update_cookie);

/*
 * release a cookie back to the cache
 * - the object will be marked as recyclable on disk if retire is true
 * - all dependents of this cookie must have already been unregistered
 *   (indices/files/pages)
 */
void __fscache_relinquish_cookie(struct fscache_cookie *cookie, bool retire)
{
	fscache_stat(&fscache_n_relinquishes);
	if (retire)
		fscache_stat(&fscache_n_relinquishes_retire);

	if (!cookie) {
		fscache_stat(&fscache_n_relinquishes_null);
		_leave(" [no cookie]");
		return;
	}

	_enter("%p{%s,%d},%d",
	       cookie, cookie->type_name,
	       atomic_read(&cookie->n_active), retire);

	trace_fscache_relinquish(cookie, retire);

	/* No further netfs-accessing operations on this cookie permitted */
	if (test_and_set_bit(FSCACHE_COOKIE_RELINQUISHED, &cookie->flags))
		BUG();

	/* Mark the cookie out of service and wait for cessation of I/O. */
	spin_lock(&cookie->lock);
	cookie->stage = FSCACHE_COOKIE_STAGE_DEAD;
	atomic_dec(&cookie->n_ops);
	spin_unlock(&cookie->lock);

	wait_var_event(&cookie->n_ops, atomic_read(&cookie->n_ops) == 0);

	/* Dispose of the backing objects */
	if (!hlist_empty(&cookie->backing_objects))
		fscache_dispatch(cookie, NULL, retire, fscache_discard_objects);

	if (atomic_read(&cookie->n_children) != 0) {
		pr_err("Cookie '%s' still has children\n",
		       cookie->type_name);
		BUG();
	}

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

	_enter("%p", cookie);

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
EXPORT_SYMBOL(fscache_cookie_put);

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
			 "COOKIE   PARENT   USAGE CHILD ACT OPS TY S FL  DEF             \n"
			 "======== ======== ===== ===== === === == = === ================\n"
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
		   "%08x %08x %5d %5d %3d %3d %s %u %03lx %-16s",
		   cookie->debug_id,
		   cookie->parent ? cookie->parent->debug_id : 0,
		   atomic_read(&cookie->usage),
		   atomic_read(&cookie->n_children),
		   atomic_read(&cookie->n_active),
		   atomic_read(&cookie->n_ops) - 1,
		   type,
		   cookie->stage,
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
