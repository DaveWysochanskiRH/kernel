/* SPDX-License-Identifier: GPL-2.0-or-later */
/* FS-Cache tracepoints
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM fscache

#if !defined(_TRACE_FSCACHE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FSCACHE_H

#include <linux/fscache.h>
#include <linux/tracepoint.h>

/*
 * Define enums for tracing information.
 */
#ifndef __FSCACHE_DECLARE_TRACE_ENUMS_ONCE_ONLY
#define __FSCACHE_DECLARE_TRACE_ENUMS_ONCE_ONLY

enum fscache_cookie_trace {
	fscache_cookie_collision,
	fscache_cookie_discard,
	fscache_cookie_get_acquire_parent,
	fscache_cookie_get_attach_object,
	fscache_cookie_get_reacquire,
	fscache_cookie_get_register_netfs,
	fscache_cookie_put_acquire_nobufs,
	fscache_cookie_put_dup_netfs,
	fscache_cookie_put_relinquish,
	fscache_cookie_put_object,
	fscache_cookie_put_parent,
};

enum fscache_op_trace {
	fscache_op_cancel,
	fscache_op_cancel_all,
	fscache_op_cancelled,
	fscache_op_completed,
	fscache_op_enqueue_async,
	fscache_op_enqueue_mythread,
	fscache_op_gc,
	fscache_op_init,
	fscache_op_put,
	fscache_op_run,
	fscache_op_signal,
	fscache_op_submit,
	fscache_op_submit_ex,
	fscache_op_work,
	fscache_op_trace__nr
};

#endif

/*
 * Declare tracing information enums and their string mappings for display.
 */
#define fscache_cookie_traces						\
	EM(fscache_cookie_collision,		"*COLLISION*")		\
	EM(fscache_cookie_discard,		"DISCARD")		\
	EM(fscache_cookie_get_acquire_parent,	"GET prn")		\
	EM(fscache_cookie_get_attach_object,	"GET obj")		\
	EM(fscache_cookie_get_reacquire,	"GET raq")		\
	EM(fscache_cookie_get_register_netfs,	"GET net")		\
	EM(fscache_cookie_put_acquire_nobufs,	"PUT nbf")		\
	EM(fscache_cookie_put_dup_netfs,	"PUT dnt")		\
	EM(fscache_cookie_put_relinquish,	"PUT rlq")		\
	EM(fscache_cookie_put_object,		"PUT obj")		\
	E_(fscache_cookie_put_parent,		"PUT prn")

#define fscache_op_traces						\
	EM(fscache_op_cancel,			"Cancel1")		\
	EM(fscache_op_cancel_all,		"CancelA")		\
	EM(fscache_op_cancelled,		"Canclld")		\
	EM(fscache_op_completed,		"Complet")		\
	EM(fscache_op_enqueue_async,		"EnqAsyn")		\
	EM(fscache_op_enqueue_mythread,		"EnqMyTh")		\
	EM(fscache_op_gc,			"GC     ")		\
	EM(fscache_op_init,			"Init   ")		\
	EM(fscache_op_put,			"Put    ")		\
	EM(fscache_op_run,			"Run    ")		\
	EM(fscache_op_signal,			"Signal ")		\
	EM(fscache_op_submit,			"Submit ")		\
	EM(fscache_op_submit_ex,		"SubmitX")		\
	E_(fscache_op_work,			"Work   ")

/*
 * Export enum symbols via userspace.
 */
#undef EM
#undef E_
#define EM(a, b) TRACE_DEFINE_ENUM(a);
#define E_(a, b) TRACE_DEFINE_ENUM(a);

fscache_cookie_traces;

/*
 * Now redefine the EM() and E_() macros to map the enums to the strings that
 * will be printed in the output.
 */
#undef EM
#undef E_
#define EM(a, b)	{ a, b },
#define E_(a, b)	{ a, b }


TRACE_EVENT(fscache_cookie,
	    TP_PROTO(struct fscache_cookie *cookie,
		     enum fscache_cookie_trace where,
		     int usage),

	    TP_ARGS(cookie, where, usage),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(unsigned int,		parent		)
		    __field(enum fscache_cookie_trace,	where		)
		    __field(int,			usage		)
		    __field(int,			n_children	)
		    __field(int,			n_active	)
		    __field(u8,				flags		)
			     ),

	    TP_fast_assign(
		    __entry->cookie	= cookie->debug_id;
		    __entry->parent	= cookie->parent ? cookie->parent->debug_id : 0;
		    __entry->where	= where;
		    __entry->usage	= usage;
		    __entry->n_children	= atomic_read(&cookie->n_children);
		    __entry->n_active	= atomic_read(&cookie->n_active);
		    __entry->flags	= cookie->flags;
			   ),

	    TP_printk("%s c=%08x u=%d p=%08x Nc=%d Na=%d f=%02x",
		      __print_symbolic(__entry->where, fscache_cookie_traces),
		      __entry->cookie, __entry->usage,
		      __entry->parent, __entry->n_children, __entry->n_active,
		      __entry->flags)
	    );

TRACE_EVENT(fscache_netfs,
	    TP_PROTO(struct fscache_netfs *netfs),

	    TP_ARGS(netfs),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __array(char,			name, 8		)
			     ),

	    TP_fast_assign(
		    __entry->cookie		= netfs->primary_index->debug_id;
		    strncpy(__entry->name, netfs->name, 8);
		    __entry->name[7]		= 0;
			   ),

	    TP_printk("c=%08x n=%s",
		      __entry->cookie, __entry->name)
	    );

TRACE_EVENT(fscache_acquire,
	    TP_PROTO(struct fscache_cookie *cookie),

	    TP_ARGS(cookie),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(unsigned int,		parent		)
		    __array(char,			name, 8		)
		    __field(int,			p_usage		)
		    __field(int,			p_n_children	)
		    __field(u8,				p_flags		)
			     ),

	    TP_fast_assign(
		    __entry->cookie		= cookie->debug_id;
		    __entry->parent		= cookie->parent->debug_id;
		    __entry->p_usage		= atomic_read(&cookie->parent->usage);
		    __entry->p_n_children	= atomic_read(&cookie->parent->n_children);
		    __entry->p_flags		= cookie->parent->flags;
		    memcpy(__entry->name, cookie->type_name, 8);
		    __entry->name[7]		= 0;
			   ),

	    TP_printk("c=%08x p=%08x pu=%d pc=%d pf=%02x n=%s",
		      __entry->cookie, __entry->parent, __entry->p_usage,
		      __entry->p_n_children, __entry->p_flags, __entry->name)
	    );

TRACE_EVENT(fscache_relinquish,
	    TP_PROTO(struct fscache_cookie *cookie, bool retire),

	    TP_ARGS(cookie, retire),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(unsigned int,		parent		)
		    __field(int,			usage		)
		    __field(int,			n_children	)
		    __field(int,			n_active	)
		    __field(u8,				flags		)
		    __field(bool,			retire		)
			     ),

	    TP_fast_assign(
		    __entry->cookie	= cookie->debug_id;
		    __entry->parent	= cookie->parent->debug_id;
		    __entry->usage	= atomic_read(&cookie->usage);
		    __entry->n_children	= atomic_read(&cookie->n_children);
		    __entry->n_active	= atomic_read(&cookie->n_active);
		    __entry->flags	= cookie->flags;
		    __entry->retire	= retire;
			   ),

	    TP_printk("c=%08x u=%d p=%08x Nc=%d Na=%d f=%02x r=%u",
		      __entry->cookie, __entry->usage,
		      __entry->parent, __entry->n_children, __entry->n_active,
		      __entry->flags, __entry->retire)
	    );

TRACE_EVENT(fscache_enable,
	    TP_PROTO(struct fscache_cookie *cookie),

	    TP_ARGS(cookie),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(int,			usage		)
		    __field(int,			n_children	)
		    __field(int,			n_active	)
		    __field(u8,				flags		)
			     ),

	    TP_fast_assign(
		    __entry->cookie	= cookie->debug_id;
		    __entry->usage	= atomic_read(&cookie->usage);
		    __entry->n_children	= atomic_read(&cookie->n_children);
		    __entry->n_active	= atomic_read(&cookie->n_active);
		    __entry->flags	= cookie->flags;
			   ),

	    TP_printk("c=%08x u=%d Nc=%d Na=%d f=%02x",
		      __entry->cookie, __entry->usage,
		      __entry->n_children, __entry->n_active, __entry->flags)
	    );

TRACE_EVENT(fscache_disable,
	    TP_PROTO(struct fscache_cookie *cookie),

	    TP_ARGS(cookie),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(int,			usage		)
		    __field(int,			n_children	)
		    __field(int,			n_active	)
		    __field(u8,				flags		)
			     ),

	    TP_fast_assign(
		    __entry->cookie	= cookie->debug_id;
		    __entry->usage	= atomic_read(&cookie->usage);
		    __entry->n_children	= atomic_read(&cookie->n_children);
		    __entry->n_active	= atomic_read(&cookie->n_active);
		    __entry->flags	= cookie->flags;
			   ),

	    TP_printk("c=%08x u=%d Nc=%d Na=%d f=%02x",
		      __entry->cookie, __entry->usage,
		      __entry->n_children, __entry->n_active, __entry->flags)
	    );

TRACE_EVENT(fscache_osm,
	    TP_PROTO(struct fscache_object *object,
		     const struct fscache_state *state,
		     bool wait, bool oob, s8 event_num),

	    TP_ARGS(object, state, wait, oob, event_num),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(unsigned int,		object		)
		    __array(char,			state, 8	)
		    __field(bool,			wait		)
		    __field(bool,			oob		)
		    __field(s8,				event_num	)
			     ),

	    TP_fast_assign(
		    __entry->cookie		= object->cookie->debug_id;
		    __entry->object		= object->debug_id;
		    __entry->wait		= wait;
		    __entry->oob		= oob;
		    __entry->event_num		= event_num;
		    memcpy(__entry->state, state->short_name, 8);
			   ),

	    TP_printk("c=%08x o=%08d %s %s%sev=%d",
		      __entry->cookie,
		      __entry->object,
		      __entry->state,
		      __print_symbolic(__entry->wait,
				       { true,  "WAIT" },
				       { false, "WORK" }),
		      __print_symbolic(__entry->oob,
				       { true,  " OOB " },
				       { false, " " }),
		      __entry->event_num)
	    );

TRACE_EVENT(fscache_op,
	    TP_PROTO(struct fscache_cookie *cookie, struct fscache_operation *op,
		     enum fscache_op_trace why),

	    TP_ARGS(cookie, op, why),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(unsigned int,		op		)
		    __field(enum fscache_op_trace,	why		)
			     ),

	    TP_fast_assign(
		    __entry->cookie		= cookie->debug_id;
		    __entry->op			= op->debug_id;
		    __entry->why		= why;
			   ),

	    TP_printk("c=%08x op=%08x %s",
		      __entry->cookie, __entry->op,
		      __print_symbolic(__entry->why, fscache_op_traces))
	    );

#endif /* _TRACE_FSCACHE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
