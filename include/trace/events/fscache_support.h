/* SPDX-License-Identifier: GPL-2.0-or-later */
/* FS-Cache support module tracepoints
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM fscache_support

#if !defined(_TRACE_FSCACHE_SUPPORT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FSCACHE_SUPPORT_H

#include <linux/fscache.h>
#include <linux/tracepoint.h>

/*
 * Define enums for tracing information.
 */
#ifndef __FSCACHE_SUPPORT_DECLARE_TRACE_ENUMS_ONCE_ONLY
#define __FSCACHE_SUPPORT_DECLARE_TRACE_ENUMS_ONCE_ONLY

enum fscache_read_helper_trace {
	fscache_read_helper_download,
	fscache_read_helper_race,
	fscache_read_helper_read,
	fscache_read_helper_reissue_down,
	fscache_read_helper_reissue_read,
	fscache_read_helper_reissue_zero,
	fscache_read_helper_skip,
	fscache_read_helper_zero,
};

#endif

#define fscache_read_helper_traces				\
	EM(fscache_read_helper_download,	"DOWN")		\
	EM(fscache_read_helper_race,		"RACE")		\
	EM(fscache_read_helper_read,		"READ")		\
	EM(fscache_read_helper_reissue_down,	"rDWN")		\
	EM(fscache_read_helper_reissue_read,	"rREA")		\
	EM(fscache_read_helper_reissue_zero,	"rZER")		\
	EM(fscache_read_helper_skip,		"SKIP")		\
	E_(fscache_read_helper_zero,		"ZERO")


/*
 * Export enum symbols via userspace.
 */
#undef EM
#undef E_
#define EM(a, b) TRACE_DEFINE_ENUM(a);
#define E_(a, b) TRACE_DEFINE_ENUM(a);

fscache_read_helper_traces;

/*
 * Now redefine the EM() and E_() macros to map the enums to the strings that
 * will be printed in the output.
 */
#undef EM
#undef E_
#define EM(a, b)	{ a, b },
#define E_(a, b)	{ a, b }

TRACE_EVENT(fscache_read_helper,
	    TP_PROTO(struct fscache_cookie *cookie, pgoff_t start, pgoff_t end,
		     unsigned int notes, enum fscache_read_helper_trace what),

	    TP_ARGS(cookie, start, end, notes, what),

	    TP_STRUCT__entry(
		    __field(unsigned int,		cookie		)
		    __field(pgoff_t,			start		)
		    __field(pgoff_t,			end		)
		    __field(unsigned int,		notes		)
		    __field(enum fscache_read_helper_trace, what	)
			     ),

	    TP_fast_assign(
		    __entry->cookie	= cookie ? cookie->debug_id : 0;
		    __entry->start	= start;
		    __entry->end	= end;
		    __entry->what	= what;
		    __entry->notes	= notes;
			   ),

	    TP_printk("c=%08x %s n=%08x p=%lx-%lx",
		      __entry->cookie,
		      __print_symbolic(__entry->what, fscache_read_helper_traces),
		      __entry->notes,
		      __entry->start, __entry->end)
	    );

#endif /* _TRACE_FSCACHE_SUPPORT_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
