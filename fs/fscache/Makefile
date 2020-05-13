# SPDX-License-Identifier: GPL-2.0
#
# Makefile for general filesystem caching code
#

ifeq ($(CONFIG_FSCACHE),y)
fscache-$(CONFIG_FSCACHE) := \
	cache.o \
	cookie.o \
	dispatcher.o \
	fsdef.o \
	io.o \
	main.o \
	netfs.o \
	obj.o \
	object_bits.o

fscache-$(CONFIG_PROC_FS) += proc.o
fscache-$(CONFIG_FSCACHE_STATS) += stats.o
fscache-$(CONFIG_FSCACHE_HISTOGRAM) += histogram.o
fscache-$(CONFIG_FSCACHE_OBJECT_LIST) += object-list.o
endif

fscache-$(CONFIG_FSCACHE_READ_HELPER) += read_helper.o

obj-$(CONFIG_FSCACHE_SERVICES) := fscache.o
