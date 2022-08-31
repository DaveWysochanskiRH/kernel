// SPDX-License-Identifier: GPL-2.0-only
/* Miscellaneous routines.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/swap.h>
#include "internal.h"

/**
 * netfs_invalidate_folio - Invalidate or partially invalidate a folio
 * @folio: Folio proposed for release
 * @offset: Offset of the invalidated region
 * @length: Length of the invalidated region
 *
 * Invalidate part or all of a folio for a network filesystem.  The folio will
 * be removed afterwards if the invalidated region covers the entire folio.
 */
void netfs_invalidate_folio(struct folio *folio, size_t offset, size_t length)
{
	_enter("{%lx},%lx,%lx", folio_index(folio), offset, length);

	folio_wait_fscache(folio);
}
EXPORT_SYMBOL(netfs_invalidate_folio);

/**
 * netfs_release_folio - Try to release a folio
 * @folio: Folio proposed for release
 * @gfp: Flags qualifying the release
 *
 * Request release of a folio and clean up its private state if it's not busy.
 * Returns true if the folio can now be released, false if not
 */
bool netfs_release_folio(struct folio *folio, gfp_t gfp)
{
	if (folio_test_private(folio))
		return false;
	if (folio_test_fscache(folio)) {
		if (current_is_kswapd() || !(gfp & __GFP_FS))
			return false;
		folio_wait_fscache(folio);
	}

	return true;
}
EXPORT_SYMBOL(netfs_release_folio);

/**
 * netfs_removing_folio - Notification of a folio about to be removed
 * @mapping: The pagecache about to be altered
 * @folio: The folio about to be removed
 */
void netfs_removing_folio(struct address_space *mapping, struct folio *folio)
{
	fscache_note_page_release(netfs_i_cookie(netfs_inode(mapping->host)));
}
EXPORT_SYMBOL(netfs_removing_folio);
