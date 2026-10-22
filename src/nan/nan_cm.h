/*
 * Wi-Fi Aware - Connection Management
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NAN_CM_H
#define NAN_CM_H

struct wpabuf;
struct nan_peer;

/* Maximum number of NDI pair entries accepted in a received KAA */
#define NAN_CM_KAA_MAX_ENTRIES 16

/**
 * struct nan_cm_kaa_entry - NDI pair entry in the KAA NDP list
 * @init_ndi: Initiator NDI
 * @resp_ndi: Responder NDI
 * @ndp_ids: NDP IDs established over the NDI pair
 * @n_ndp_ids: Number of entries in &ndp_ids
 */
struct nan_cm_kaa_entry {
	const u8 *init_ndi;
	const u8 *resp_ndi;
	const u8 *ndp_ids;
	u8 n_ndp_ids;
};

/**
 * struct nan_cm_kaa - Parsed Keep Alive attribute
 * @ndps_present: Whether the NDP list is present
 * @n_entries: Number of entries in &entries
 * @entries: NDP list entries. The pointers refer to the parsed attribute
 *	data and are valid only as long as that data is.
 */
struct nan_cm_kaa {
	bool ndps_present;
	u8 n_entries;
	struct nan_cm_kaa_entry entries[NAN_CM_KAA_MAX_ENTRIES];
};

/**
 * nan_cm_build_kaa - Build a Keep Alive attribute
 * @peer: Peer for which the attribute is built
 * @buf: Buffer to which the attribute is appended
 * Returns: 0 on success, -1 on failure
 *
 * The NDP list carries one entry for each NDI pair of the active NDPs with
 * the peer, listing the NDP IDs established over that NDI pair.
 */
int nan_cm_build_kaa(struct nan_peer *peer, struct wpabuf *buf);

/**
 * nan_cm_parse_kaa - Parse a Keep Alive attribute
 * @data: Attribute body (after the Attribute ID and Length fields)
 * @len: Length of the attribute body
 * @kaa: Buffer for returning the parsed attribute
 * Returns: 0 on success, -1 on failure
 */
int nan_cm_parse_kaa(const u8 *data, size_t len, struct nan_cm_kaa *kaa);

#endif /* NAN_CM_H */
