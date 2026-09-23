/*
 * wpa_supplicant - NAN IEEE Data Path (IDP)
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPAS_IDP_H
#define WPAS_IDP_H

#include "utils/list.h"
#include "common/nan_defs.h"
#include "common/wpa_common.h"

struct wpa_global;

/**
 * enum wpas_idp_role - IDP role in the connection
 */
enum wpas_idp_role {
	WPAS_IDP_ROLE_AP,
	WPAS_IDP_ROLE_STA,
};

/**
 * enum idp_state - IDP session state
 */
enum idp_state {
	IDP_STATE_NONE,
	IDP_STATE_NEGOTIATING,
	IDP_STATE_NEGOTIATED,
	IDP_STATE_CONFIGURING_AP,
	IDP_STATE_CONFIGURING_STA,
	IDP_STATE_ACTIVE_AP,
	IDP_STATE_ACTIVE_STA,
	IDP_STATE_TERMINATING,
	IDP_STATE_TERM_WAIT_RESP,
	IDP_STATE_TERM_WAIT_CONFIRM,
	IDP_STATE_PEER_CONNECTED,
};

/**
 * struct wpas_idp_session - IDP session state
 *
 * Stores the state for one IDP connection.
 */
struct wpas_idp_session {
	struct dl_list list;
	unsigned int id;
	struct wpa_supplicant *wpa_s;
	u8 peer_addr[ETH_ALEN];
	enum wpas_idp_role role;
	enum idp_state state;

	/* NAN discovery information */
	int handle; /* NAN service handle */

	u8 bssid[ETH_ALEN];

	/* Whether the AP advertises its SSID in beacons */
	bool discoverable;

	/* Network ID used by the STA */
	int network_id;

	/* AP address of the connected peer STA */
	u8 connected_sta_mac_addr[ETH_ALEN];
};

/**
 * struct wpas_idp_pending_request - Pending incoming PASN M1 request
 *
 * Stores the request until the user accepts or rejects it with IDP_RESPONSE.
 * No session or interface is created before acceptance.
 *
 * @list: Entry in the pending request list (wpas_idp_info::pending_requests)
 * @peer_addr: Initiator's NAN management address
 * @proposed_role: Local role if the request is accepted
 * @m1_frame: PASN M1 frame used to resume authentication
 * @freq: Frequency on which PASN M1 was received
 * @handle: Matching local NAN service handle
 */
struct wpas_idp_pending_request {
	struct dl_list list;
	u8 peer_addr[ETH_ALEN];
	enum wpas_idp_role proposed_role;
	struct wpabuf *m1_frame;
	int freq;
	int handle;
};

/**
 * struct wpas_idp_info - Global IDP context
 */
struct wpas_idp_info {
	struct wpa_global *global;
	struct dl_list sessions; /* Active IDP sessions,
				  * struct wpas_idp_session */
	unsigned int next_id; /* Next session ID */
	struct dl_list pending_requests; /* Requests awaiting a response */
};

int wpas_idp_init(struct wpa_global *global);
void wpas_idp_deinit(struct wpa_global *global);
struct wpas_idp_session *
wpas_idp_get_session_by_peer(struct wpa_supplicant *wpa_s, const u8 *peer_addr);
struct wpas_idp_session *
wpas_idp_alloc_session(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
		       enum wpas_idp_role role);
struct wpas_idp_pending_request *
wpas_idp_get_pending_request_by_peer(struct wpa_supplicant *wpa_s,
				     const u8 *peer_addr);

#endif /* WPAS_IDP_H */
