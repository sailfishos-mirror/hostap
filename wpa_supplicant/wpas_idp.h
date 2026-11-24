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
#include "drivers/driver.h"

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
 * enum wpas_idp_event - IDP state machine events
 */
enum wpas_idp_event {
	IDP_EVENT_INIT,
	IDP_EVENT_PASN_SUCCESS,
	IDP_EVENT_PASN_FAILED,
	IDP_EVENT_AP_UP,
	IDP_EVENT_STA_CONNECTED,
	IDP_EVENT_DISCONNECTED,
	IDP_EVENT_FAILURE,
	IDP_EVENT_TERM_INITIATED,
	IDP_EVENT_TERM_REQUEST_RX,
	IDP_EVENT_TERM_RESPONSE_RX,
	IDP_EVENT_TERM_CONFIRM_RX,
	IDP_EVENT_TERM_TIMEOUT,
	IDP_EVENT_PEER_CONNECTED,
};

/**
 * struct wpas_idp_channel_info - Negotiated channel parameters for IDP
 */
struct wpas_idp_channel_info {
	u8 country_string[3];
	u8 operating_class;
	u8 channel_number;
};

/**
 * enum wpas_idp_termination_reason - Reason for IDP termination
 * @IDP_TERM_REASON_USER_REQUEST: Local user requested termination
 * @IDP_TERM_REASON_TIMEOUT: Termination handshake timed out
 * @IDP_TERM_REASON_FAILURE: Data path or negotiation failure
 * @IDP_TERM_REASON_PEER_REQUEST: Peer requested termination
 *
 * The values are used in the reason parameter of the IDP_TERMINATE
 * command and in the IDP-TERMINATED event.
 */
enum wpas_idp_termination_reason {
	IDP_TERM_REASON_USER_REQUEST = 0,
	IDP_TERM_REASON_TIMEOUT = 1,
	IDP_TERM_REASON_FAILURE = 2,
	IDP_TERM_REASON_PEER_REQUEST = 3,
};

/* Timeout for an unanswered termination request, in seconds */
#define IDP_TERM_REQUEST_TIMEOUT_SEC 5

/**
 * struct wpas_idp_termination_info - Session termination state
 * @termination_in_progress: Termination handshake is active
 * @expected_response: Next termination message expected from the peer
 * @is_initiator: Local device initiated termination
 * @reason: Termination reason
 * @ndp_transition: Replace the data path with an NDP
 * @handshake_mode: Two-way or three-way termination
 * @request_time: Time the request was sent or received
 * @wait_idp_tx: Defer teardown until the termination response is sent
 */
struct wpas_idp_termination_info {
	bool termination_in_progress;
	enum nan_idp_term_type expected_response;
	bool is_initiator;
	enum wpas_idp_termination_reason reason;
	bool ndp_transition;
	u8 handshake_mode;
	struct os_reltime request_time;
	bool wait_idp_tx;
};

/**
 * struct wpas_idp_pending_termination - Pending peer termination request
 * @peer_addr: Peer NAN management address
 * @reason: Termination reason
 * @mode: Two-way or three-way termination
 * @ndp: Whether to transition to an NDP
 * @session_id: Session being terminated
 */
struct wpas_idp_pending_termination {
	u8 peer_addr[ETH_ALEN];
	u8 reason;
	u8 mode;
	u8 ndp;
	unsigned int session_id;
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
	u8 peer_instance_id; /* Peer service instance ID */

	u8 bssid[ETH_ALEN];
	u8 ssid[SSID_MAX_LEN];
	size_t ssid_len;

	/* IDP session identifier from the IDP ID attribute */
	u8 idp_session_id;

	/* Whether the AP advertises its SSID in beacons */
	bool discoverable;

	/* PMK derived from the PASN handshake */
	u8 pmk[PMK_LEN];
	size_t pmk_len;
	u8 pmkid[PMKID_LEN];
	bool pmkid_valid;

	/* ND-PMK derived for the infrastructure connection */
	u8 nd_pmk[PMK_LEN];
	bool nd_pmk_valid;

	/* Network ID used by the STA */
	int network_id;

	/* Negotiated channel parameters */
	struct wpas_idp_channel_info channel;

	/* AP address of the connected peer STA */
	u8 connected_sta_mac_addr[ETH_ALEN];

	/* IDP interface information */
	struct wpa_supplicant *group_wpa_s;
	char iface_name[IFNAMSIZ];
	u8 iface_addr[ETH_ALEN];
	char pending_iface_name[IFNAMSIZ];
	u8 pending_iface_addr[ETH_ALEN];
	int pending_iface_type;

	/* PASN context used for pairing verification */
	struct idp_pasn_context *pasn_ctx;

	/* Termination state */
	struct wpas_idp_termination_info termination;
	bool termination_completed;
	struct wpas_idp_pending_termination *pending_termination;
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

bool wpas_idp_peer_supports_idp(struct wpa_supplicant *wpa_s,
				const u8 *peer_addr);

struct wpas_idp_session *
wpas_idp_get_session_by_peer(struct wpa_supplicant *wpa_s, const u8 *peer_addr);
struct wpas_idp_pending_request *
wpas_idp_get_pending_request_by_peer(struct wpa_supplicant *wpa_s,
				     const u8 *peer_addr);

/* Attribute builders */
struct wpabuf * wpas_idp_build_nan_elem(const struct wpabuf *attrs);
struct wpabuf * wpas_idp_build_req_attrs(struct wpas_idp_session *session);
struct wpabuf * wpas_idp_build_resp_attrs(struct wpas_idp_session *session);

/* Attribute processors */
int wpas_idp_process_req_attrs(struct wpas_idp_session *session,
			       const u8 *attrs, size_t attrs_len);
int wpas_idp_process_resp_attrs(struct wpas_idp_session *session,
				const u8 *attrs, size_t attrs_len);

int wpas_idp_set_pmk(struct wpas_idp_session *session,
		     const u8 *pmk, size_t pmk_len);

int wpas_idp_state_machine(struct wpas_idp_session *session,
			   enum wpas_idp_event event);

/* Interface management */
bool wpas_idp_need_separate_iface(struct wpa_supplicant *wpa_s);
int wpas_idp_add_interface(struct wpa_supplicant *wpa_s,
			   struct wpas_idp_session *session,
			   enum wpa_driver_if_type type);
struct wpa_supplicant *
wpas_idp_init_interface(struct wpa_supplicant *wpa_s,
			struct wpas_idp_session *session);
void wpas_idp_remove_interface(struct wpa_supplicant *wpa_s,
			       struct wpas_idp_session *session);

void wpas_idp_add_sdf_info_attr(struct wpa_supplicant *wpa_s,
				struct wpabuf *buf);

int wpas_idp_rx_action(struct wpa_supplicant *wpa_s,
		       const struct ieee80211_mgmt *mgmt, size_t len);
int wpas_idp_terminate(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
		       enum wpas_idp_termination_reason reason,
		       u8 handshake_mode, bool ndp_transition);
int wpas_idp_term_response(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
			   bool accept);
int wpas_idp_request(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
		     enum wpas_idp_role role, int handle, u8 instance_id,
		     int freq, bool discoverable);
int wpas_idp_response(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
		      bool accept, int handle, int freq, int discoverable);
int wpas_idp_list(struct wpa_supplicant *wpa_s, char *buf, size_t buflen);
int wpas_idp_flush(struct wpa_supplicant *wpa_s);
int wpas_idp_get_nd_pmk(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
			char *buf, size_t buflen);

/* Event handling */
void wpas_idp_sta_authorized(struct wpa_supplicant *wpa_s,
			     const u8 *sta_mac);
#ifdef CONFIG_NAN_IDP
void wpas_idp_event(struct wpa_supplicant *wpa_s, enum wpa_event_type event);
#else /* CONFIG_NAN_IDP */
static inline void wpas_idp_event(struct wpa_supplicant *wpa_s,
				  enum wpa_event_type event)
{
}
#endif /* CONFIG_NAN_IDP */

#endif /* WPAS_IDP_H */
