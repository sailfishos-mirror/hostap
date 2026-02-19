/*
 * Wi-Fi Aware - Internal definitions for NAN module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NAN_I_H
#define NAN_I_H

#include "list.h"
#include "common/ieee802_11_defs.h"
#include "common/nan_defs.h"
#include "nan.h"

struct nan_config;

/*
 * enum nan_ndp_state - State of NDP establishment
 * @NAN_NDP_STATE_NONE: No NDP establishment in progress
 * @NAN_NDP_STATE_START: Starting NDP establishment
 * @NAN_NDP_STATE_REQ_SENT: NDP request was sent
 * @NAN_NDP_STATE_REQ_RECV: NDP response was received and processed
 * @NAN_NDP_STATE_RES_SENT: NDP response was sent and NDP is not accepted yet
 * @NAN_NDP_STATE_RES_RECV: NDP response was received and NDP was not accepted
 *     yet (security is negotiated or confirmation is required)
 * @NAN_NDP_STATE_CON_SENT: NDP confirm was sent and NDP was not done yet, as
 *     security is negotiated
 * @NAN_NDP_STATE_CON_RECV: NDP confirm received and NDP was not done yet, as
 *     security is negotiated
 * @NAN_NDP_STATE_DONE: NDP establishment is done (either success or reject).
 *     In this state the NAN module handles actions such as notification to the
 *     encapsulating logic, etc. Once processing is done the NDP should either
 *     be cleared (rejected) or moved to the list of NDPs associated with the
 *     peer.
 */
enum nan_ndp_state {
	NAN_NDP_STATE_NONE,
	NAN_NDP_STATE_START,
	NAN_NDP_STATE_REQ_SENT,
	NAN_NDP_STATE_REQ_RECV,
	NAN_NDP_STATE_RES_SENT,
	NAN_NDP_STATE_RES_RECV,
	NAN_NDP_STATE_CON_SENT,
	NAN_NDP_STATE_CON_RECV,
	NAN_NDP_STATE_DONE,
};

/*
 * struct nan_ndp - NDP information
 *
 * Used to maintain the NDP as an object in a peer's list of NDPs.
 *
 * @list: Used for linking in the NDPs list
 * @peer: Pointer to the peer data structure
 * @initiator: True iff the local device is the initiator
 * @ndp_id: NDP ID
 * @init_ndi: Initiator NDI
 * @resp_ndi: Responder NDI. Might not always be set (as this depends on the
 *     state of NDP establishment and the status).
 * @qos: QoS requirements for this NDP
 */
struct nan_ndp {
	/* for nan_peer ndps list */
	struct dl_list list;
	struct nan_peer *peer;
	bool initiator;
	u8 ndp_id;
	u8 init_ndi[ETH_ALEN];
	u8 resp_ndi[ETH_ALEN];

	struct nan_qos qos;
};

/*
 * struct nan_ndp_setup - Holds the state of the NDP setup
 * @ndp: NDP information
 * @state: Current state
 * @status: Current status
 * @dialog_token: Setup dialog token
 * @publisher_inst_id: Publish function instance ID
 * @conf_req: True iff the NDP exchange requires confirm message
 * @reason: Reject reason. Only valid when status is rejected.
 * @ssi: Service specific information
 * @ssi_len: Service specific information length
 * @service_id: Service ID of the service used for NDP setup
 */
struct nan_ndp_setup {
	struct nan_ndp *ndp;
	enum nan_ndp_state state;
	enum nan_ndp_status status;
	u8 dialog_token;
	u8 publish_inst_id;
	bool conf_req;
	enum nan_reason reason;
	u8 *ssi;
	u16 ssi_len;

	u8 service_id[NAN_SERVICE_ID_LEN];
};

/**
 * struct nan_band_chan - NAN channel/band entry
 *
 * @band_id: Band ID as specified by enum nan_band_entry
 * @chan: Channel entry as specified by &struct nan_chan_entry
 */
struct nan_band_chan {
	union {
		u8 band_id;
		struct nan_chan_entry chan;
	} u;
};

/**
 * enum nan_band_chan_type - NAN band or channel
 *
 * @NAN_TYPE_BAND: The entry is a band entry
 * @NAN_TYPE_CHANNEL: The entry is a channel entry
 */
enum nan_band_chan_type {
	NAN_TYPE_BAND,
	NAN_TYPE_CHANNEL,
};

/**
 * struct nan_avail_entry - NAN availability entry
 *
 * @list: Used for linking in the availability entries list
 * @map_id: Map ID of the availability attribute that this entry belongs to
 * @type: Availability type. One of NAN_AVAIL_ENTRY_CTRL_TYPE_*.
 * @preference: Preference of being available in the NAN slots specified by
 *	the associated time bitmap. The preference is higher when the value is
 *	set larger. Valid values are 0 - 3.
 * @utilization: Indicating proportion within the NAN slots specified by the
 *	associated time bitmap that are already utilized for other purposes,
 *	quantized to 20%. Valid values are 0 - 5.
 * @rx_nss: Maximum number of special streams the NAN device can receive during
 *	the NAN slots specified by the associated time bitmap
 * @tbm: Time bitmap specifying the NAN slots in which the device will be
 *	available for NAN operations
 * @band_chan_type: Type of entries in &band_chan array, as specified by
 *	enum nan_band_chan_type
 * @n_band_chan: Number of entries in &band_chan array
 * @band_chan: Array of bands/channels on which the NAN device will be
 *	available
 */
struct nan_avail_entry {
	struct dl_list list;
	u8 map_id;
	u8 type;
	u8 preference;
	u8 utilization;
	u8 rx_nss;
	struct nan_time_bitmap tbm;
	enum nan_band_chan_type band_chan_type;
	u8 n_band_chan;
	struct nan_band_chan *band_chan;
};

/**
 * struct nan_dev_capa_entry - NAN Device Capability entry
 *
 * @list: Used for linking in the device capabilities list
 *	(in struct nan_peer_info::dev_capa)
 * @map_id: Map ID of the device capabilities
 * @capa: Device capabilities as specified by &struct nan_device_capabilities
 */
struct nan_dev_capa_entry {
	struct dl_list list;
	u8 map_id;
	struct nan_device_capabilities capa;
};

/**
 * struct nan_peer_info - NAN peer information
 *
 * @last_seen: Timestamp of the last update of the peer info
 * @seq_id: Sequence id of the last availability update
 * @avail_entries: List of availability entries of the peer
 * @dev_capa: List of device capabilities of the peer
 *	(struct nan_dev_capa_entry::list entries)
 */
struct nan_peer_info {
	struct os_reltime last_seen;
	u8 seq_id;
	struct dl_list avail_entries;
	struct dl_list dev_capa;
};

/**
 * struct nan_peer - Represents a known NAN peer
 * @list: List node for linking peers
 * @nmi_addr: NMI of the peer
 * @last_seen: Timestamp of the last time this peer was seen
 * @info: Information about the peer
 * @ndps: List of NDPs associated with this peer
 * @ndp_setup: Used to hold an NDP object while NDP establishment is in
 *     progress
 */
struct nan_peer {
	struct dl_list list;
	u8 nmi_addr[ETH_ALEN];
	struct os_reltime last_seen;
	struct nan_peer_info info;

	struct dl_list ndps;

	struct nan_ndp_setup ndp_setup;
};

/**
 * struct nan_data - Internal data structure for NAN
 * @cfg: Pointer to the NAN configuration structure
 * @nan_started: Flag indicating if NAN has been started
 * @peer_list: List of known peers
 * @ndp_id_counter: NDP identifier counter. Incremented for each NDP request,
 *     and is used to set ndp_id in &struct nan_ndp.
 * @next_dialog_token: Dialog token for NDP and NDL negotiations. Incremented
 *     for each NDP and NDL request.
 */
struct nan_data {
	struct nan_config *cfg;
	u8 nan_started:1;
	struct dl_list peer_list;

	u8 ndp_id_counter;
	u8 next_dialog_token;
};

struct nan_attrs_entry {
	struct dl_list list;
	const u8 *ptr;
	u16 len;
};

struct nan_attrs {
	struct dl_list serv_desc_ext;
	struct dl_list avail;
	struct dl_list ndc;
	struct dl_list dev_capa;
	struct dl_list element_container;

	const u8 *ndp;
	const u8 *ndl;
	const u8 *ndl_qos;
	const u8 *cipher_suite_info;
	const u8 *sec_ctxt_info;
	const u8 *shared_key_desc;

	u16 ndp_len;
	u16 ndl_len;
	u16 ndl_qos_len;
	u16 cipher_suite_info_len;
	u16 sec_ctxt_info_len;
	u16 shared_key_desc_len;
};

struct nan_msg {
	u8 oui_type;
	u8 oui_subtype;
	struct nan_attrs attrs;

	/* The full frame is required for the NDP security flows, that compute
	 * the NDP authentication token over the entire frame body. */
	const struct ieee80211_mgmt *mgmt;
	size_t len;
};


/**
 * nan_get_next_dialog_token - Allocate the next nonzero dialog token
 *
 * Wi-Fi Aware Specification v4.0, Tables 82, 86, 105: Dialog Token must be
 * set to a nonzero value.
 */
static inline u8 nan_get_next_dialog_token(struct nan_data *nan)
{
	if (++nan->next_dialog_token == 0)
		nan->next_dialog_token++;
	return nan->next_dialog_token;
}

struct nan_peer * nan_get_peer(struct nan_data *nan, const u8 *addr);
bool nan_is_naf(const struct ieee80211_mgmt *mgmt, size_t len);
int nan_parse_attrs(struct nan_data *nan, const u8 *data, size_t len,
		    struct nan_attrs *attrs);
int nan_parse_naf(struct nan_data *nan, const struct ieee80211_mgmt *mgmt,
		  size_t len, struct nan_msg *msg);
void nan_attrs_clear(struct nan_data *nan, struct nan_attrs *attrs);
void nan_add_dev_capa_attr(struct nan_data *nan, struct wpabuf *buf);

int nan_ndp_setup_req(struct nan_data *nan, struct nan_peer *peer,
		      struct nan_ndp_params *params);
int nan_ndp_setup_resp(struct nan_data *nan, struct nan_peer *peer,
		       struct nan_ndp_params *params);
int nan_ndp_handle_ndp_attr(struct nan_data *nan, struct nan_peer *peer,
			    struct nan_msg *msg);
int nan_ndp_add_ndp_attr(struct nan_data *nan, struct nan_peer *peer,
			 struct wpabuf *buf);
void nan_ndp_setup_reset(struct nan_data *nan, struct nan_peer *peer);
void nan_ndp_setup_failure(struct nan_data *nan, struct nan_peer *peer,
			   enum nan_reason reason, bool reset_state);
int nan_ndp_naf_sent(struct nan_data *nan, struct nan_peer *peer,
		     enum nan_subtype subtype);
int nan_parse_device_attrs(struct nan_data *nan, struct nan_peer *peer,
			   const u8 *attrs_data, size_t attrs_len);

#endif /* NAN_I_H */
