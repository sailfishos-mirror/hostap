/*
 * Wi-Fi Aware - NAN module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NAN_H
#define NAN_H

#include "common/nan_defs.h"

struct nan_cluster_config;
enum nan_reason;
struct ieee80211_mgmt;

/*
 * struct nan_device_capabilities - NAN device capabilities
 * @cdw_info: Committed DW information
 * @supported_bands: Supported bands
 * @op_mode: Operation mode
 * @n_antennas: Number of antennas
 * @channel_switch_time: Maximal channel switch time
 * @capa: Device capabilities
 */
struct nan_device_capabilities {
	u16 cdw_info;
	u8 supported_bands;
	u8 op_mode;
	u8 n_antennas;
	u16 channel_switch_time;
	u8 capa;
};

/**
 * struct nan_qos - NAN QoS requirements
 * @min_slots: Minimal number of slots
 * @max_latency: Maximum allowed NAN slots between every two non-contiguous
 *     NAN Data Link (NDL) Common Resource Blocks (CRB)
 */
struct nan_qos {
	u8 min_slots;
	u16 max_latency;
};

/**
 * enum nan_ndp_action - NDP action
 * @NAN_NDP_ACTION_REQ: Request NDP establishment
 * @NAN_NDP_ACTION_RESP: Response to NDP establishment request
 * @NAN_NDP_ACTION_CONF: Confirm NDP establishment
 * @NAN_NDP_ACTION_TERM: Request NDP termination
 */
enum nan_ndp_action {
	NAN_NDP_ACTION_REQ,
	NAN_NDP_ACTION_RESP,
	NAN_NDP_ACTION_CONF,
	NAN_NDP_ACTION_TERM,
};

/**
 * struct nan_ndp_id - Unique identifier of an NDP
 *
 * @peer_nmi: Peer NAN Management Interface (NMI)
 * @init_ndi: Initiator NAN Data Interface (NDI)
 * @id: NDP identifier
 */
struct nan_ndp_id {
	u8 peer_nmi[ETH_ALEN];
	u8 init_ndi[ETH_ALEN];
	u8 id;
};

/*
 * The maximal period of a NAN schedule is 8192 TUs. With time slots of 16 TUs,
 * need 64 octets to represent a complete schedule bitmap.
 */
#define NAN_MAX_PERIOD_TUS        8192
#define NAN_MAX_TIME_BITMAP_SLOTS (NAN_MAX_PERIOD_TUS / 16)
#define NAN_TIME_BITMAP_MAX_LEN   (NAN_MAX_TIME_BITMAP_SLOTS / 8)

/**
 * struct nan_time_bitmap - NAN time bitmap
 *
 * @duration: Slot duration represented by each bit in the bitmap. Valid values
 *     are as defined in nan_defs.h and Wi-Fi Aware spec v4.0, Table 97 (Time
 *     Bitmap Control field format for the NAN Availability attribute).
 * @period: Indicates the repeat interval of the bitmap.
 *     When set to zero, the bitmap is not repeated. Valid values are
 *     as defined in nan_defs.h and Wi-Fi Aware spec v4.0, Table 97 (Time
 *     Bitmap Control field format for the NAN Availability attribute).
 * @offset: The time period specified by the %bitmap field starts at
 *     16 * offset TUs after DW0.
 * @len: Length of the %bitmap field, in bytes. If this is zero, the NAN device
 *     is available for 512 NAN slots beginning after the immediate previous
 *     DW0.
 * @bitmap: Each bit in the time bitmap corresponds to a time duration indicated
 *     by the value of the %duration field. When a bit is set to 1, the NAN
 *     device is available (or conditionally or potentially available)
 *     for any NAN operations for the time associated with the bit.
 */
struct nan_time_bitmap {
	u8 duration;
	u16 period;
	u16 offset;
	u8 len;
	u8 bitmap[NAN_TIME_BITMAP_MAX_LEN];
};

/**
 * struct nan_sched_chan - NAN scheduled channel
 *
 * @freq: Primary channel center frequency of the 20 MHz
 * @center_freq1: Center frequency of the first segment
 * @center_freq2: Center frequency of the second segment, if any
 * @bandwidth: The channel bandwidth in MHz
 */
struct nan_sched_chan {
	int freq;
	int center_freq1;
	int center_freq2;
	int bandwidth;
};

/**
 * struct nan_chan_schedule - NAN channel schedule
 *
 * @chan: The channel associated with the schedule
 * @committed: Committed schedule time bitmap
 * @conditonal: Conditional schedule time bitmap
 * @map_id: The map_id of the availability attribute where this schedule is
 *     represented
 */
struct nan_chan_schedule {
	struct nan_sched_chan chan;
	struct nan_time_bitmap committed;
	struct nan_time_bitmap conditional;
	u8 map_id;
};

/**
 * struct nan_sched_qos - QoS requirements in units of 16 TUs per 512 TUs
 *
 * @required_slots: Number of required slots
 * @min_slots: Minimum number of CRB slots needed for this NDL. If this amount
 *     of CRB slots can't be scheduled the NDL should fail.
 * @max_gap: Maximum allowed latency (in slots) of the CRB schedule
 */
struct nan_sched_qos {
	u8 required_slots;
	u8 min_slots;
	u8 max_gap;
};

#define NAN_SCHEDULE_MAX_CHANNELS 6

/**
 * struct nan_schedule - NAN schedule
 *
 * @map_ids_bitmap: Bitmap of map IDs included in this schedule. Not all map IDs
 *    are covered by &chans. For map IDs that are not covered, when building
 *    NAFs, NAN availability attributes would be added with potential
 *    availability entries.
 * @n_chans: Number of channels for this schedule.
 * @chans:  The channels included in the schedule. The channels must be sorted
 *     such that the map IDs (in struct nan_chan_schedule) are in ascending
 *     order.
 * @ndc: NDC bitmap schedule
 * @ndc_map_id: The NDC map ID
 * @sequence_id: Schedule sequence ID
 * @elems: Additional elements to be set in an element container attribute
 */
struct nan_schedule {
	u32 map_ids_bitmap;
	u8 n_chans;
	struct nan_chan_schedule chans[NAN_SCHEDULE_MAX_CHANNELS];
	struct nan_time_bitmap ndc;
	u8 ndc_map_id;
	u8 sequence_id;
	struct wpabuf *elems;
};

/**
 * struct nan_ndp_params - Holds the NDP parameters for setting up or
 * terminating an NDP.
 *
 * @type: The request type. See &enum nan_ndp_action
 * @ndp_id: The NDP identifier
 * @qos: The NDP QoS parameters. In case there is no requirement for
 *     max_latency, max_latency should be set to NAN_QOS_MAX_LATENCY_NO_PREF.
 *     Should be set only with NAN_NDP_ACTION_REQ and NAN_NDP_ACTION_RESP.
 *     Ignored for other types.
 * @ssi: Service specific information. Should be set only with
 *     NAN_NDP_ACTION_REQ and NAN_NDP_ACTION_RESP. Ignored for other types.
 * @ssi_len: Service specific information length
 * @publish_inst_id: Identifier for the instance of the Publisher function
 *     associated with the data path setup request.
 * @service_id: Service identifier of the service associated with the data path
 *     setup request.
 * @resp_ndi: In case of successful response, the responder's NDI. In case of
 *     response to a counter proposal, the initiator's NDI (the one used with
 *     NAN_NDP_ACTION_REQ).
 * @status: Response status
 * @reason_code: In case of rejected response, the rejection reason.
 * @sched_valid: Indicates whether the schedule field is valid
 * @sched: The NAN schedule associated with the NDP parameters
 */
struct nan_ndp_params {
	enum nan_ndp_action type;

	struct nan_ndp_id ndp_id;
	struct nan_qos qos;
	const u8 *ssi;
	u16 ssi_len;

	union {
		struct nan_ndp_setup_req {
			u8 publish_inst_id;
			u8 service_id[NAN_SERVICE_ID_LEN];
		} req;

		/*
		 * Used with both NAN_NDP_ACTION_RESP (as a response to an NDP
		 * request) and NAN_NDP_ACTION_CONF (as a response to an NDP
		 * response with a counter).
		 */
		struct nan_ndp_setup_resp {
			u8 resp_ndi[ETH_ALEN];
			u8 status;
			u8 reason_code;
		} resp;
	} u;

	bool sched_valid;
	struct nan_schedule sched;
};

/**
 * struct nan_channel_info - Channel information for NAN channel selection
 * @op_class: Operating class
 * @channel: Control channel index
 * @pref: Channel Preference (higher is preferred). Valid values are 0-3.
 */
struct nan_channel_info {
	u8 op_class;
	u8 channel;
	u8 pref;
};

/**
 * struct nan_channels - Array of channel information entries
 *
 * @n_chans: Number of channel information entries
 * @chans: Array of channel information. Sorted by preference.
 */
struct nan_channels {
	unsigned int n_chans;
	struct nan_channel_info *chans;
};

/**
 * struct nan_ndp_connection_params - Parameters for NDP connection
 * @ndp_id: NDP identifier
 * @peer_ndi: Peer NDI MAC address
 * @local_ndi: Local NDI MAC address
 * @ssi: Service specific information
 * @ssi_len: Service specific information length
 */
struct nan_ndp_connection_params {
	struct nan_ndp_id ndp_id;
	const u8 *peer_ndi;
	const u8 *local_ndi;
	const u8 *ssi;
	size_t ssi_len;
};

/**
 * struct nan_ndp_action_notif_params - Parameters for NDP action notification
 * @ndp_id: NDP identifier
 * @is_request: Whether the data is associated with an NDP request frame (true)
 *     or with an NDP response (false).
 * @ndp_status: NDP status
 * @ndl_status: NDL status
 * @publish_inst_id: Identifier for the publish instance function
 * @ssi: Service specific information
 * @ssi_len: Service specific information length
 */
struct nan_ndp_action_notif_params {
	struct nan_ndp_id ndp_id;
	bool is_request;

	enum nan_ndp_status ndp_status;
	enum nan_ndl_status ndl_status;

	u8 publish_inst_id;
	const u8 *ssi;
	size_t ssi_len;
};

struct nan_config {
	void *cb_ctx;

	struct nan_device_capabilities dev_capa;

	/**
	 * start - Start NAN
	 * @ctx: Callback context from cb_ctx
	 * @config: NAN cluster configuration
	 */
	int (*start)(void *ctx, const struct nan_cluster_config *config);

	/**
	 * stop - Stop NAN
	 * @ctx: Callback context from cb_ctx
	 */
	void (*stop)(void *ctx);

	/**
	 * update_config - Update NAN configuration
	 * @ctx: Callback context from cb_ctx
	 * @config: NAN cluster configuration
	 */
	int (*update_config)(void *ctx,
			     const struct nan_cluster_config *config);

	/**
	 * ndp_action_notif - Notify NDP action is required
	 * @ctx: Callback context from cb_ctx
	 * @params: NDP action notification parameters
	 *
	 * A notification sent when an NDP establishment frame is received, and
	 * upper layer input is required to continue the flow.
	 */
	void (*ndp_action_notif)(void *ctx,
				 struct nan_ndp_action_notif_params *params);

	/**
	 * ndp_connected - Notify that NDP was successfully connected
	 * @ctx: Callback context from cb_ctx
	 * @params: NDP connection parameters
	 */
	void (*ndp_connected)(void *ctx,
			      struct nan_ndp_connection_params *params);

	/**
	 * ndp_disconnected - Notify that NDP was disconnected
	 * @ctx: Callback context from cb_ctx
	 * @ndp_id: NDP identifier
	 * @local_ndi: Local NDI MAC address
	 * @peer_ndi: Peer NDI MAC address
	 * @reason: Disconnection reason
	 *
	 * This callback notifies that an NDP has been disconnected. It can be
	 * called both during NDP establishment (indicating failure) or after
	 * successful establishment (indicating termination).
	 */
	void (*ndp_disconnected)(void *ctx, struct nan_ndp_id *ndp_id,
				 const u8 *local_ndi, const u8 *peer_ndi,
				 enum nan_reason reason);

	/**
	 * get_chans - Get the prioritized allowed channel information to be
	 * used for building the potential availability entries associated with
	 * the given map ID.
	 *
	 * @ctx: Callback context from cb_ctx
	 * @map_id: Map ID of the availability attribute for which the channels
	 *     are requested.
	 * @chans: Pointer to a nan_channels structure that should be filled
	 *     with the prioritized frequencies. On successful return the
	 *     channels should be sorted having the higher priority channels
	 *     first.
	 * Returns: 0 on success, -1 on failure.
	 *
	 * Note: The callback is responsible for allocating chans->chans as
	 * needed. The caller (the NAN module) is responsible for freeing the
	 * memory allocated for the chans->chans.
	 *
	 * Note: The callback should add all channels that are considered valid
	 * for use by the NAN module for the given map.
	 */
	int (*get_chans)(void *ctx, u8 map_id, struct nan_channels *chans);

	/**
	 * send_naf - Transmit a NAN Action frame
	 * @ctx: Callback context from cb_ctx
	 * @dst: Destination MAC address
	 * @src: Source MAC address. Can be NULL.
	 * @cluster_id: The cluster ID
	 * @buf: Frame body (starting from the Category field)
	 * Returns: 0 on success, -1 on failure
	 */
	int (*send_naf)(void *ctx, const u8 *dst, const u8 *src,
			const u8 *cluster_id, struct wpabuf *buf);
};

struct nan_data * nan_init(const struct nan_config *cfg);
void nan_deinit(struct nan_data *nan);
int nan_start(struct nan_data *nan, const struct nan_cluster_config *config);
int nan_update_config(struct nan_data *nan,
		      const struct nan_cluster_config *config);
void nan_stop(struct nan_data *nan);
void nan_flush(struct nan_data *nan);

int nan_add_peer(struct nan_data *nan, const u8 *addr,
		 const u8 *device_attrs, size_t device_attrs_len);

bool nan_publish_instance_id_valid(struct nan_data *nan, u8 instance_id,
				   u8 *service_id);
void nan_set_cluster_id(struct nan_data *nan, const u8 *cluster_id);
int nan_action_rx(struct nan_data *nan, const struct ieee80211_mgmt *mgmt,
		  size_t len);
int nan_tx_status(struct nan_data *nan, const u8 *dst, const u8 *data,
		  size_t data_len, bool acked);

#endif /* NAN_H */
