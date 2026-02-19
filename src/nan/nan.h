/*
 * Wi-Fi Aware - NAN module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NAN_H
#define NAN_H

struct nan_cluster_config;

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

#endif /* NAN_H */
