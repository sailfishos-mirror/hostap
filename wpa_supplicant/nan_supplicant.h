/*
 * wpa_supplicant - NAN
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NAN_SUPPLICANT_H
#define NAN_SUPPLICANT_H

#ifdef CONFIG_NAN

int wpas_nan_init(struct wpa_supplicant *wpa_s);
void wpas_nan_deinit(struct wpa_supplicant *wpa_s);
int wpas_nan_start(struct wpa_supplicant *wpa_s);
int wpas_nan_stop(struct wpa_supplicant *wpa_s);
void wpas_nan_flush(struct wpa_supplicant *wpa_s);
void wpas_nan_cluster_join(struct wpa_supplicant *wpa_s,
			   const u8 *cluster_id,
			   bool new_cluster);
void wpas_nan_next_dw(struct wpa_supplicant *wpa_s, u32 freq);

#else /* CONFIG_NAN */

static inline int wpas_nan_init(struct wpa_supplicant *wpa_s)
{
	return -1;
}

static inline void wpas_nan_deinit(struct wpa_supplicant *wpa_s)
{}

static inline int wpas_nan_start(struct wpa_supplicant *wpa_s)
{
	return -1;
}

static inline int wpas_nan_stop(struct wpa_supplicant *wpa_s)
{
	return -1;
}

static inline void wpas_nan_flush(struct wpa_supplicant *wpa_s)
{}

#endif /* CONFIG_NAN */

#ifdef CONFIG_NAN_USD

struct nan_subscribe_params;
struct nan_publish_params;
enum nan_service_protocol_type;

int wpas_nan_de_init(struct wpa_supplicant *wpa_s);
void wpas_nan_de_deinit(struct wpa_supplicant *wpa_s);
void wpas_nan_de_rx_sdf(struct wpa_supplicant *wpa_s, const u8 *src,
			const u8 *a3, unsigned int freq,
			const u8 *buf, size_t len);
void wpas_nan_de_flush(struct wpa_supplicant *wpa_s);
int wpas_nan_publish(struct wpa_supplicant *wpa_s, const char *service_name,
		     enum nan_service_protocol_type srv_proto_type,
		     const struct wpabuf *ssi,
		     struct nan_publish_params *params, bool p2p);
void wpas_nan_cancel_publish(struct wpa_supplicant *wpa_s, int publish_id);
int wpas_nan_update_publish(struct wpa_supplicant *wpa_s, int publish_id,
			    const struct wpabuf *ssi);
int wpas_nan_usd_unpause_publish(struct wpa_supplicant *wpa_s, int publish_id,
				 u8 peer_instance_id, const u8 *peer_addr);
int wpas_nan_usd_publish_stop_listen(struct wpa_supplicant *wpa_s,
				     int publish_id);
int wpas_nan_subscribe(struct wpa_supplicant *wpa_s,
		       const char *service_name,
		       enum nan_service_protocol_type srv_proto_type,
		       const struct wpabuf *ssi,
		       struct nan_subscribe_params *params, bool p2p);
void wpas_nan_cancel_subscribe(struct wpa_supplicant *wpa_s,
			       int subscribe_id);
int wpas_nan_usd_subscribe_stop_listen(struct wpa_supplicant *wpa_s,
				       int subscribe_id);
int wpas_nan_transmit(struct wpa_supplicant *wpa_s, int handle,
		      const struct wpabuf *ssi, const struct wpabuf *elems,
		      const u8 *peer_addr, u8 req_instance_id);
void wpas_nan_usd_remain_on_channel_cb(struct wpa_supplicant *wpa_s,
				       unsigned int freq,
				       unsigned int duration);
void wpas_nan_usd_cancel_remain_on_channel_cb(struct wpa_supplicant *wpa_s,
					      unsigned int freq);
void wpas_nan_usd_tx_wait_expire(struct wpa_supplicant *wpa_s);
int * wpas_nan_usd_all_freqs(struct wpa_supplicant *wpa_s);
void wpas_nan_usd_state_change_notif(struct wpa_supplicant *wpa_s);

#endif /* CONFIG_NAN_USD */

#endif /* NAN_SUPPLICANT_H */
