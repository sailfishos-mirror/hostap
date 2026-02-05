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

/* NAN synchronization only */
#ifdef CONFIG_NAN

int wpas_nan_init(struct wpa_supplicant *wpa_s);
void wpas_nan_deinit(struct wpa_supplicant *wpa_s);
int wpas_nan_start(struct wpa_supplicant *wpa_s);
int wpas_nan_set(struct wpa_supplicant *wpa_s, char *cmd);
int wpas_nan_update_conf(struct wpa_supplicant *wpa_s);
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

static inline int wpas_nan_set(struct wpa_supplicant *wpa_s, char *cmd)
{
	return -1;
}

static inline int wpas_nan_update_conf(struct wpa_supplicant *wpa_s)
{
	return -1;
}

static inline int wpas_nan_stop(struct wpa_supplicant *wpa_s)
{
	return -1;
}

static inline void wpas_nan_flush(struct wpa_supplicant *wpa_s)
{}

static inline void wpas_nan_cluster_join(struct wpa_supplicant *wpa_s,
					 const u8 *cluster_id,
					 bool new_cluster)
{}

static inline void wpas_nan_next_dw(struct wpa_supplicant *wpa_s, u32 freq)
{}

#endif /* CONFIG_NAN */

struct nan_subscribe_params;
struct nan_publish_params;
enum nan_service_protocol_type;

/* NAN sync and USD common */
#if defined(CONFIG_NAN_USD) || defined(CONFIG_NAN)

int wpas_nan_de_init(struct wpa_supplicant *wpa_s);
void wpas_nan_de_deinit(struct wpa_supplicant *wpa_s);
void wpas_nan_de_rx_sdf(struct wpa_supplicant *wpa_s, const u8 *src,
			const u8 *a3, unsigned int freq,
			const u8 *buf, size_t len, int rssi);
void wpas_nan_de_flush(struct wpa_supplicant *wpa_s);
int wpas_nan_publish(struct wpa_supplicant *wpa_s, const char *service_name,
		     enum nan_service_protocol_type srv_proto_type,
		     const struct wpabuf *ssi,
		     struct nan_publish_params *params, bool p2p);
void wpas_nan_cancel_publish(struct wpa_supplicant *wpa_s, int publish_id);
int wpas_nan_update_publish(struct wpa_supplicant *wpa_s, int publish_id,
			    const struct wpabuf *ssi);
int wpas_nan_subscribe(struct wpa_supplicant *wpa_s,
		       const char *service_name,
		       enum nan_service_protocol_type srv_proto_type,
		       const struct wpabuf *ssi,
		       struct nan_subscribe_params *params, bool p2p);
void wpas_nan_cancel_subscribe(struct wpa_supplicant *wpa_s,
			       int subscribe_id);
int wpas_nan_transmit(struct wpa_supplicant *wpa_s, int handle,
		      const struct wpabuf *ssi, const struct wpabuf *elems,
		      const u8 *peer_addr, u8 req_instance_id);

#else /* CONFIG_NAN_USD || CONFIG_NAN */

static inline int wpas_nan_de_init(struct wpa_supplicant *wpa_s)
{
	return 0;
}

static inline void wpas_nan_de_deinit(struct wpa_supplicant *wpa_s)
{}

static inline
void wpas_nan_de_rx_sdf(struct wpa_supplicant *wpa_s, const u8 *src,
			const u8 *a3, unsigned int freq,
			const u8 *buf, size_t len, int rssi)
{}

static inline void wpas_nan_de_flush(struct wpa_supplicant *wpa_s)
{}

#endif /* CONFIG_NAN_USD || CONFIG_NAN */

/* NAN USD only */
#ifdef CONFIG_NAN_USD

void wpas_nan_usd_remain_on_channel_cb(struct wpa_supplicant *wpa_s,
				       unsigned int freq,
				       unsigned int duration);
void wpas_nan_usd_cancel_remain_on_channel_cb(struct wpa_supplicant *wpa_s,
					      unsigned int freq);
void wpas_nan_usd_tx_wait_expire(struct wpa_supplicant *wpa_s);
int * wpas_nan_usd_all_freqs(struct wpa_supplicant *wpa_s);
int wpas_nan_usd_unpause_publish(struct wpa_supplicant *wpa_s, int publish_id,
				 u8 peer_instance_id, const u8 *peer_addr);
int wpas_nan_usd_publish_stop_listen(struct wpa_supplicant *wpa_s,
				     int publish_id);
int wpas_nan_usd_subscribe_stop_listen(struct wpa_supplicant *wpa_s,
				       int subscribe_id);
void wpas_nan_usd_state_change_notif(struct wpa_supplicant *wpa_s);

#else /* CONFIG_NAN_USD */

static inline
void wpas_nan_usd_remain_on_channel_cb(struct wpa_supplicant *wpa_s,
				       unsigned int freq,
				       unsigned int duration)
{}

static inline
void wpas_nan_usd_cancel_remain_on_channel_cb(struct wpa_supplicant *wpa_s,
					      unsigned int freq)
{}

static inline
int * wpas_nan_usd_all_freqs(struct wpa_supplicant *wpa_s)
{
	return NULL;
}

static inline
int wpas_nan_usd_unpause_publish(struct wpa_supplicant *wpa_s, int publish_id,
				 u8 peer_instance_id, const u8 *peer_addr)
{
	return -1;
}

static inline
int wpas_nan_usd_publish_stop_listen(struct wpa_supplicant *wpa_s,
				     int publish_id)
{
	return -1;
}

static inline
int wpas_nan_usd_subscribe_stop_listen(struct wpa_supplicant *wpa_s,
				       int subscribe_id)
{
	return -1;
}

static inline void wpas_nan_usd_state_change_notif(struct wpa_supplicant *wpa_s)
{}

#endif /* CONFIG_NAN_USD */

#endif /* NAN_SUPPLICANT_H */
