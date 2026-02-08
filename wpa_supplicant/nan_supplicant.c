/*
 * wpa_supplicant - NAN
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "utils/eloop.h"
#include "common/nan_de.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "nan/nan.h"
#include "config.h"
#include "offchannel.h"
#include "notify.h"
#include "p2p_supplicant.h"
#include "pr_supplicant.h"
#include "nan_supplicant.h"

#define DEFAULT_NAN_MASTER_PREF 2
#define DEFAULT_NAN_DUAL_BAND   0
#define DEFAULT_NAN_SCAN_PERIOD 60
#define DEFAULT_NAN_SCAN_DWELL_TIME 150
#define DEFAULT_NAN_DISCOVERY_BEACON_INTERVAL 100
#define DEFAULT_NAN_LOW_BAND_FREQUENCY 2437
#define DEFAULT_NAN_HIGH_BAND_FREQUENCY 5745
#define DEFAULT_NAN_RSSI_CLOSE -50
#define DEFAULT_NAN_RSSI_MIDDLE -65

#define NAN_MIN_RSSI_CLOSE  -60
#define NAN_MIN_RSSI_MIDDLE -75

#ifdef CONFIG_NAN

static int wpas_nan_start_cb(void *ctx, const struct nan_cluster_config *config)
{
	struct wpa_supplicant *wpa_s = ctx;

	return wpa_drv_nan_start(wpa_s, config);
}


static int wpas_nan_update_config_cb(void *ctx,
				     const struct nan_cluster_config *config)
{
	struct wpa_supplicant *wpa_s = ctx;

	return wpa_drv_nan_update_config(wpa_s, config);
}


static void wpas_nan_stop_cb(void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_drv_nan_stop(wpa_s);
}


int wpas_nan_init(struct wpa_supplicant *wpa_s)
{
	struct nan_config nan;

	if (!(wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_SUPPORT_NAN) ||
	    !(wpa_s->nan_drv_flags & WPA_DRIVER_FLAGS_NAN_SUPPORT_SYNC_CONFIG))
	{
		wpa_printf(MSG_INFO, "NAN: Driver does not support NAN");
		return -1;
	}

	os_memset(&nan, 0, sizeof(nan));
	nan.cb_ctx = wpa_s;

	nan.start = wpas_nan_start_cb;
	nan.stop = wpas_nan_stop_cb;
	nan.update_config = wpas_nan_update_config_cb;

	wpa_s->nan = nan_init(&nan);
	if (!wpa_s->nan) {
		wpa_printf(MSG_INFO, "NAN: Failed to init");
		return -1;
	}

	/* Set the default configuration */
	os_memset(&wpa_s->nan_config, 0, sizeof(wpa_s->nan_config));

	wpa_s->nan_config.master_pref = DEFAULT_NAN_MASTER_PREF;
	wpa_s->nan_config.dual_band = DEFAULT_NAN_DUAL_BAND;
	os_memset(wpa_s->nan_config.cluster_id, 0, ETH_ALEN);
	wpa_s->nan_config.scan_period = DEFAULT_NAN_SCAN_PERIOD;
	wpa_s->nan_config.scan_dwell_time = DEFAULT_NAN_SCAN_DWELL_TIME;
	wpa_s->nan_config.discovery_beacon_interval =
		DEFAULT_NAN_DISCOVERY_BEACON_INTERVAL;

	wpa_s->nan_config.low_band_cfg.frequency =
		DEFAULT_NAN_LOW_BAND_FREQUENCY;
	wpa_s->nan_config.low_band_cfg.rssi_close = DEFAULT_NAN_RSSI_CLOSE;
	wpa_s->nan_config.low_band_cfg.rssi_middle = DEFAULT_NAN_RSSI_MIDDLE;
	wpa_s->nan_config.low_band_cfg.awake_dw_interval = true;

	wpa_s->nan_config.high_band_cfg.frequency =
		DEFAULT_NAN_HIGH_BAND_FREQUENCY;
	wpa_s->nan_config.high_band_cfg.rssi_close = DEFAULT_NAN_RSSI_CLOSE;
	wpa_s->nan_config.high_band_cfg.rssi_middle = DEFAULT_NAN_RSSI_MIDDLE;
	wpa_s->nan_config.high_band_cfg.awake_dw_interval = true;

	/* TODO: Optimize this, so that the notification are enabled only when
	 * needed, i.e., when the DE is configured with unsolicited publish or
	 * active subscribe
	 */
	wpa_s->nan_config.enable_dw_notif =
		!!(wpa_s->nan_drv_flags &
		   WPA_DRIVER_FLAGS_NAN_SUPPORT_USERSPACE_DE);

	return 0;
}


void wpas_nan_deinit(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s || !wpa_s->nan)
		return;

	nan_deinit(wpa_s->nan);
	wpa_s->nan = NULL;
}


static int wpas_nan_ready(struct wpa_supplicant *wpa_s)
{
	return wpa_s->nan_mgmt && wpa_s->nan && wpa_s->nan_de &&
		wpa_s->wpa_state != WPA_INTERFACE_DISABLED;
}


/* Join a cluster using current configuration */
int wpas_nan_start(struct wpa_supplicant *wpa_s)
{
	if (!wpas_nan_ready(wpa_s))
		return -1;

	return nan_start(wpa_s->nan, &wpa_s->nan_config);
}


int wpas_nan_stop(struct wpa_supplicant *wpa_s)
{
	if (!wpas_nan_ready(wpa_s))
		return -1;

	nan_stop(wpa_s->nan);
	nan_de_set_cluster_id(wpa_s->nan_de, NULL);

	return 0;
}


void wpas_nan_flush(struct wpa_supplicant *wpa_s)
{
	if (!wpas_nan_ready(wpa_s))
		return;

	nan_flush(wpa_s->nan);
}


int wpas_nan_set(struct wpa_supplicant *wpa_s, char *cmd)
{
	struct nan_cluster_config *config = &wpa_s->nan_config;
	char *param = os_strchr(cmd, ' ');

	if (!param)
		return -1;

	*param++ = '\0';

#define NAN_PARSE_INT(_str, _min, _max)				     \
	if (os_strcmp(#_str, cmd) == 0) {			     \
		int val = atoi(param);                               \
								     \
		if (val < (_min) || val > (_max)) {                  \
			wpa_printf(MSG_INFO,                         \
				   "NAN: Invalid value for " #_str); \
			return -1;                                   \
		}                                                    \
		config->_str = val;                                  \
		return 0;                                            \
	}

#define NAN_PARSE_BAND(_str)						\
	if (os_strcmp(#_str, cmd) == 0) {				\
		int a, b, c, d;						\
									\
		if (sscanf(param, "%d,%d,%d,%d", &a, &b, &c, &d) !=	\
		    4) {						\
			wpa_printf(MSG_DEBUG,				\
				   "NAN: Invalid value for " #_str);	\
			return -1;					\
		}							\
									\
		if (a < NAN_MIN_RSSI_CLOSE ||				\
		    b < NAN_MIN_RSSI_MIDDLE ||				\
		    a <= b) {						\
			wpa_printf(MSG_DEBUG,				\
				   "NAN: Invalid value for " #_str);	\
			return -1;					\
		}							\
		config->_str.rssi_close = a;				\
		config->_str.rssi_middle = b;				\
		config->_str.awake_dw_interval = c;			\
		config->_str.disable_scan = !!d;			\
		return 0;						\
	}

	/* 0 and 255 are reserved */
	NAN_PARSE_INT(master_pref, 1, 254);
	NAN_PARSE_INT(dual_band, 0, 1);
	NAN_PARSE_INT(scan_period, 0, 0xffff);
	NAN_PARSE_INT(scan_dwell_time, 10, 150);
	NAN_PARSE_INT(discovery_beacon_interval, 50, 200);

	NAN_PARSE_BAND(low_band_cfg);
	NAN_PARSE_BAND(high_band_cfg);

	if (os_strcmp("cluster_id", cmd) == 0) {
		u8 cluster_id[ETH_ALEN];

		if (hwaddr_aton(param, cluster_id) < 0) {
			wpa_printf(MSG_INFO, "NAN: Invalid cluster ID");
			return -1;
		}

		if (cluster_id[0] != 0x50 || cluster_id[1] != 0x6f ||
		    cluster_id[2] != 0x9a || cluster_id[3] != 0x01) {
			wpa_printf(MSG_DEBUG, "NAN: Invalid cluster ID format");
			return -1;
		}

		os_memcpy(config->cluster_id, cluster_id, ETH_ALEN);
		return 0;
	}
#undef NAN_PARSE_INT
#undef NAN_PARSE_BAND

	wpa_printf(MSG_INFO, "NAN: Unknown NAN_SET cmd='%s'", cmd);
	return -1;
}


int wpas_nan_update_conf(struct wpa_supplicant *wpa_s)
{
	if (!wpas_nan_ready(wpa_s))
		return -1;

	wpa_printf(MSG_DEBUG, "NAN: Update NAN configuration");
	return nan_update_config(wpa_s->nan, &wpa_s->nan_config);
}


void wpas_nan_cluster_join(struct wpa_supplicant *wpa_s,
			   const u8 *cluster_id,
			   bool new_cluster)
{
	if (!wpas_nan_ready(wpa_s))
		return;

	wpa_msg_global(wpa_s, MSG_INFO, NAN_CLUSTER_JOIN "cluster_id=" MACSTR
		       " new=%d", MAC2STR(cluster_id), new_cluster);

	nan_de_set_cluster_id(wpa_s->nan_de, cluster_id);
}


void wpas_nan_next_dw(struct wpa_supplicant *wpa_s, u32 freq)
{
	if (!wpas_nan_ready(wpa_s))
		return;

	wpa_printf(MSG_DEBUG, "NAN: Next DW notification freq=%d", freq);
	nan_de_dw_trigger(wpa_s->nan_de, freq);
}

#endif /* CONFIG_NAN */


static const char *
tx_status_result_txt(enum offchannel_send_action_result result)
{
	switch (result) {
	case OFFCHANNEL_SEND_ACTION_SUCCESS:
		return "success";
	case OFFCHANNEL_SEND_ACTION_NO_ACK:
		return "no-ack";
	case OFFCHANNEL_SEND_ACTION_FAILED:
		return "failed";
	}

	return "?";
}


static void wpas_nan_de_tx_status(struct wpa_supplicant *wpa_s,
				  unsigned int freq, const u8 *dst,
				  const u8 *src, const u8 *bssid,
				  const u8 *data, size_t data_len,
				  enum offchannel_send_action_result result)
{
	if (!wpa_s->nan_de)
		return;

	wpa_printf(MSG_DEBUG, "NAN: TX status A1=" MACSTR " A2=" MACSTR
		   " A3=" MACSTR " freq=%d len=%zu result=%s",
		   MAC2STR(dst), MAC2STR(src), MAC2STR(bssid), freq,
		   data_len, tx_status_result_txt(result));

	nan_de_tx_status(wpa_s->nan_de, freq, dst);
}


struct wpas_nan_usd_tx_work {
	unsigned int freq;
	unsigned int wait_time;
	u8 dst[ETH_ALEN];
	u8 src[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	struct wpabuf *buf;
};


static void wpas_nan_usd_tx_work_free(struct wpas_nan_usd_tx_work *twork)
{
	if (!twork)
		return;
	wpabuf_free(twork->buf);
	os_free(twork);
}


static void wpas_nan_usd_tx_work_done(struct wpa_supplicant *wpa_s)
{
	struct wpas_nan_usd_tx_work *twork;

	if (!wpa_s->nan_usd_tx_work)
		return;

	twork = wpa_s->nan_usd_tx_work->ctx;
	wpas_nan_usd_tx_work_free(twork);
	radio_work_done(wpa_s->nan_usd_tx_work);
	wpa_s->nan_usd_tx_work = NULL;
}


static int wpas_nan_de_tx_send(struct wpa_supplicant *wpa_s, unsigned int freq,
			       unsigned int wait_time, const u8 *dst,
			       const u8 *src, const u8 *bssid,
			       const struct wpabuf *buf)
{
	wpa_printf(MSG_DEBUG, "NAN: TX NAN SDF A1=" MACSTR " A2=" MACSTR
		   " A3=" MACSTR " freq=%d len=%zu",
		   MAC2STR(dst), MAC2STR(src), MAC2STR(bssid), freq,
		   wpabuf_len(buf));

	return offchannel_send_action(wpa_s, freq, dst, src, bssid,
				      wpabuf_head(buf), wpabuf_len(buf),
				      wait_time, wpas_nan_de_tx_status, 1);
}


static void wpas_nan_usd_start_tx_cb(struct wpa_radio_work *work, int deinit)
{
	struct wpa_supplicant *wpa_s = work->wpa_s;
	struct wpas_nan_usd_tx_work *twork = work->ctx;

	if (deinit) {
		if (work->started) {
			wpa_s->nan_usd_tx_work = NULL;
			offchannel_send_action_done(wpa_s);
		}
		wpas_nan_usd_tx_work_free(twork);
		return;
	}

	wpa_s->nan_usd_tx_work = work;

	if (wpas_nan_de_tx_send(wpa_s, twork->freq, twork->wait_time,
				twork->dst, twork->src, twork->bssid,
				twork->buf) < 0)
		wpas_nan_usd_tx_work_done(wpa_s);
}


static int wpas_nan_de_tx(void *ctx, unsigned int freq, unsigned int wait_time,
			  const u8 *dst, const u8 *src, const u8 *bssid,
			  const struct wpabuf *buf)
{
	struct wpa_supplicant *wpa_s = ctx;
	struct wpas_nan_usd_tx_work *twork;

	if (!freq && !wait_time) {
		int ret;

		wpa_printf(MSG_DEBUG, "NAN: SYNC TX NAN SDF A1=" MACSTR " A2="
			   MACSTR " A3=" MACSTR " len=%zu",
			   MAC2STR(dst), MAC2STR(src), MAC2STR(bssid),
			   wpabuf_len(buf));
		ret = wpa_drv_send_action(wpa_s, 0, 0, dst, src, bssid,
					  wpabuf_head(buf), wpabuf_len(buf),
					  1);
		if (ret)
			wpa_printf(MSG_DEBUG,
				   "NAN: Failed to send sync action frame (%d)",
				   ret);
		return ret;
	}

	if (wpa_s->nan_usd_tx_work || wpa_s->nan_usd_listen_work) {
		/* Reuse ongoing radio work */
		return wpas_nan_de_tx_send(wpa_s, freq, wait_time, dst, src,
					   bssid, buf);
	}

	twork = os_zalloc(sizeof(*twork));
	if (!twork)
		return -1;
	twork->freq = freq;
	twork->wait_time = wait_time;
	os_memcpy(twork->dst, dst, ETH_ALEN);
	os_memcpy(twork->src, src, ETH_ALEN);
	os_memcpy(twork->bssid, bssid, ETH_ALEN);
	twork->buf = wpabuf_dup(buf);
	if (!twork->buf) {
		wpas_nan_usd_tx_work_free(twork);
		return -1;
	}

	if (radio_add_work(wpa_s, freq, "nan-usd-tx", 0,
			   wpas_nan_usd_start_tx_cb, twork) < 0) {
		wpas_nan_usd_tx_work_free(twork);
		return -1;
	}

	return 0;
}


struct wpas_nan_usd_listen_work {
	unsigned int freq;
	unsigned int duration;
};


static void wpas_nan_usd_listen_work_done(struct wpa_supplicant *wpa_s)
{
	struct wpas_nan_usd_listen_work *lwork;

	if (!wpa_s->nan_usd_listen_work)
		return;

	lwork = wpa_s->nan_usd_listen_work->ctx;
	os_free(lwork);
	radio_work_done(wpa_s->nan_usd_listen_work);
	wpa_s->nan_usd_listen_work = NULL;
}


static void wpas_nan_usd_remain_on_channel_timeout(void *eloop_ctx,
						   void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct wpas_nan_usd_listen_work *lwork = timeout_ctx;

	wpas_nan_usd_cancel_remain_on_channel_cb(wpa_s, lwork->freq);
}


static void wpas_nan_usd_start_listen_cb(struct wpa_radio_work *work,
					 int deinit)
{
	struct wpa_supplicant *wpa_s = work->wpa_s;
	struct wpas_nan_usd_listen_work *lwork = work->ctx;
	unsigned int duration;

	if (deinit) {
		if (work->started) {
			wpa_s->nan_usd_listen_work = NULL;
			wpa_drv_cancel_remain_on_channel(wpa_s);
		}
		os_free(lwork);
		return;
	}

	wpa_s->nan_usd_listen_work = work;

	duration = lwork->duration;
	if (duration > wpa_s->max_remain_on_chan)
		duration = wpa_s->max_remain_on_chan;
	wpa_printf(MSG_DEBUG, "NAN: Start listen on %u MHz for %u ms",
		   lwork->freq, duration);
	if (wpa_drv_remain_on_channel(wpa_s, lwork->freq, duration) < 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Failed to request the driver to remain on channel (%u MHz) for listen",
			   lwork->freq);
		eloop_cancel_timeout(wpas_nan_usd_remain_on_channel_timeout,
				     wpa_s, ELOOP_ALL_CTX);
		/* Restart the listen state after a delay */
		eloop_register_timeout(0, 500,
				       wpas_nan_usd_remain_on_channel_timeout,
				       wpa_s, lwork);
		wpas_nan_usd_listen_work_done(wpa_s);
		return;
	}
}


static int wpas_nan_de_listen(void *ctx, unsigned int freq,
			      unsigned int duration)
{
	struct wpa_supplicant *wpa_s = ctx;
	struct wpas_nan_usd_listen_work *lwork;

	lwork = os_zalloc(sizeof(*lwork));
	if (!lwork)
		return -1;
	lwork->freq = freq;
	lwork->duration = duration;

	if (radio_add_work(wpa_s, freq, "nan-usd-listen", 0,
			   wpas_nan_usd_start_listen_cb, lwork) < 0) {
		os_free(lwork);
		return -1;
	}

	return 0;
}


static void
wpas_nan_de_discovery_result(void *ctx, int subscribe_id,
			     enum nan_service_protocol_type srv_proto_type,
			     const u8 *ssi, size_t ssi_len, int peer_publish_id,
			     const u8 *peer_addr, bool fsd, bool fsd_gas)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpas_notify_nan_discovery_result(wpa_s, srv_proto_type, subscribe_id,
					 peer_publish_id, peer_addr, fsd,
					 fsd_gas, ssi, ssi_len);
}


static void wpas_nan_de_replied(void *ctx, int publish_id, const u8 *peer_addr,
				int peer_subscribe_id,
				enum nan_service_protocol_type srv_proto_type,
				const u8 *ssi, size_t ssi_len)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpas_notify_nan_replied(wpa_s, srv_proto_type, publish_id,
				peer_subscribe_id, peer_addr, ssi, ssi_len);
}


static void wpas_nan_de_publish_terminated(void *ctx, int publish_id,
					   enum nan_de_reason reason)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpas_notify_nan_publish_terminated(wpa_s, publish_id, reason);
}


static void wpas_nan_usd_offload_cancel_publish(void *ctx, int publish_id)
{
	struct wpa_supplicant *wpa_s = ctx;

	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_USD_OFFLOAD)
		wpas_drv_nan_cancel_publish(wpa_s, publish_id);
}


static void wpas_nan_de_subscribe_terminated(void *ctx, int subscribe_id,
					     enum nan_de_reason reason)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpas_notify_nan_subscribe_terminated(wpa_s, subscribe_id, reason);
}


static void wpas_nan_usd_offload_cancel_subscribe(void *ctx, int subscribe_id)
{
	struct wpa_supplicant *wpa_s = ctx;

	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_USD_OFFLOAD)
		wpas_drv_nan_cancel_subscribe(wpa_s, subscribe_id);
}


static void wpas_nan_de_receive(void *ctx, int id, int peer_instance_id,
				const u8 *ssi, size_t ssi_len,
				const u8 *peer_addr)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpas_notify_nan_receive(wpa_s, id, peer_instance_id, peer_addr,
				ssi, ssi_len);
}


#ifdef CONFIG_P2P
static void wpas_nan_process_p2p_usd_elems(void *ctx, const u8 *buf,
					   u16 buf_len, const u8 *peer_addr,
					   unsigned int freq)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpas_p2p_process_usd_elems(wpa_s, buf, buf_len, peer_addr, freq);
}
#endif /* CONFIG_P2P */


#ifdef CONFIG_PR
static void wpas_nan_process_pr_usd_elems(void *ctx, const u8 *buf, u16 buf_len,
					  const u8 *peer_addr,
					  unsigned int freq)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpas_pr_process_usd_elems(wpa_s, buf, buf_len, peer_addr, freq);
}
#endif /* CONFIG_PR */


int wpas_nan_de_init(struct wpa_supplicant *wpa_s)
{
	struct nan_callbacks cb;
	bool offload = !!(wpa_s->drv_flags2 &
			  WPA_DRIVER_FLAGS2_NAN_USD_OFFLOAD);

	os_memset(&cb, 0, sizeof(cb));
	cb.ctx = wpa_s;
	cb.tx = wpas_nan_de_tx;
	cb.listen = wpas_nan_de_listen;
	cb.discovery_result = wpas_nan_de_discovery_result;
	cb.replied = wpas_nan_de_replied;
	cb.publish_terminated = wpas_nan_de_publish_terminated;
	cb.subscribe_terminated = wpas_nan_de_subscribe_terminated;
	cb.offload_cancel_publish = wpas_nan_usd_offload_cancel_publish;
	cb.offload_cancel_subscribe = wpas_nan_usd_offload_cancel_subscribe;
	cb.receive = wpas_nan_de_receive;
#ifdef CONFIG_P2P
	cb.process_p2p_usd_elems = wpas_nan_process_p2p_usd_elems;
#endif /* CONFIG_P2P */
#ifdef CONFIG_PR
	cb.process_pr_usd_elems = wpas_nan_process_pr_usd_elems;
#endif /* CONFIG_PR */

	wpa_s->nan_de = nan_de_init(wpa_s->own_addr, offload, false,
				    wpa_s->max_remain_on_chan, &cb);
	if (!wpa_s->nan_de)
		return -1;
	return 0;
}


void wpas_nan_de_deinit(struct wpa_supplicant *wpa_s)
{
	eloop_cancel_timeout(wpas_nan_usd_remain_on_channel_timeout,
			     wpa_s, ELOOP_ALL_CTX);
	nan_de_deinit(wpa_s->nan_de);
	wpa_s->nan_de = NULL;
}


void wpas_nan_de_rx_sdf(struct wpa_supplicant *wpa_s, const u8 *src,
			const u8 *a3, unsigned int freq,
			const u8 *buf, size_t len, int rssi)
{
	if (!wpa_s->nan_de)
		return;
	nan_de_rx_sdf(wpa_s->nan_de, src, a3, freq, buf, len, rssi);
}


void wpas_nan_de_flush(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s->nan_de)
		return;
	nan_de_flush(wpa_s->nan_de);
	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_USD_OFFLOAD)
		wpas_drv_nan_flush(wpa_s);
}


int wpas_nan_publish(struct wpa_supplicant *wpa_s, const char *service_name,
		     enum nan_service_protocol_type srv_proto_type,
		     const struct wpabuf *ssi,
		     struct nan_publish_params *params, bool p2p)
{
	int publish_id;
	struct wpabuf *elems = NULL;
	const u8 *addr;

	if (!wpa_s->nan_de)
		return -1;

	if (params->proximity_ranging && !params->solicited) {
		wpa_printf(MSG_INFO,
			   "PR unsolicited publish service discovery not allowed");
		return -1;
	}

	addr = wpa_s->own_addr;

#ifdef CONFIG_NAN
	if (params->sync) {
		if (!(wpa_s->nan_drv_flags &
		      WPA_DRIVER_FLAGS_NAN_SUPPORT_USERSPACE_DE)) {
			wpa_printf(MSG_INFO,
				   "NAN: Cannot advertise sync service, driver does not support user space DE");
			return -1;
		}

		if (!wpas_nan_ready(wpa_s)) {
			wpa_printf(MSG_INFO,
				   "NAN: Synchronized support is not enabled");
			return -1;
		}

		if (p2p) {
			wpa_printf(MSG_INFO,
				   "NAN: Sync discovery is not supported for P2P");
			return -1;
		}

		if (params->proximity_ranging) {
			wpa_printf(MSG_INFO,
				   "NAN: Sync discovery is not supported for PR");
			return -1;
		}
	}
#endif /* CONFIG_NAN */

	if (p2p) {
		elems = wpas_p2p_usd_elems(wpa_s, service_name);
		addr = wpa_s->global->p2p_dev_addr;
	} else if (params->proximity_ranging) {
		elems = wpas_pr_usd_elems(wpa_s);
	}

	publish_id = nan_de_publish(wpa_s->nan_de, service_name, srv_proto_type,
				    ssi, elems, params, p2p);
	if (publish_id >= 1 && !params->sync &&
	    (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_USD_OFFLOAD) &&
	    wpas_drv_nan_publish(wpa_s, addr, publish_id, service_name,
				 nan_de_get_service_id(wpa_s->nan_de,
						       publish_id),
				 srv_proto_type, ssi, elems, params) < 0) {
		nan_de_cancel_publish(wpa_s->nan_de, publish_id);
		publish_id = -1;
	}

	wpabuf_free(elems);
	return publish_id;
}


void wpas_nan_cancel_publish(struct wpa_supplicant *wpa_s, int publish_id)
{
	if (!wpa_s->nan_de)
		return;
	nan_de_cancel_publish(wpa_s->nan_de, publish_id);
	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_USD_OFFLOAD)
		wpas_drv_nan_cancel_publish(wpa_s, publish_id);
}


int wpas_nan_update_publish(struct wpa_supplicant *wpa_s, int publish_id,
			    const struct wpabuf *ssi)
{
	int ret;

	if (!wpa_s->nan_de)
		return -1;
	ret = nan_de_update_publish(wpa_s->nan_de, publish_id, ssi);
	if (ret == 0 && (wpa_s->drv_flags2 &
			 WPA_DRIVER_FLAGS2_NAN_USD_OFFLOAD) &&
	    wpas_drv_nan_update_publish(wpa_s, publish_id, ssi) < 0)
		return -1;
	return ret;
}


int wpas_nan_usd_unpause_publish(struct wpa_supplicant *wpa_s, int publish_id,
				 u8 peer_instance_id, const u8 *peer_addr)
{
	if (!wpa_s->nan_de)
		return -1;
	return nan_de_unpause_publish(wpa_s->nan_de, publish_id,
				      peer_instance_id, peer_addr);
}


static int wpas_nan_stop_listen(struct wpa_supplicant *wpa_s, int id)
{
	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_USD_OFFLOAD)
		return 0;

	if (nan_de_stop_listen(wpa_s->nan_de, id) < 0)
		return -1;

	if (wpa_s->nan_usd_listen_work) {
		wpa_printf(MSG_DEBUG, "NAN: Stop listen operation");
		wpa_drv_cancel_remain_on_channel(wpa_s);
		wpas_nan_usd_listen_work_done(wpa_s);
	}

	if (wpa_s->nan_usd_tx_work) {
		wpa_printf(MSG_DEBUG, "NAN: Stop TX wait operation");
		offchannel_send_action_done(wpa_s);
		wpas_nan_usd_tx_work_done(wpa_s);
	}

	return 0;
}


int wpas_nan_usd_publish_stop_listen(struct wpa_supplicant *wpa_s,
				     int publish_id)
{
	if (!wpa_s->nan_de)
		return -1;

	wpa_printf(MSG_DEBUG, "NAN: Request to stop listen for publish_id=%d",
		   publish_id);
	return wpas_nan_stop_listen(wpa_s, publish_id);
}


int wpas_nan_subscribe(struct wpa_supplicant *wpa_s,
		       const char *service_name,
		       enum nan_service_protocol_type srv_proto_type,
		       const struct wpabuf *ssi,
		       struct nan_subscribe_params *params, bool p2p)
{
	int subscribe_id;
	struct wpabuf *elems = NULL;
	const u8 *addr;

	if (!wpa_s->nan_de)
		return -1;

	if (params->proximity_ranging && !params->active) {
		wpa_printf(MSG_INFO,
			   "PR passive subscriber service discovery not allowed");
		return -1;
	}

	addr = wpa_s->own_addr;

#ifdef CONFIG_NAN
	if (params->sync) {
		if (!(wpa_s->nan_drv_flags &
		      WPA_DRIVER_FLAGS_NAN_SUPPORT_USERSPACE_DE)) {
			wpa_printf(MSG_INFO,
				   "NAN: Cannot subscribe sync, user space DE is not supported");
			return -1;
		}

		if (!wpas_nan_ready(wpa_s)) {
			wpa_printf(MSG_INFO, "NAN: Not ready (subscribe)");
			return -1;
		}

		if (p2p) {
			wpa_printf(MSG_INFO,
				   "NAN: Sync discovery is not supported for P2P (subscribe)");
			return -1;
		}

		if (params->proximity_ranging) {
			wpa_printf(MSG_INFO,
				   "NAN: Sync discovery is not supported for PR (subscribe)");
			return -1;
		}
	}
#endif /* CONFIG_NAN */

	if (p2p) {
		elems = wpas_p2p_usd_elems(wpa_s, service_name);
		addr = wpa_s->global->p2p_dev_addr;
	} else if (params->proximity_ranging) {
		elems = wpas_pr_usd_elems(wpa_s);
	}

	subscribe_id = nan_de_subscribe(wpa_s->nan_de, service_name,
					srv_proto_type, ssi, elems, params,
					p2p);
	if (subscribe_id >= 1 && !params->sync &&
	    (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_USD_OFFLOAD) &&
	    wpas_drv_nan_subscribe(wpa_s, addr, subscribe_id, service_name,
				   nan_de_get_service_id(wpa_s->nan_de,
							 subscribe_id),
				   srv_proto_type, ssi, elems, params) < 0) {
		nan_de_cancel_subscribe(wpa_s->nan_de, subscribe_id);
		subscribe_id = -1;
	}

	wpabuf_free(elems);
	return subscribe_id;
}


void wpas_nan_cancel_subscribe(struct wpa_supplicant *wpa_s,
			       int subscribe_id)
{
	if (!wpa_s->nan_de)
		return;
	nan_de_cancel_subscribe(wpa_s->nan_de, subscribe_id);
	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_USD_OFFLOAD)
		wpas_drv_nan_cancel_subscribe(wpa_s, subscribe_id);
}


int wpas_nan_usd_subscribe_stop_listen(struct wpa_supplicant *wpa_s,
				       int subscribe_id)
{
	if (!wpa_s->nan_de)
		return -1;

	wpa_printf(MSG_DEBUG, "NAN: Request to stop listen for subscribe_id=%d",
		   subscribe_id);
	return wpas_nan_stop_listen(wpa_s, subscribe_id);
}


int wpas_nan_transmit(struct wpa_supplicant *wpa_s, int handle,
		      const struct wpabuf *ssi, const struct wpabuf *elems,
		      const u8 *peer_addr, u8 req_instance_id)
{
	if (!wpa_s->nan_de)
		return -1;
	return nan_de_transmit(wpa_s->nan_de, handle, ssi, elems, peer_addr,
			       req_instance_id);
}


void wpas_nan_usd_remain_on_channel_cb(struct wpa_supplicant *wpa_s,
				       unsigned int freq, unsigned int duration)
{
	wpas_nan_usd_listen_work_done(wpa_s);

	if (wpa_s->nan_de)
		nan_de_listen_started(wpa_s->nan_de, freq, duration);
}


void wpas_nan_usd_cancel_remain_on_channel_cb(struct wpa_supplicant *wpa_s,
					      unsigned int freq)
{
	if (wpa_s->nan_de)
		nan_de_listen_ended(wpa_s->nan_de, freq);
}


void wpas_nan_usd_tx_wait_expire(struct wpa_supplicant *wpa_s)
{
	wpas_nan_usd_tx_work_done(wpa_s);

	if (wpa_s->nan_de)
		nan_de_tx_wait_ended(wpa_s->nan_de);
}


int * wpas_nan_usd_all_freqs(struct wpa_supplicant *wpa_s)
{
	int i, j;
	int *freqs = NULL;

	if (!wpa_s->hw.modes)
		return NULL;

	for (i = 0; i < wpa_s->hw.num_modes; i++) {
		struct hostapd_hw_modes *mode = &wpa_s->hw.modes[i];

		for (j = 0; j < mode->num_channels; j++) {
			struct hostapd_channel_data *chan = &mode->channels[j];

			/* All 20 MHz channels on 2.4 and 5 GHz band */
			if (chan->freq < 2412 || chan->freq > 5900)
				continue;

			/* that allow frames to be transmitted */
			if (chan->flag & (HOSTAPD_CHAN_DISABLED |
					  HOSTAPD_CHAN_NO_IR |
					  HOSTAPD_CHAN_RADAR))
				continue;

			int_array_add_unique(&freqs, chan->freq);
		}
	}

	return freqs;
}


void wpas_nan_usd_state_change_notif(struct wpa_supplicant *wpa_s)
{
	struct wpa_supplicant *ifs;
	unsigned int n_active = 0;
	struct nan_de_cfg cfg;

	if (!wpa_s->radio)
		return;

	os_memset(&cfg, 0, sizeof(cfg));

	dl_list_for_each(ifs, &wpa_s->radio->ifaces, struct wpa_supplicant,
			 radio_list) {
		if (ifs->wpa_state >= WPA_AUTHENTICATING)
			n_active++;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN: state change notif: n_active=%u, p2p_in_progress=%u",
		   n_active, wpas_p2p_in_progress(wpa_s));

	if (n_active) {
		cfg.n_max = 3;

		if (!wpas_p2p_in_progress(wpa_s)) {
			/* Limit the USD operation on channel to 100 - 300 TUs
			 * to allow more time for other interfaces.
			 */
			cfg.n_min = 1;
		} else {
			/* Limit the USD operation on channel to 200 - 300 TUs
			 * to allow P2P operation to complete.
			 */
			cfg.n_min = 2;
		}

		/* Each 500 ms suspend USD operation for 300 ms */
		cfg.cycle = 500;
		cfg.suspend = 300;
	}

	dl_list_for_each(ifs, &wpa_s->radio->ifaces, struct wpa_supplicant,
			 radio_list) {
		if (ifs->nan_de)
			nan_de_config(ifs->nan_de, &cfg);
	}
}
