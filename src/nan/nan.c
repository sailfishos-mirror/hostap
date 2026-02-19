/*
 * Wi-Fi Aware - NAN module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "nan.h"
#include "nan_i.h"

#define NAN_MAX_PEERS 32


struct nan_data * nan_init(const struct nan_config *cfg)
{
	struct nan_data *nan;

	if (!cfg->start || !cfg->stop)
		return NULL;

	nan = os_zalloc(sizeof(*nan));
	if (!nan)
		return NULL;

	nan->cfg = os_memdup(cfg, sizeof(*cfg));
	if (!nan->cfg) {
		os_free(nan);
		return NULL;
	}

	dl_list_init(&nan->peer_list);

	wpa_printf(MSG_DEBUG, "NAN: Initialized");

	return nan;
}


static void nan_del_peer(struct nan_data *nan, struct nan_peer *peer)
{
	if (!peer)
		return;

	wpa_printf(MSG_DEBUG, "NAN: Removing peer: " MACSTR,
		   MAC2STR(peer->nmi_addr));

	if (!dl_list_empty(&peer->ndps)) {
		struct nan_ndp *ndp, *tndp;

		/* TODO: tear down active NDPs */
		wpa_printf(MSG_DEBUG,
			   "NAN: Peer delete while there are active NDPs");

		dl_list_for_each_safe(ndp, tndp, &peer->ndps,
				      struct nan_ndp, list) {
			dl_list_del(&ndp->list);
			os_free(ndp);
		}
	}

	if (peer->ndp_setup.ndp) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Peer delete while NDP setup is WIP");
		nan_ndp_setup_reset(nan, peer);
	}

	dl_list_del(&peer->list);
	os_free(peer);
}


static void nan_peer_clear_all(struct nan_data *nan)
{
	struct nan_peer *peer, *n_peer;

	dl_list_for_each_safe(peer, n_peer, &nan->peer_list,
			      struct nan_peer, list)
		nan_del_peer(nan, peer);
}


void nan_deinit(struct nan_data *nan)
{
	wpa_printf(MSG_DEBUG, "NAN: Deinit");
	nan_peer_clear_all(nan);
	os_free(nan->cfg);
	os_free(nan);
}


int nan_start(struct nan_data *nan, const struct nan_cluster_config *config)
{
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: Starting/joining NAN cluster");

	if (nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Already started");
		return -1;
	}

	ret = nan->cfg->start(nan->cfg->cb_ctx, config);
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: Failed to start - ret=%d", ret);
		return ret;
	}
	nan->nan_started = 1;

	return 0;
}


int nan_update_config(struct nan_data *nan,
		      const struct nan_cluster_config *config)
{
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: Update configuration");

	if (!nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Not started yet");
		return -1;
	}

	ret = nan->cfg->update_config(nan->cfg->cb_ctx, config);
	if (ret)
		wpa_printf(MSG_DEBUG, "NAN: Failed to update config. ret=%d",
			   ret);

	return ret;
}


void nan_flush(struct nan_data *nan)
{
	wpa_printf(MSG_DEBUG, "NAN: Reset internal state");

	if (!nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Already stopped");
		return;
	}

	nan->nan_started = 0;
	nan_peer_clear_all(nan);
}


void nan_stop(struct nan_data *nan)
{
	wpa_printf(MSG_DEBUG, "NAN: Stopping");

	if (!nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Already stopped");
		return;
	}

	nan_flush(nan);
	nan->cfg->stop(nan->cfg->cb_ctx);
}


struct nan_peer * nan_get_peer(struct nan_data *nan, const u8 *addr)
{
	struct nan_peer *peer;

	dl_list_for_each(peer, &nan->peer_list, struct nan_peer, list) {
		if (ether_addr_equal(peer->nmi_addr, addr))
			return peer;
	}

	return NULL;
}


static struct nan_peer * nan_alloc_peer(struct nan_data *nan)
{
	struct nan_peer *peer, *oldest = NULL;
	size_t count = 0;

	dl_list_for_each(peer, &nan->peer_list, struct nan_peer, list) {
		count++;

		/* Do not expire peers that we have NDPs with */
		if (!dl_list_empty(&peer->ndps) || peer->ndp_setup.ndp)
			continue;

		if (!oldest ||
		    os_reltime_before(&peer->last_seen, &oldest->last_seen))
			oldest = peer;
	}

	if (count >= NAN_MAX_PEERS) {
		if (!oldest) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Cannot remove any of the peers");
			return NULL;
		}

		wpa_printf(MSG_DEBUG,
			   "NAN: Remove peer=" MACSTR " to make room",
			   MAC2STR(oldest->nmi_addr));

		nan_del_peer(nan, oldest);
	}

	peer = os_zalloc(sizeof(*peer));
	if (!peer)
		return NULL;

	dl_list_add(&nan->peer_list, &peer->list);
	dl_list_init(&peer->ndps);
	return peer;
}


int nan_add_peer(struct nan_data *nan, const u8 *addr,
		 const u8 *device_attrs, size_t device_attrs_len)
{
	struct nan_peer *peer;

	/* Allow adding peer devices even if NAN was not started, to support
	 * discovery during USD, etc. */
	if (!nan)
		return -1;

	/* TODO: parse the device attributes to update the peer information */
	if (!device_attrs || !device_attrs_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Ignore add_peer with no device attributes");
		return -1;
	}

	peer = nan_get_peer(nan, addr);
	if (!peer) {
		peer = nan_alloc_peer(nan);
		if (!peer)
			return -1;

		os_memcpy(peer->nmi_addr, addr, ETH_ALEN);
	}

	os_get_reltime(&peer->last_seen);
	return 0;
}


/*
 * nan_publish_instance_id_valid - Check if instance ID is a valid publish ID
 * @nan: NAN module context from nan_init()
 * @instance_id: Instance ID to check
 * @service_id: On return, holds the service ID if the instance ID is valid
 * Returns: true if there is a local publish service ID with the given instance
 * ID; false otherwise
 */
bool nan_publish_instance_id_valid(struct nan_data *nan, u8 instance_id,
				   u8 *service_id)
{
	/* TODO: Need implement this logic */
	wpa_printf(MSG_DEBUG,
		   "NAN: TODO: Publish instance ID validation not implemented");
	return true;
}
