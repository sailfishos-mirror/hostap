/*
 * Wi-Fi Aware - NAN Data link
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "common/ieee802_11_common.h"
#include "nan_i.h"


struct ndl_attr_params {
	u8 dialog_token;
	u8 type;
	u8 status;
	u8 reason;
	enum nan_ndl_setup_reason setup_reason;

	u16 max_idle_period;
	u8 min_slots;
	u16 max_latency;

	u8 ndc_id[ETH_ALEN];
	const u8 *ndc_sched;
	u16 ndc_sched_len;

	const u8 *immut_sched; u16 immut_sched_len;
};


static const char * nan_ndl_state_str(enum nan_ndl_state state)
{
#define C2S(x) case x: return #x;
	switch (state) {
	C2S(NAN_NDL_STATE_NONE)
	C2S(NAN_NDL_STATE_START)
	C2S(NAN_NDL_STATE_REQ_SENT)
	C2S(NAN_NDL_STATE_REQ_RECV)
	C2S(NAN_NDL_STATE_RES_SENT)
	C2S(NAN_NDL_STATE_RES_RECV)
	C2S(NAN_NDL_STATE_CON_SENT)
	C2S(NAN_NDL_STATE_CON_RECV)
	C2S(NAN_NDL_STATE_DONE)
	default:
		return "Invalid NAN NDL state";
	}
}


static void nan_ndl_set_state(struct nan_data *nan, struct nan_ndl *ndl,
			      enum nan_ndl_state state)
{
	wpa_printf(MSG_DEBUG, "NAN: NDL: State %s (%u) --> %s (%u)",
		   nan_ndl_state_str(ndl->state), ndl->state,
		   nan_ndl_state_str(state), state);

	ndl->state = state;
}


static void nan_ndl_time_bitmap_print(struct nan_data *nan,
				      struct nan_time_bitmap *tbm,
				      const char *type)
{
	if (!tbm->len)
		return;

	wpa_printf(MSG_DEBUG,
		   "channel sched: %s: dur=%u, per=%u, off=%u, len=%u",
		   type, tbm->duration, tbm->period, tbm->offset, tbm->len);

	wpa_printf(MSG_DEBUG, "bitmap[0:3]: 0x%x:0x%x:0x%x:0x%x",
		   tbm->bitmap[0], tbm->bitmap[1],
		   tbm->bitmap[2], tbm->bitmap[3]);
}


static void nan_ndl_chan_sched_print(struct nan_data *nan, size_t idx,
				     struct nan_chan_schedule *cs)
{
	wpa_printf(MSG_DEBUG, "NAN: sched: index=%zu, map_id=%u",
		   idx, cs->map_id);

	wpa_printf(MSG_DEBUG,
		   "channel sched: chan: freq=%u, c1=%d, c2=%d, bandwidth=%d",
		   cs->chan.freq, cs->chan.center_freq1, cs->chan.center_freq2,
		   cs->chan.bandwidth);

	nan_ndl_time_bitmap_print(nan, &cs->committed, "committed");
	nan_ndl_time_bitmap_print(nan, &cs->conditional, "conditional");
}


static void nan_ndl_sched_print(struct nan_data *nan,
				struct nan_schedule *sched)
{
	size_t i;

	wpa_printf(MSG_DEBUG,
		   "NAN: sched: map_ids=0x%x, n_chans=%u, seq_id=%u",
		   sched->map_ids_bitmap,
		   sched->n_chans, sched->sequence_id);

	for (i = 0; i < sched->n_chans; i++)
		nan_ndl_chan_sched_print(nan, i, &sched->chans[i]);
}


static void nan_ndl_clear(struct nan_data *nan, struct nan_peer *peer)
{
	struct nan_ndl *ndl = peer->ndl;

	wpa_printf(MSG_DEBUG,
		   "NAN: NDL: Clear info for peer=" MACSTR " state=%s (%u)",
		   MAC2STR(peer->nmi_addr),
		   nan_ndl_state_str(peer->ndl->state), peer->ndl->state);

	os_free(ndl->ndc_sched);
	ndl->ndc_sched = NULL;
	ndl->ndc_sched_len = 0;

	os_free(ndl->immut_sched);
	ndl->immut_sched = NULL;
	ndl->immut_sched_len = 0;

	ndl->dialog_token = 0;
	ndl->max_idle_period = 0;

	os_memset(ndl->ndc_id, 0, sizeof(ndl->ndc_id));

	ndl->peer_qos.max_latency = NAN_QOS_MAX_LATENCY_NO_PREF;
	ndl->local_qos.max_latency = NAN_QOS_MAX_LATENCY_NO_PREF;

	ndl->setup_reason = NAN_NDL_SETUP_REASON_NONE;

	wpabuf_free(ndl->sched.elems);
	os_memset(&ndl->sched, 0, sizeof(ndl->sched));
}


/*
 * nan_ndl_reset - Reset the NDL state
 *
 * @nan: NAN module context from nan_init()
 * @peer: The peer that requires NDL setup reset
 */
void nan_ndl_reset(struct nan_data *nan, struct nan_peer *peer)
{
	wpa_printf(MSG_DEBUG, "NAN: NDL: Reset state for peer=" MACSTR,
		   MAC2STR(peer->nmi_addr));

	if (!peer->ndl) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: Reset: no NDL");
		return;
	}

	nan_ndl_clear(nan, peer);

	os_free(peer->ndl);
	peer->ndl = NULL;
}


static struct nan_ndl * nan_ndl_alloc(struct nan_data *nan)
{
	struct nan_ndl *ndl;

	wpa_printf(MSG_DEBUG, "NAN: NDL: Allocating a new NDL");

	ndl = os_zalloc(sizeof(struct nan_ndl));
	if (!ndl) {
		wpa_printf(MSG_INFO, "NAN: NDL: Failed to allocate NDL");
		return NULL;
	}

	ndl->status = NAN_NDL_STATUS_ACCEPTED;
	ndl->reason = NAN_REASON_RESERVED;

	ndl->local_qos.min_slots = NAN_QOS_MIN_SLOTS_NO_PREF;
	ndl->local_qos.max_latency = NAN_QOS_MAX_LATENCY_NO_PREF;

	ndl->peer_qos.min_slots = NAN_QOS_MIN_SLOTS_NO_PREF;
	ndl->peer_qos.max_latency = NAN_QOS_MAX_LATENCY_NO_PREF;

	nan_ndl_set_state(nan, ndl, NAN_NDL_STATE_NONE);

	return ndl;
}


static int nan_ndl_validate_peer_avail(struct nan_data *nan,
				       struct nan_peer *peer)
{
	struct nan_ndl *ndl = peer->ndl;
	int ret;

	/* First, validate if immutable is covered by the availability map */
	ret = nan_sched_covered_by_avail_entries(nan, &peer->info.avail_entries,
						 ndl->immut_sched,
						 ndl->immut_sched_len);
	if (ret <= 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Peer avail: Immutable is not covered by avail");
		return -1;
	}

	/* Now validate NDC schedule is covered by the availability map */
	ret = nan_sched_covered_by_avail_entries(nan, &peer->info.avail_entries,
						 ndl->ndc_sched,
						 ndl->ndc_sched_len);
	if (ret <= 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Peer avail: NDC is not covered by avail");
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN: NDL: Peer NDC and immutable are covered by avail");
	return 0;
}


static enum nan_ndl_status nan_ndl_res_status(struct nan_data *nan,
					      struct nan_peer *peer)
{
	/* TODO: properly set the status */
	return NAN_NDL_STATUS_ACCEPTED;
}


/*
 * nan_ndl_setup - Handle NDL setup either as an initiator or a responder
 *
 * @nan: NAN module context from nan_init()
 * @peer: The peer for which the NDL is being setup
 * @params: NDP setup request parameters
 * Returns: 0 on success, negative on failure.

 * It is possible that an NDL with the peer already exists in which case it
 * would be reused. Otherwise, new NDL establishment will be started.
 */
int nan_ndl_setup(struct nan_data *nan, struct nan_peer *peer,
		  const struct nan_ndp_params *params)
{
	struct nan_ndl *ndl;
	enum nan_reason reason;

	if (!peer->ndl) {
		if (params->type != NAN_NDP_ACTION_REQ) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Invalid action; expecting request");
			return -1;
		}

		peer->ndl = nan_ndl_alloc(nan);
		if (!peer->ndl)
			return -1;

		ndl = peer->ndl;
	} else {
		ndl = peer->ndl;

		ndl->send_naf_on_error = 0;

		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: peer=" MACSTR ". state=%s (%u)",
			   MAC2STR(peer->nmi_addr),
			   nan_ndl_state_str(ndl->state),
			   ndl->state);

		if (ndl->state == NAN_NDL_STATE_DONE) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Already established");
			return 0;
		}

		if (!((params->type == NAN_NDP_ACTION_RESP &&
		       ndl->state == NAN_NDL_STATE_REQ_RECV) ||
		      (params->type == NAN_NDP_ACTION_CONF &&
		       ndl->state == NAN_NDL_STATE_RES_RECV))) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Invalid action type=%u, state=%u",
				   params->type, ndl->state);
			return -1;
		}

		if (params->u.resp.status == NAN_NDP_STATUS_REJECTED) {
			reason = params->u.resp.reason_code;
			goto out_fail;
		}
	}

	if (!params->sched_valid) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: no valid schedule");
		reason = NAN_REASON_INVALID_PARAMETERS;
		goto out_fail;
	}

	wpabuf_free(ndl->sched.elems);
	os_memcpy(&ndl->sched, &params->sched, sizeof(ndl->sched));
	nan_ndl_sched_print(nan, &peer->ndl->sched);

	/* Copy elems buffer */
	if (params->sched.elems) {
		ndl->sched.elems =
			wpabuf_alloc_copy(wpabuf_head(params->sched.elems),
					  wpabuf_len(params->sched.elems));
		if (!ndl->sched.elems) {
			reason = NAN_REASON_UNSPECIFIED_REASON;
			goto out_fail;
		}
	}

	if (is_zero_ether_addr(ndl->ndc_id)) {
		os_get_random(ndl->ndc_id, ETH_ALEN);
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: generated NDC ID " MACSTR,
			   MAC2STR(ndl->ndc_id));
	}

	ndl->local_qos.min_slots = params->qos.min_slots;
	ndl->local_qos.max_latency = params->qos.max_latency;

	if (ndl->state == NAN_NDL_STATE_NONE) {
		ndl->dialog_token = nan_get_next_dialog_token(nan);
		nan_ndl_set_state(nan, ndl, NAN_NDL_STATE_START);
		ndl->status = NAN_NDL_STATUS_CONTINUED;
	} else {
		ndl->status = nan_ndl_res_status(nan, peer);
	}

	ndl->setup_reason = NAN_NDL_SETUP_REASON_NDP;

	wpa_printf(MSG_DEBUG,
		   "NAN: NDL: success: state=%s (%u). Dialog token=%u",
		   nan_ndl_state_str(ndl->state), ndl->state,
		   ndl->dialog_token);

	return 0;

out_fail:
	wpa_printf(MSG_DEBUG, "NAN: NDL: Failed. reason=%u", reason);
	if (ndl->state == NAN_NDL_STATE_REQ_RECV ||
	    ndl->state == NAN_NDL_STATE_RES_RECV) {
		ndl->status = NAN_NDL_STATUS_REJECTED;
		ndl->reason = reason;
		ndl->send_naf_on_error = 1;
	}

	/* Clear the NDL info but leave the state, status, and reason. Full
	 * cleanup will be done on Tx status handling. */
	nan_ndl_clear(nan, peer);
	return -1;
}


/**
 * nan_ndl_setup_failure - Indicate failure during NDL setup
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer
 * @reason: Failure reason
 * @reset_state: Reset the NDL state if true.
 */
void nan_ndl_setup_failure(struct nan_data *nan, struct nan_peer *peer,
			   enum nan_reason reason, bool reset_state)
{
	struct nan_ndl *ndl = peer->ndl;

	wpa_printf(MSG_DEBUG,
		   "NAN: NDL: Setup failure: peer " MACSTR
		   ". state=%s (%u). reason=%u",
		   MAC2STR(peer->nmi_addr), nan_ndl_state_str(ndl->state),
		   ndl->state, reason);

	if (reset_state) {
		nan_ndl_reset(nan, peer);
	} else {
		ndl->status = NAN_NDL_STATUS_REJECTED;
		ndl->reason = reason;
	}
}


static int nan_ndl_parse_ndc_attr(struct nan_data *nan,
				  const struct ieee80211_ndc *ndc_attr,
				  u16 ndc_attr_len, u8 *ndc_id,
				  const u8 **ndc_schedule,
				  u16 *ndc_schedule_len)
{
	u16 ext_ndc_len;

	/* Consider only the selected NDC */
	if (!(ndc_attr->ctrl & NAN_NDC_CTRL_SELECTED))
		return -1;

	if (ndc_attr_len < sizeof(*ndc_attr))
		return -1;
	ext_ndc_len = ndc_attr_len - sizeof(*ndc_attr);

	if (ext_ndc_len <= sizeof(struct nan_sched_entry)) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: Request with invalid len=%u",
			   ndc_attr_len);
		return -1;
	}

	os_memcpy(ndc_id, ndc_attr->ndc_id, sizeof(ndc_attr->ndc_id));
	*ndc_schedule_len = ext_ndc_len;
	*ndc_schedule = (const u8 *) (ndc_attr + 1);

	wpa_printf(MSG_DEBUG, "NAN: NDL: ndc_id=" MACSTR " schedule_len=%u",
		   MAC2STR(ndc_id), *ndc_schedule_len);
	return 0;
}


static int nan_ndl_parse_qos_attr(struct nan_data *nan,
				  const struct ieee80211_nan_qos *qos_attr,
				  u16 qos_attr_len,
				  u8 *min_slots, u16 *max_latency)
{
	*min_slots = qos_attr->min_slots;
	*max_latency = le_to_host16(qos_attr->max_latency);

	wpa_printf(MSG_DEBUG, "NAN: QoS attr: min_slots=%u, max_latency=%u",
		   *min_slots, *max_latency);
	return 0;
}


static int nan_ndl_attr_handle_req(struct nan_data *nan, struct nan_peer *peer,
				   const struct ndl_attr_params *params)
{
	struct nan_ndl *ndl;
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: NDL: Handle request");

	if (peer->ndl) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Request while another establishment is ongoing");
		return -1;
	}

	if (params->status != NAN_NDL_STATUS_CONTINUED) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Request with invalid status=%u",
			   params->status);
		return -1;
	}

	peer->ndl = nan_ndl_alloc(nan);
	if (!peer->ndl)
		return -1;

	ndl = peer->ndl;

	ndl->status = NAN_NDL_STATUS_CONTINUED;

	ndl->dialog_token = params->dialog_token;
	ndl->max_idle_period = params->max_idle_period;
	ndl->setup_reason = params->setup_reason;

	if (!is_zero_ether_addr(params->ndc_id)) {
		os_memcpy(ndl->ndc_id, params->ndc_id, sizeof(ndl->ndc_id));

		if (params->ndc_sched && params->ndc_sched_len) {
			os_free(ndl->ndc_sched);
			ndl->ndc_sched_len = 0;

			ndl->ndc_sched = os_memdup(params->ndc_sched,
						   params->ndc_sched_len);
			if (!ndl->ndc_sched) {
				wpa_printf(MSG_INFO,
					   "NAN: NDL: Failed to copy NDC schedule");
				goto fail;
			}

			ndl->ndc_sched_len = params->ndc_sched_len;
		}
	}

	ndl->peer_qos.min_slots = params->min_slots;
	ndl->peer_qos.max_latency = params->max_latency;

	if (params->immut_sched && params->immut_sched_len) {
		ndl->immut_sched = os_memdup(params->immut_sched,
					     params->immut_sched_len);
		if (!ndl->immut_sched) {
			wpa_printf(MSG_INFO,
				   "NAN: NDL: Failed to copy immutable schedule");
			goto fail;
		}
		ndl->immut_sched_len = params->immut_sched_len;
	}

	ret = nan_ndl_validate_peer_avail(nan, peer);
	if (!ret)
		goto fail;

	nan_ndl_set_state(nan, ndl, NAN_NDL_STATE_REQ_RECV);

	wpa_printf(MSG_DEBUG, "NAN: NDL: Handle request done");
	return 0;

fail:
	nan_ndl_reset(nan, peer);
	return -1;
}


static int nan_ndl_attr_handle_resp(struct nan_data *nan, struct nan_peer *peer,
				    const struct ndl_attr_params *params)
{
	struct nan_ndl *ndl = peer->ndl;
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: NDL: Handle response");

	if (!ndl) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: Unexpected response");
		return -1;
	}

	if (ndl->state != NAN_NDL_STATE_REQ_SENT) {
		if (ndl->state != NAN_NDL_STATE_START) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Response while state=%s (%u)",
				   nan_ndl_state_str(ndl->state), ndl->state);
			return -1;
		}

		/*
		 * Due to races with the driver, it is possible that the
		 * response is received before an ACK is indicated. Allow the
		 * processing of the attribute, and if all parameters are OK,
		 * fast forward the state machine below.
		 */
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Response received before Tx status");
	}

	ndl->send_naf_on_error = 0;
	ndl->status = params->status;
	nan_ndl_set_state(nan, ndl, NAN_NDL_STATE_RES_RECV);

	if (ndl->dialog_token != params->dialog_token) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Resp: Invalid dialog token (%u != %u)",
			   ndl->dialog_token, params->dialog_token);
		return -1;
	}

	if (params->status != NAN_NDL_STATUS_CONTINUED &&
	    params->status != NAN_NDL_STATUS_ACCEPTED) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Resp: Rejected. status=%u, reason=%u",
			   params->status, params->reason);

		ndl->reason = params->reason;
		ndl->status = NAN_NDL_STATUS_REJECTED;
		return 0;
	}

	if (is_zero_ether_addr(params->ndc_id)) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: Response without NDC");
		return -1;
	}

	if (os_memcmp(ndl->ndc_id, params->ndc_id, sizeof(ndl->ndc_id)) != 0) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: Resp: ndc_id changed");
		os_memcpy(ndl->ndc_id, params->ndc_id, sizeof(ndl->ndc_id));
	}

	ndl->max_idle_period = params->max_idle_period;
	ndl->peer_qos.min_slots = params->min_slots;
	ndl->peer_qos.max_latency = params->max_latency;

	/* TODO: validate that in case an ACCEPTED NDL and an NDC, the NDC
	 * schedule is covered by the local device committed availability.
	 */
	if (params->ndc_sched && params->ndc_sched_len) {
		os_free(ndl->ndc_sched);
		ndl->ndc_sched_len = 0;

		ndl->ndc_sched = os_memdup(params->ndc_sched,
					   params->ndc_sched_len);
		if (!ndl->ndc_sched) {
			wpa_printf(MSG_INFO,
				   "NAN: NDL: Resp: Failed to allocate NDC schedule");
			ret = -1;
			goto fail;
		}

		ndl->ndc_sched_len = params->ndc_sched_len;
	}

	if (params->immut_sched && params->immut_sched_len) {
		if (params->status == NAN_NDL_STATUS_ACCEPTED) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Resp: Immutable not allowed with status == accept");
			return -1;
		}

		os_free(ndl->immut_sched);
		ndl->immut_sched_len = 0;
		ndl->immut_sched = os_memdup(params->immut_sched,
					     params->immut_sched_len);
		if (!ndl->immut_sched) {
			wpa_printf(MSG_INFO,
				   "NAN: NDL: Resp: fail allocate immutable schedule");
			ret = -1;
			goto fail;
		}
		ndl->immut_sched_len = params->immut_sched_len;
	}

	ret = nan_ndl_validate_peer_avail(nan, peer);
	if (!ret)
		goto fail;

	wpa_printf(MSG_DEBUG, "NAN: NDL: Resp: status=%u", params->status);

	ndl->status = params->status;
	if (params->status == NAN_NDL_STATUS_ACCEPTED)
		nan_ndl_set_state(nan, ndl, NAN_NDL_STATE_DONE);

	return 0;

fail:
	nan_ndl_clear(nan, peer);
	ndl->status = NAN_NDL_STATUS_REJECTED;
	ndl->reason = NAN_REASON_RESOURCE_LIMITATION;
	ndl->send_naf_on_error = 1;
	return ret;
}


static int nan_ndl_attr_handle_conf(struct nan_data *nan, struct nan_peer *peer,
				    const struct ndl_attr_params *params)
{
	struct nan_ndl *ndl = peer->ndl;
	int ret;

	if (!ndl) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: Confirm without an NDL");
		return -1;
	}

	if (ndl->state != NAN_NDL_STATE_RES_SENT) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Confirm while not expecting one");

		if (ndl->state != NAN_NDL_STATE_REQ_RECV ||
		    ndl->status != NAN_NDL_STATUS_CONTINUED)
			return -1;

		/*
		 * Due to races with the driver, it is possible that the
		 * response is received before an ACK is indicated. Allow the
		 * processing of the attribute, and if all parameters are OK,
		 * fast forward the state machine below.
		 */
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Confirm received before Tx status");
	}

	ndl->send_naf_on_error = 0;
	ndl->status = params->status;
	nan_ndl_set_state(nan, ndl, NAN_NDL_STATE_CON_RECV);

	if (params->status != NAN_NDL_STATUS_ACCEPTED) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Confirm was not accepted. status=%u, reason=%u",
			   params->status, params->reason);
		ndl->status = NAN_NDL_STATUS_REJECTED;
		ndl->reason = params->reason;
		return 0;
	}

	if (ndl->dialog_token != params->dialog_token) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Confirm with invalid dialog token (%u != %u)",
			   ndl->dialog_token, params->dialog_token);
		return -1;
	}

	if (!is_zero_ether_addr(params->ndc_id) &&
	    os_memcmp(ndl->ndc_id, params->ndc_id, sizeof(ndl->ndc_id)) != 0) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: Confirm: ndc_id changed");
		os_memcpy(ndl->ndc_id, params->ndc_id, sizeof(ndl->ndc_id));
	}

	ndl->max_idle_period = params->max_idle_period;
	ndl->peer_qos.min_slots = params->min_slots;
	ndl->peer_qos.max_latency = params->max_latency;

	/* TODO: validate that the NDC schedule is covered by the local device
	 * committed availability.
	 */
	if (params->ndc_sched && params->ndc_sched_len) {
		os_free(ndl->ndc_sched);
		ndl->ndc_sched_len = 0;

		ndl->ndc_sched = os_memdup(params->ndc_sched,
					   params->ndc_sched_len);
		if (!ndl->ndc_sched) {
			wpa_printf(MSG_INFO,
				   "NAN: NDL: Failed to allocate NDC schedule");
			ret = -1;
			goto fail;
		}
		ndl->ndc_sched_len = params->ndc_sched_len;
	}

	/* TODO: validate that the immutable schedule is covered by the local
	 * device committed availability.
	 */
	if (params->immut_sched && params->immut_sched_len) {
		os_free(ndl->immut_sched);
		ndl->immut_sched_len = 0;

		ndl->immut_sched = os_memdup(params->immut_sched,
					     params->immut_sched_len);
		if (!ndl->immut_sched) {
			wpa_printf(MSG_INFO,
				   "NAN: NDL: Failed to allocate immutable schedule");
			ret = -1;
			goto fail;
		}
		ndl->immut_sched_len = params->immut_sched_len;
	}

	ret = nan_ndl_validate_peer_avail(nan, peer);
	if (!ret)
		goto fail;

	nan_ndl_set_state(nan, ndl, NAN_NDL_STATE_DONE);
	return 0;

fail:
	ndl->reason = NAN_REASON_RESOURCE_LIMITATION;
	ndl->send_naf_on_error = 1;
	return ret;
}


/*
 * nan_ndl_handle_ndl_attr - Handle NDL attribute and update local state
 *
 * @nan: NAN module context from nan_init()
 * @peer: The peer from which the original message was received
 * @msg: Parsed NAN Action frame
 * Returns: 0 on success, negative on failure to parse the attributes etc.
 *
 * As part of the NDL attribute handling, the function also parses NDC and QoS
 * attributes.
 */
int nan_ndl_handle_ndl_attr(struct nan_data *nan, struct nan_peer *peer,
			    struct nan_msg *msg)
{
	const struct ieee80211_ndl *ndl_attr;
	const u8 *ndl_attr_ext;
	struct ndl_attr_params params;
	u16 ndl_attr_len, ndl_attr_ext_len;
	u16 control;
	u8 ctrl_setup_reason;
	u8 ndc_ok;
	int ret;

	os_memset(&params, 0, sizeof(params));

	if (!msg || !peer)
		return -1;

	/*
	 * It is possible that we receive a confirm NAF before the TX status
	 * of the previous NAF was processed. If NDL was accepted, the confirm
	 * would not include the NDL attribute, thus fast forward to state
	 * "done" here.
	 */
	if (msg->oui_subtype == NAN_SUBTYPE_DATA_PATH_CONFIRM &&
	    peer->ndl->state == NAN_NDL_STATE_REQ_RECV &&
	    peer->ndl->status == NAN_NDL_STATUS_ACCEPTED) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL is accepted - fast forward to state done");
		nan_ndl_set_state(nan, peer->ndl, NAN_NDL_STATE_DONE);
	}

	if (peer->ndl && peer->ndl->state == NAN_NDL_STATE_DONE) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: NDL already done");
		return 0;
	}

	if (!msg->attrs.ndl)
		return 0;

	ndl_attr = (const struct ieee80211_ndl *) msg->attrs.ndl;
	ndl_attr_len = msg->attrs.ndl_len;
	if (ndl_attr_len < sizeof(struct ieee80211_ndl))
		return -1;

	ndl_attr_ext = (const u8 *) (ndl_attr + 1);
	ndl_attr_ext_len = ndl_attr_len - sizeof(struct ieee80211_ndl);

	params.type = BITS(ndl_attr->type_and_status, NAN_NDL_TYPE_MASK,
			   NAN_NDL_TYPE_POS);

	params.status = BITS(ndl_attr->type_and_status, NAN_NDL_STATUS_MASK,
			     NAN_NDL_STATUS_POS);
	control = le_to_host16(ndl_attr->ctrl);

	if (peer->ndl)
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: curr: state=%s (%d), status=%d",
			   nan_ndl_state_str(peer->ndl->state),
			   peer->ndl->state, peer->ndl->status);
	else
		wpa_printf(MSG_DEBUG, "NAN: NDL: NDL does not exist");

	params.dialog_token = ndl_attr->dialog_token;

	wpa_printf(MSG_DEBUG,
		   "NAN: NDL: dialog=%u, type=0x%x, status=0x%x, ctrl=0x%x",
		   params.dialog_token, params.type, params.status, control);

	if (control & NAN_NDL_CTRL_PEER_ID_PRESENT) {
		if (ndl_attr_ext_len < 1) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Request with invalid len=%u, control=0x%x",
				   ndl_attr_len, control);
			return -1;
		}

		/*
		 * Peer ID is no longer used. It is considered as reserved in
		 * Wi-Fi Aware Specification v4.0, Table 105 (NDL attribute
		 * format). Just skip it.
		 */
		ndl_attr_ext++;
		ndl_attr_ext_len--;
	}

	if (control & NAN_NDL_CTRL_MAX_IDLE_PERIOD_PRESENT) {
		if (ndl_attr_ext_len < 2) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Request with invalid len=%u, control=0x%x",
				   ndl_attr_len, control);
			return -1;
		}

		params.max_idle_period = WPA_GET_LE16(ndl_attr_ext);
		ndl_attr_ext += 2;
		ndl_attr_ext_len -= 2;
	}

	ndc_ok = 1;
	if (control & NAN_NDL_CTRL_NDC_ATTR_PRESENT) {
		struct nan_attrs_entry *n;

		ret = -1;
		dl_list_for_each(n, &msg->attrs.ndc, struct nan_attrs_entry,
				 list) {
			ret = nan_ndl_parse_ndc_attr(
				nan, (const struct ieee80211_ndc *) n->ptr,
				n->len, params.ndc_id,
				&params.ndc_sched, &params.ndc_sched_len);
			if (!ret)
				break;
		}

		if (ret)
			ndc_ok = 0;
	} else if (params.type == NAN_NDL_TYPE_RESPONSE) {
		ndc_ok = 0;
	}

	if (!ndc_ok) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: Missing valid selected NDC");
		return -1;
	}

	params.min_slots = NAN_QOS_MIN_SLOTS_NO_PREF;
	params.max_latency = NAN_QOS_MAX_LATENCY_NO_PREF;
	if (control & NAN_NDL_CTRL_NDL_QOS_ATTR_PRESENT) {
		if (!msg->attrs.ndl_qos) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL QoS attribute not present but control flag is set");
			return -1;
		}
		ret = nan_ndl_parse_qos_attr(
			nan,
			(const struct ieee80211_nan_qos *) msg->attrs.ndl_qos,
			msg->attrs.ndl_qos_len, &params.min_slots,
			&params.max_latency);
		if (ret)
			return ret;
	}

	if (control & NAN_NDL_CTRL_IMMUT_SCHED_PRESENT) {
		if (ndl_attr_ext_len <= sizeof(struct nan_sched_entry)) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Request with invalid len=%u, control=0x%x",
				ndl_attr_len, control);
			return -1;
		}

		params.immut_sched = ndl_attr_ext;
		params.immut_sched_len = ndl_attr_ext_len;
	}

	ctrl_setup_reason = BITS(control, NAN_NDL_CTRL_NDL_SETUP_REASON_MASK,
				 NAN_NDL_CTRL_NDL_SETUP_REASON_POS);
	if (ctrl_setup_reason == NAN_NDL_CTRL_NDL_SETUP_REASON_NDP) {
		params.setup_reason = NAN_NDL_SETUP_REASON_NDP;
	} else {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Unknown setup reason. Assume NDP");
		params.setup_reason = NAN_NDL_SETUP_REASON_NDP;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN: NDL: max_idle_period=%u, immutable len=%u",
		   params.max_idle_period, params.immut_sched_len);

	switch (params.type) {
	case NAN_NDL_TYPE_REQUEST:
		return nan_ndl_attr_handle_req(nan, peer, &params);
	case NAN_NDL_TYPE_RESPONSE:
		return nan_ndl_attr_handle_resp(nan, peer, &params);
	case NAN_NDL_TYPE_CONFIRM:
		return nan_ndl_attr_handle_conf(nan, peer, &params);
	default:
		return -1;
	}
}


/**
 * nan_ndl_add_avail_attrs - Add availability attributes
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer for NDL establishment
 * @buf: Frame buffer to which the attribute would be added
 * Returns: 0 on success, negative on failure
 *
 * An availability attribute is added for each map (identified by map ID) in the
 * NDL schedule. Each attribute holds an availability entry for committed slots
 * and an availability entry for conditional slots.
 */
int nan_ndl_add_avail_attrs(struct nan_data *nan, const struct nan_peer *peer,
			    struct wpabuf *buf)
{
	struct nan_schedule *sched;
	u8 type_for_conditional = NAN_AVAIL_ENTRY_CTRL_TYPE_COND;

	if (!peer || !peer->ndl)
		return -1;

	sched = &peer->ndl->sched;

	wpa_printf(MSG_DEBUG,
		   "NAN: NDL: Add Avail attribute. state=%s, status=%u",
		   nan_ndl_state_str(peer->ndl->state), peer->ndl->status);

	if (sched->n_chans < 1) {
		if (peer->ndl->status == NAN_NDL_STATUS_REJECTED) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Rejected. Not adding availability attributes");
			return 0;
		}

		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Cannot build availability without channels");
		return -1;
	}

	/* In case the NDL exchange was complete successfully, consider the
	 * conditional entries as committed, as this is expected by the spec.
	 */
	if (peer->ndl->status == NAN_NDL_STATUS_ACCEPTED) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Add conditional entry as committed");
		type_for_conditional = NAN_AVAIL_ENTRY_CTRL_TYPE_COMMITTED;
	}

	return nan_add_avail_attrs(nan, sched->sequence_id,
				   sched->map_ids_bitmap,
				   type_for_conditional,
				   sched->n_chans, sched->chans, buf);
}


/**
 * nan_ndl_add_ndl_attr - Add NDL attribute to frame
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer for NDL establishment
 * @buf: Frame buffer to which the attribute would be added
 * Returns: 0 on success, negative on failure.
 */
int nan_ndl_add_ndl_attr(struct nan_data *nan, const struct nan_peer *peer,
			 struct wpabuf *buf)
{
	struct nan_ndl *ndl;
	u16 ndl_ctrl = 0;
	u8 type;

	if (!peer || !peer->ndl)
		return -1;

	ndl = peer->ndl;

	wpa_printf(MSG_DEBUG, "NAN: Add NDL attribute. state=%s, status=%u",
		   nan_ndl_state_str(ndl->state), ndl->status);

	switch (ndl->state) {
	case NAN_NDL_STATE_NONE:
	case NAN_NDL_STATE_REQ_SENT:
	case NAN_NDL_STATE_RES_SENT:
	case NAN_NDL_STATE_CON_SENT:
	default:
		return -1;
	case NAN_NDL_STATE_START:
		type = NAN_NDL_TYPE_REQUEST;
		if (ndl->sched.ndc.len)
			ndl_ctrl |= NAN_NDL_CTRL_NDC_ATTR_PRESENT;
		break;
	case NAN_NDL_STATE_REQ_RECV:
		type = NAN_NDL_TYPE_RESPONSE;
		if (ndl->sched.ndc.len &&
		    ndl->status != NAN_NDL_STATUS_REJECTED)
			ndl_ctrl |= NAN_NDL_CTRL_NDC_ATTR_PRESENT;
		break;
	case NAN_NDL_STATE_RES_RECV:
		type = NAN_NDL_TYPE_CONFIRM;
		if (ndl->sched.ndc.len &&
		    ndl->status != NAN_NDL_STATUS_REJECTED)
			ndl_ctrl |= NAN_NDL_CTRL_NDC_ATTR_PRESENT;
		break;
	case NAN_NDL_STATE_DONE:
		wpa_printf(MSG_DEBUG,
			   "NAN: NDL: Done. Not adding NDL attribute");
		return 0;
	}

	/* QoS attribute is going to be added */
	if (ndl->local_qos.max_latency != NAN_QOS_MAX_LATENCY_NO_PREF ||
	    ndl->local_qos.min_slots != NAN_QOS_MIN_SLOTS_NO_PREF)
		ndl_ctrl |= NAN_NDL_CTRL_NDL_QOS_ATTR_PRESENT;

	wpabuf_put_u8(buf, NAN_ATTR_NDL);
	wpabuf_put_le16(buf, sizeof(struct ieee80211_ndl));

	wpabuf_put_u8(buf, ndl->dialog_token);
	wpabuf_put_u8(buf, type | (ndl->status << NAN_NDL_STATUS_POS));
	wpabuf_put_u8(buf, ndl->reason);
	wpabuf_put_u8(buf, ndl_ctrl);

	return 0;
}


/**
 * nan_ndl_add_ndc_attr - Add NDC attribute to frame
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer for NDL establishment
 * @buf: Frame buffer to which the attribute would be added
 * Returns: 0 on success, negative on failure.
 */
int nan_ndl_add_ndc_attr(struct nan_data *nan, const struct nan_peer *peer,
			 struct wpabuf *buf)
{
	struct nan_ndl *ndl;
	u8 ndc_ctrl = NAN_NDC_CTRL_SELECTED;
	u16 sched_entry_ctrl = 0;

	if (!peer || !peer->ndl)
		return -1;

	ndl = peer->ndl;

	if (ndl->state != NAN_NDL_STATE_START &&
	    ndl->state != NAN_NDL_STATE_REQ_RECV &&
	    ndl->state != NAN_NDL_STATE_RES_RECV)
		return 0;

	wpa_printf(MSG_DEBUG, "NAN: Add NDC attribute. state=%s, status=%u",
		   nan_ndl_state_str(ndl->state), ndl->status);

	/* NDC attribute is optional in case of reject */
	if (ndl->status == NAN_NDL_STATUS_REJECTED)
		return 0;

	/*
	 * NDC attribute for NDP Request is optional. In all other cases it is
	 * mandatory
	 */
	if (!ndl->sched.ndc.len) {
		if (ndl->state != NAN_NDL_STATE_START) {
			wpa_printf(MSG_DEBUG, "NAN: NDL: No NDC to add");
			return -1;
		}

		return 0;
	}

	wpabuf_put_u8(buf, NAN_ATTR_NDC);
	wpabuf_put_le16(buf, sizeof(struct ieee80211_ndc) +
			sizeof(struct nan_sched_entry) +
			ndl->sched.ndc.len);

	wpabuf_put_data(buf, ndl->ndc_id, sizeof(ndl->ndc_id));
	wpabuf_put_u8(buf, ndc_ctrl);

	/* Add the schedule entry */
	wpabuf_put_u8(buf, ndl->sched.ndc_map_id);

	sched_entry_ctrl |= ndl->sched.ndc.duration <<
		NAN_TIME_BM_CTRL_BIT_DURATION_POS;
	sched_entry_ctrl |= ndl->sched.ndc.period <<
		NAN_TIME_BM_CTRL_PERIOD_POS;
	sched_entry_ctrl |= ndl->sched.ndc.offset <<
		NAN_TIME_BM_CTRL_START_OFFSET_POS;

	wpabuf_put_le16(buf, sched_entry_ctrl);

	/* Add the time bitmap */
	wpabuf_put_u8(buf, ndl->sched.ndc.len);
	wpabuf_put_data(buf, ndl->sched.ndc.bitmap, ndl->sched.ndc.len);

	return 0;
}


/**
 * nan_ndl_add_qos_attr - Add QOS attribute to frame
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer for NDL establishment
 * @buf: Frame buffer to which the attribute would be added
 * Returns: 0 on success, negative on failure.
 */
int nan_ndl_add_qos_attr(struct nan_data *nan,
			 const struct nan_peer *peer,
			 struct wpabuf *buf)
{
	struct nan_ndl *ndl;

	if (!peer || !peer->ndl)
		return -1;

	ndl = peer->ndl;

	wpa_printf(MSG_DEBUG, "NAN: Add QoS attribute. state=%s, status=%u",
		   nan_ndl_state_str(ndl->state), ndl->status);

	switch (ndl->state) {
	case NAN_NDL_STATE_START:
	case NAN_NDL_STATE_REQ_RECV:
	case NAN_NDL_STATE_RES_RECV:
		break;
	case NAN_NDL_STATE_NONE:
	case NAN_NDL_STATE_REQ_SENT:
	case NAN_NDL_STATE_RES_SENT:
	case NAN_NDL_STATE_CON_SENT:
	case NAN_NDL_STATE_CON_RECV:
	case NAN_NDL_STATE_DONE:
	default:
		return 0;
	}

	if (ndl->local_qos.max_latency == NAN_QOS_MAX_LATENCY_NO_PREF &&
	    ndl->local_qos.min_slots == NAN_QOS_MIN_SLOTS_NO_PREF)
		return 0;

	wpabuf_put_u8(buf, NAN_ATTR_NDL_QOS);
	wpabuf_put_le16(buf, sizeof(struct ieee80211_nan_qos));
	wpabuf_put_u8(buf, ndl->local_qos.min_slots);
	wpabuf_put_le16(buf, ndl->local_qos.max_latency);

	return 0;
}


/**
 * nan_ndl_naf_sent - Indicate a NAF has been sent
 * @nan: NAN module context from nan_init()
 * @peer: The peer with whom the NDL is being setup
 * @subtype: The NAN OUI subtype
 *
 * A notification indicating to the NDL state machine that a NAF was sent, so
 * the NDL state machine can update its state.
 *
 * In case the NDL setup negotiation is successfully done, the final schedule
 * is applied and the NDL is active. If the negotiation is done and failed, the
 * NDL state is reset.
 */
int nan_ndl_naf_sent(struct nan_data *nan, struct nan_peer *peer,
		     enum nan_subtype subtype)
{
	struct nan_ndl *ndl;

	if (!peer || !peer->ndl)
		return -1;

	ndl = peer->ndl;

	if (ndl->state == NAN_NDL_STATE_DONE)
		return 0;

	wpa_printf(MSG_DEBUG,
		   "NAN: NDL: Tx done with peer=" MACSTR " state=%s, status=%u",
		   MAC2STR(peer->nmi_addr), nan_ndl_state_str(ndl->state),
		   ndl->status);

	/* Note: Due to races between the Tx status and Rx path, it is possible
	 * that the Tx status is received after the peer response was already
	 * processed (which can result with another frame being sent). In such a
	 * case the logic above fast-forwards the state, and the transitions
	 * here need to take this into consideration.
	 */
	switch (ndl->state) {
	case NAN_NDL_STATE_START:
		if (subtype != NAN_SUBTYPE_DATA_PATH_REQUEST)
			return 0;
		if (ndl->status != NAN_NDL_STATUS_CONTINUED) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Tx sent: invalid continue status");
			return -1;
		}
		nan_ndl_set_state(nan, ndl, NAN_NDL_STATE_REQ_SENT);
		return 0;
	case NAN_NDL_STATE_REQ_RECV:
		if (subtype != NAN_SUBTYPE_DATA_PATH_RESPONSE)
			return 0;
		if (ndl->status == NAN_NDL_STATUS_CONTINUED) {
			nan_ndl_set_state(nan, ndl, NAN_NDL_STATE_RES_SENT);
			return 0;
		}
		break;
	case NAN_NDL_STATE_RES_RECV:
		if (subtype != NAN_SUBTYPE_DATA_PATH_CONFIRM)
			return 0;
		if (ndl->status == NAN_NDL_STATUS_CONTINUED) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDL: Tx sent: invalid continue status");
			return -1;
		}
		break;
	case NAN_NDL_STATE_CON_RECV:
	case NAN_NDL_STATE_REQ_SENT:
	case NAN_NDL_STATE_RES_SENT:
	case NAN_NDL_STATE_CON_SENT:
	case NAN_NDL_STATE_DONE:
	default:
		wpa_printf(MSG_DEBUG, "NAN: NDL: Tx sent: unexpected state %d",
			   ndl->state);
		return 0;
	}

	if (ndl->status == NAN_NDL_STATUS_ACCEPTED) {
		wpa_printf(MSG_DEBUG, "NAN: NDL: Schedule setup success");
		nan_ndl_set_state(nan, ndl, NAN_NDL_STATE_DONE);
		return 0;
	}

	/* NDL is rejected and NAF already sent. Higher layer is expected to
	 * handle it.
	 */
	return 0;
}
