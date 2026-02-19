/*
 * Wi-Fi Aware - NAN Data Path
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "nan_i.h"


static const char * nan_ndp_state_str(enum nan_ndp_state state)
{
#define C2S(x) case x: return #x;
	switch (state) {
	C2S(NAN_NDP_STATE_NONE)
	C2S(NAN_NDP_STATE_START)
	C2S(NAN_NDP_STATE_REQ_SENT)
	C2S(NAN_NDP_STATE_REQ_RECV)
	C2S(NAN_NDP_STATE_RES_SENT)
	C2S(NAN_NDP_STATE_RES_RECV)
	C2S(NAN_NDP_STATE_CON_SENT)
	C2S(NAN_NDP_STATE_CON_RECV)
	C2S(NAN_NDP_STATE_DONE)
	default:
		return "Invalid NAN NDP state";
	}
}


static void nan_ndp_set_state(struct nan_data *nan,
			      struct nan_ndp_setup *ndp_setup,
			      enum nan_ndp_state state)
{
	wpa_printf(MSG_DEBUG,
		   "NAN: NDP: state: %s (%u) --> %s (%u)",
		   nan_ndp_state_str(ndp_setup->state),
		   ndp_setup->state, nan_ndp_state_str(state),
		   state);

	ndp_setup->state = state;
}


static struct nan_ndp *
nan_ndp_alloc(struct nan_data *nan, struct nan_peer *peer,
	      u8 initiator, u8 *init_ndi, u8 ndp_id, u8 min_slots,
	      u16 max_latency)
{
	struct nan_ndp *ndp = os_zalloc(sizeof(*ndp));

	if (!ndp)
		return NULL;

	ndp->peer = peer;
	ndp->initiator = initiator;
	ndp->ndp_id = ndp_id;

	os_memcpy(ndp->init_ndi, init_ndi, sizeof(ndp->init_ndi));

	ndp->qos.min_slots = min_slots;
	ndp->qos.max_latency = max_latency;

	return ndp;
}


static int nan_ndp_ssi(struct nan_data *nan, struct nan_ndp_setup *ndp_setup,
		       const u8 *ssi, u16 ssi_len)
{
	os_free(ndp_setup->ssi);
	ndp_setup->ssi = NULL;
	ndp_setup->ssi_len = 0;

	if (!ssi || !ssi_len)
		return 0;

	ndp_setup->ssi = os_memdup(ssi, ssi_len);
	if (!ndp_setup->ssi) {
		wpa_printf(MSG_INFO, "NAN: NDP: Failed to allocate NDP ssi");
		return -1;
	}

	ndp_setup->ssi_len = ssi_len;
	return 0;
}


/**
 * nan_ndp_setup_req - Start handling of NDP setup request
 * @nan: NAN module context from nan_init()
 * @peer: The peer to initiate the NDP setup with
 * @params: NDP setup request parameters
 * Returns: 0 on success, negative on failure
 *
 * On successful request, the data structures would be ready to
 * continue the NDP establishment.
 */
int nan_ndp_setup_req(struct nan_data *nan, struct nan_peer *peer,
		      struct nan_ndp_params *params)
{
	int ret;

	if (peer->ndp_setup.ndp) {
		wpa_printf(MSG_DEBUG, "NAN: NDP: already WIP with peer");
		return -1;
	}

	peer->ndp_setup.ndp = nan_ndp_alloc(nan, peer, 1,
					    params->ndp_id.init_ndi,
					    params->ndp_id.id,
					    params->qos.min_slots,
					    params->qos.max_latency);
	if (!peer->ndp_setup.ndp) {
		wpa_printf(MSG_DEBUG, "NAN: NDP: Failed allocation");
		return -1;
	}

	peer->ndp_setup.dialog_token = nan_get_next_dialog_token(nan);
	peer->ndp_setup.publish_inst_id = params->u.req.publish_inst_id;
	os_memcpy(peer->ndp_setup.service_id, params->u.req.service_id,
		  NAN_SERVICE_ID_LEN);

	/* Require confirmation for all locally initiated NDPs */
	peer->ndp_setup.conf_req = 1;

	/* Store service specific information */
	ret = nan_ndp_ssi(nan, &peer->ndp_setup, params->ssi, params->ssi_len);
	if (ret) {
		os_free(peer->ndp_setup.ndp);
		peer->ndp_setup.ndp = NULL;
		return ret;
	}

	nan_ndp_set_state(nan, &peer->ndp_setup, NAN_NDP_STATE_START);
	peer->ndp_setup.status = NAN_NDP_STATUS_CONTINUED;
	return 0;
}


/**
 * nan_ndp_setup_resp - Handle higher layer response for an NDP request
 * @nan: NAN module context from nan_init()
 * @peer: Peer that originated the NDP setup request
 * @params: NDP setup parameters
 * Returns: 0 on success, negative on failure
 *
 * The response status can be either ACCEPTED or REJECTED. The internal logic of
 * the NDP state machine adjusts its own state according to the response status
 * and its internal state.
 */
int nan_ndp_setup_resp(struct nan_data *nan, struct nan_peer *peer,
		       struct nan_ndp_params *params)
{
	int ret;

	if (!peer->ndp_setup.ndp ||
	    peer->ndp_setup.ndp->ndp_id != params->ndp_id.id ||
	    !ether_addr_equal(peer->ndp_setup.ndp->init_ndi,
			      params->ndp_id.init_ndi)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: No matching NDP found for NDP response");
		return -1;
	}

	if (peer->ndp_setup.state != NAN_NDP_STATE_REQ_RECV) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: Unexpected state for response");
		return -1;
	}

	if (params->u.resp.status != NAN_NDP_STATUS_ACCEPTED &&
	    params->u.resp.status != NAN_NDP_STATUS_REJECTED) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: Unexpected response status=%u",
			params->u.resp.status);
		return -1;
	}

	/* Store service specific information */
	ret = nan_ndp_ssi(nan, &peer->ndp_setup, params->ssi, params->ssi_len);
	if (ret)
		return ret;

	/* TODO: In case of security and status accept, need to change to
	 * continue
	 */
	peer->ndp_setup.status = params->u.resp.status;
	peer->ndp_setup.reason = params->u.resp.reason_code;

	if (peer->ndp_setup.status == NAN_NDP_STATUS_ACCEPTED) {
		if (peer->ndp_setup.conf_req)
			peer->ndp_setup.status = NAN_NDP_STATUS_CONTINUED;

		os_memcpy(peer->ndp_setup.ndp->resp_ndi,
			  params->u.resp.resp_ndi, ETH_ALEN);
	}

	return 0;
}


static int nan_ndp_attr_handle_req(struct nan_data *nan, struct nan_peer *peer,
				   struct ieee80211_ndp *ndp_attr, u16 ndp_len,
				   u8 status)
{
	struct nan_ndp_setup *ndp_setup = &peer->ndp_setup;
	u16 exp_len = sizeof(struct ieee80211_ndp);
	u8 publish_inst_id;

	if (ndp_setup->ndp) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: req: While already WIP with peer");
		return -1;
	}

	if (!(ndp_attr->ndp_ctrl & NAN_NDP_CTRL_PUBLISH_ID_PRESENT)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: req: Without publish ID");
		return -1;
	}

	exp_len++;
	if (ndp_len < exp_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: req: Length too short: ndp_len=%u, exp_len=%u",
			   ndp_len, exp_len);
		return -1;
	}

	publish_inst_id = *ndp_attr->optional;
	if (!nan_publish_instance_id_valid(nan, publish_inst_id,
					   ndp_setup->service_id)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: req: Invalid publish instance ID=%u",
			publish_inst_id);
		return -1;
	}

	/* Note: The QoS setting should be set in the response. */
	ndp_setup->ndp = nan_ndp_alloc(nan, peer, 0,
				       ndp_attr->initiator_ndi,
				       ndp_attr->ndp_id,
				       NAN_QOS_MIN_SLOTS_NO_PREF,
				       NAN_QOS_MAX_LATENCY_NO_PREF);
	if (!ndp_setup->ndp)
		return -1;

	nan_ndp_set_state(nan, ndp_setup, NAN_NDP_STATE_REQ_RECV);

	ndp_setup->status = NAN_NDP_STATUS_CONTINUED;
	ndp_setup->conf_req =
		!!(ndp_attr->ndp_ctrl & NAN_NDP_CTRL_CONFIRM_REQUIRED);
	ndp_setup->dialog_token = ndp_attr->dialog_token;
	ndp_setup->publish_inst_id = publish_inst_id;

	/* Handle service specific information */
	ndp_len -= exp_len;

	if (ndp_attr->ndp_ctrl & NAN_NDP_CTRL_SPEC_INFO_PRESENT && ndp_len) {
		int ret;

		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: req: Handle NDP service specific information");
		ret = nan_ndp_ssi(nan, &peer->ndp_setup,
				  (const u8 *) ndp_attr->optional + 1,
				  ndp_len);
		if (ret)
			wpa_printf(MSG_DEBUG,
				   "NAN: NDP: req: Failed to save ssi. continue");
	}

	return 0;
}


static int nan_ndp_attr_handle_res(struct nan_data *nan, struct nan_peer *peer,
				   struct ieee80211_ndp *ndp_attr, u16 ndp_len,
				   u8 status)
{
	struct nan_ndp_setup *ndp_setup = &peer->ndp_setup;
	u16 opt_len;

	if (!ndp_setup->ndp) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: resp: While no NDP WIP with peer");
		return -1;
	}

	if (ndp_setup->state != NAN_NDP_STATE_REQ_SENT) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: resp: While not expecting one");

		if (ndp_setup->state != NAN_NDP_STATE_START)
			return -1;

		/*
		 * Due to races with the driver, it is possible that the
		 * response is received before an ACK is indicated. Allow the
		 * processing of the attribute, and if all parameters are OK,
		 * fast forward the state machine below.
		 */
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: resp: Received before Tx status.");
	}

	if (ndp_attr->ndp_ctrl & NAN_NDP_CTRL_PUBLISH_ID_PRESENT) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: resp: Unexpected publish ID");
		return -1;
	}

	opt_len = 0;
	if (status == NAN_NDP_STATUS_CONTINUED ||
	    status == NAN_NDP_STATUS_ACCEPTED) {
		if (!(ndp_attr->ndp_ctrl &
		      NAN_NDP_CTRL_RESPONDER_NDI_PRESENT)) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDP: resp: without responder NDI");
			return -1;
		}
		opt_len += ETH_ALEN;
	}

	if (ndp_len < (sizeof(struct ieee80211_ndp) + opt_len)) {
		wpa_printf(MSG_DEBUG, "NAN: NDP: resp: Length too short");
		return -1;
	}

	if (ndp_setup->ndp->ndp_id != ndp_attr->ndp_id ||
	    ndp_setup->dialog_token != ndp_attr->dialog_token ||
	    !ether_addr_equal(ndp_setup->ndp->init_ndi,
			      ndp_attr->initiator_ndi)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: resp: Invalid NDP ID, dialog token or addr");
		return -1;
	}

	if (ndp_setup->state == NAN_NDP_STATE_START) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: resp: Continue though no TX status yet.");
		nan_ndp_set_state(nan, &peer->ndp_setup,
				  NAN_NDP_STATE_REQ_SENT);
	}

	ndp_setup->status = status;

	if (status == NAN_NDP_STATUS_REJECTED) {
		ndp_setup->reason = ndp_attr->reason_code;
		nan_ndp_set_state(nan, &peer->ndp_setup,
				  NAN_NDP_STATE_DONE);
		goto store_ssi;
	}

	if (((ndp_attr->ndp_ctrl & NAN_NDP_CTRL_SECURITY_PRESENT) ||
	     ndp_setup->conf_req) && status != NAN_NDP_STATUS_CONTINUED) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: Security present and status != continue");
		return -1;
	}

	if (status == NAN_NDP_STATUS_ACCEPTED)
		nan_ndp_set_state(nan, &peer->ndp_setup, NAN_NDP_STATE_DONE);
	else
		nan_ndp_set_state(nan, &peer->ndp_setup,
				  NAN_NDP_STATE_RES_RECV);

	os_memcpy(ndp_setup->ndp->resp_ndi, &ndp_attr->optional[0],
		  sizeof(ndp_setup->ndp->resp_ndi));

	/*
	 * In case that security is not configured, move the status to accepted.
	 * The state machine would transition to the 'done' state after the
	 * confirm is acked.
	 * TODO: Once security is configured, need to validate the security must
	 * be present.
	 */
	if (!(ndp_attr->ndp_ctrl & NAN_NDP_CTRL_SECURITY_PRESENT))
		ndp_setup->status = NAN_NDP_STATUS_ACCEPTED;

store_ssi:
	/* Handle service specific information */
	ndp_len -= sizeof(struct ieee80211_ndp) + opt_len;
	if (ndp_attr->ndp_ctrl & NAN_NDP_CTRL_SPEC_INFO_PRESENT && ndp_len) {
		int ret;

		wpa_printf(MSG_DEBUG, "NAN: NDP: resp: Handle NDP ssi");
		ret = nan_ndp_ssi(nan, &peer->ndp_setup,
				  ndp_attr->optional + opt_len, ndp_len);
		if (ret)
			wpa_printf(MSG_DEBUG,
				   "NAN: NDP: resp: Failed to save ssi. continue");
	}

	return 0;
}


static int nan_ndp_attr_handle_confirm(struct nan_data *nan,
				       struct nan_peer *peer,
				       struct ieee80211_ndp *ndp_attr,
				       u8 status)
{
	struct nan_ndp_setup *ndp_setup = &peer->ndp_setup;

	if (!ndp_setup->ndp) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: Received confirm while no NDP WIP with peer");
		return -1;
	}

	if (ndp_setup->state != NAN_NDP_STATE_RES_SENT) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: confirm: While not expecting one");

		if (ndp_setup->state != NAN_NDP_STATE_REQ_RECV ||
		    ndp_setup->status != NAN_NDP_STATUS_CONTINUED)
			return -1;

		/*
		 * Due to races with the driver, it is possible that the
		 * confirm is received before an ACK is indicated. Allow the
		 * processing of the attribute, and if all parameters are OK,
		 * fast forward the state machine below.
		 */
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: Confirm received before Tx status");
	}

	if (ndp_setup->ndp->ndp_id != ndp_attr->ndp_id ||
	    ndp_setup->dialog_token != ndp_attr->dialog_token ||
	    !ether_addr_equal(ndp_setup->ndp->init_ndi,
			      ndp_attr->initiator_ndi)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: confirm: Invalid NDP ID, dialog token or init ID");
		return -1;
	}

	if ((ndp_attr->ndp_ctrl & NAN_NDP_CTRL_SECURITY_PRESENT) &&
	    status != NAN_NDP_STATUS_CONTINUED) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: confirm: status != continue with security");
		return -1;
	}

	if (ndp_setup->state == NAN_NDP_STATE_REQ_RECV) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: confirm: Continue though no TX status yet.");
		nan_ndp_set_state(nan, &peer->ndp_setup,
				  NAN_NDP_STATE_RES_SENT);
	}

	ndp_setup->status = status;

	/* TODO: handle security */
	if (status == NAN_NDP_STATUS_ACCEPTED)
		nan_ndp_set_state(nan, &peer->ndp_setup, NAN_NDP_STATE_DONE);
	else
		nan_ndp_set_state(nan, &peer->ndp_setup, NAN_NDP_STATE_DONE);

	return 0;
}


static int nan_ndp_attr_handle_term(struct nan_data *nan, struct nan_peer *peer,
				    struct ieee80211_ndp *ndp_attr, u8 status)
{
	struct nan_ndp_setup *ndp_setup = &peer->ndp_setup;

	/*
	 * This should not really happen, but just in case,
	 * terminate the establishment.
	 */
	if (ndp_setup->ndp) {
		if (ndp_setup->ndp->ndp_id == ndp_attr->ndp_id &&
		    ether_addr_equal(ndp_setup->ndp->init_ndi,
				     ndp_attr->initiator_ndi)) {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDP: term: WIP with peer. Terminate");

			nan_ndp_set_state(nan, &peer->ndp_setup,
					  NAN_NDP_STATE_DONE);
			ndp_setup->status = NAN_NDP_STATUS_REJECTED;
			ndp_setup->reason = NAN_REASON_UNSPECIFIED_REASON;
		} else {
			wpa_printf(MSG_DEBUG,
				   "NAN: NDP: term: different NDP WIP with peer. Ignore");
		}
		return 0;
	}

	/* TODO: handle already established NDPs */
	wpa_printf(MSG_DEBUG, "NAN: NDP: Terminate established NDP");
	return 0;
}


/**
 * nan_ndp_handle_ndp_attr - Handle NDP attribute and update local state
 * @nan: NAN module context from nan_init()
 * @peer: The peer from which the original message was received
 * @msg: Parsed NAN Action frame
 * Returns: 0 on success, negative on failure
 */
int nan_ndp_handle_ndp_attr(struct nan_data *nan, struct nan_peer *peer,
			    struct nan_msg *msg)
{
	struct ieee80211_ndp *ndp_attr;
	u8 type, status;

	if (!msg || !peer || !msg->attrs.ndp)
		return -1;

	ndp_attr = (struct ieee80211_ndp *) msg->attrs.ndp;
	type = BITS(ndp_attr->type_and_status, NAN_NDP_TYPE_MASK,
		    NAN_NDP_TYPE_POS);
	status = BITS(ndp_attr->type_and_status, NAN_NDP_STATUS_MASK,
		      NAN_NDP_STATUS_POS);

	if (peer->ndp_setup.ndp) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NDP: attr: state=%s (%d), status=%d",
			   nan_ndp_state_str(peer->ndp_setup.state),
			   peer->ndp_setup.state,
			   peer->ndp_setup.status);
	} else {
		wpa_printf(MSG_DEBUG, "NAN: NDP: attr: no active NDP setup");
	}

	wpa_printf(MSG_DEBUG, "NAN: NDP: attr: type=0x%x, status=0x%x",
		   type, status);

	switch (type) {
	case NAN_NDP_TYPE_REQUEST:
		return nan_ndp_attr_handle_req(nan, peer, ndp_attr,
					       msg->attrs.ndp_len, status);
	case NAN_NDP_TYPE_RESPONSE:
		return nan_ndp_attr_handle_res(nan, peer, ndp_attr,
					       msg->attrs.ndp_len,
					       status);
	case NAN_NDP_TYPE_CONFIRM:
		return nan_ndp_attr_handle_confirm(nan, peer, ndp_attr, status);
	case NAN_NDP_TYPE_SECURITY_INSTALL:
		/* TODO: Handle security */
		return -1;
	case NAN_NDP_TYPE_TERMINATE:
		return nan_ndp_attr_handle_term(nan, peer, ndp_attr, status);
	default:
		return -1;
	}
}


/**
 * nan_ndp_add_ndp_attr - Add NDP attribute to frame
 * @nan: NAN module context from nan_init()
 * @peer: The peer to which the NAF should be sent
 * @buf: wpabuf to which the attribute would be added
 * Returns: 0 on success, negative on failure
 */
int nan_ndp_add_ndp_attr(struct nan_data *nan, struct nan_peer *peer,
			 struct wpabuf *buf)
{
	struct nan_ndp_setup *ndp_setup;
	u8 type, ndp_ctrl = 0;
	u8 *len_ptr;

	if (!peer || !peer->ndp_setup.ndp)
		return -1;

	ndp_setup = &peer->ndp_setup;

	switch (ndp_setup->state) {
	case NAN_NDP_STATE_START:
		type = NAN_NDP_TYPE_REQUEST;
		ndp_ctrl = NAN_NDP_CTRL_PUBLISH_ID_PRESENT;
		if (ndp_setup->conf_req)
			ndp_ctrl |= NAN_NDP_CTRL_CONFIRM_REQUIRED;
		if (ndp_setup->ssi && ndp_setup->ssi_len)
			ndp_ctrl |= NAN_NDP_CTRL_SPEC_INFO_PRESENT;
		break;
	case NAN_NDP_STATE_REQ_RECV:
		type = NAN_NDP_TYPE_RESPONSE;
		if (ndp_setup->status != NAN_NDP_STATUS_REJECTED)
			ndp_ctrl |= NAN_NDP_CTRL_RESPONDER_NDI_PRESENT;
		if (ndp_setup->ssi && ndp_setup->ssi_len)
			ndp_ctrl |= NAN_NDP_CTRL_SPEC_INFO_PRESENT;
		break;
	case NAN_NDP_STATE_RES_RECV:
		type = NAN_NDP_TYPE_CONFIRM;
		break;
	case NAN_NDP_STATE_CON_RECV:
		/* TODO: Integrate NDP security flows */
		type = NAN_NDP_TYPE_SECURITY_INSTALL;
		break;
	case NAN_NDP_STATE_NONE:
	case NAN_NDP_STATE_REQ_SENT:
	case NAN_NDP_STATE_RES_SENT:
	case NAN_NDP_STATE_CON_SENT:
	case NAN_NDP_STATE_DONE:
	default:
		return 0;
	}

	wpabuf_put_u8(buf, NAN_ATTR_NDP);
	len_ptr = wpabuf_put(buf, 2);

	wpabuf_put_u8(buf, ndp_setup->dialog_token);
	wpabuf_put_u8(buf, type |
		      (ndp_setup->status << NAN_NDP_STATUS_POS));
	wpabuf_put_u8(buf, ndp_setup->reason);
	wpabuf_put_data(buf, ndp_setup->ndp->init_ndi, ETH_ALEN);
	wpabuf_put_u8(buf, ndp_setup->ndp->ndp_id);
	wpabuf_put_u8(buf, ndp_ctrl);

	if (ndp_ctrl & NAN_NDP_CTRL_PUBLISH_ID_PRESENT)
		wpabuf_put_u8(buf, ndp_setup->publish_inst_id);

	if (ndp_ctrl & NAN_NDP_CTRL_RESPONDER_NDI_PRESENT)
		wpabuf_put_data(buf, ndp_setup->ndp->resp_ndi, ETH_ALEN);

	if (ndp_ctrl & NAN_NDP_CTRL_SPEC_INFO_PRESENT)
		wpabuf_put_data(buf, ndp_setup->ssi, ndp_setup->ssi_len);

	WPA_PUT_LE16(len_ptr, (u8 *) wpabuf_put(buf, 0) - len_ptr - 2);
	return 0;
}


/**
 * nan_ndp_setup_reset - Reset the ndp_setup state
 * @nan: NAN module context from nan_init()
 * @peer: The peer that requires ndp setup reset
 */
void nan_ndp_setup_reset(struct nan_data *nan, struct nan_peer *peer)
{
	if (!peer)
		return;

	os_free(peer->ndp_setup.ssi);
	os_free(peer->ndp_setup.ndp);

	os_memset(&peer->ndp_setup, 0, sizeof(peer->ndp_setup));
	nan_ndp_set_state(nan, &peer->ndp_setup, NAN_NDP_STATE_NONE);
}


/**
 * nan_ndp_setup_failure - Indicate failure during NDP setup
 * @nan: NAN module context from nan_init()
 * @peer: The peer from which the original message was received
 * @reason: The failure reason
 * @reset_state: Reset the NDP state iff equals to true.
 */
void nan_ndp_setup_failure(struct nan_data *nan, struct nan_peer *peer,
			   enum nan_reason reason, bool reset_state)
{
	struct nan_ndp_setup *ndp_setup = &peer->ndp_setup;

	wpa_printf(MSG_DEBUG, "NAN: NDP: setup failure: peer " MACSTR
		   ". state=%s (%u). reason=%u",
		   MAC2STR(peer->nmi_addr), nan_ndp_state_str(ndp_setup->state),
		   ndp_setup->state, reason);

	if (reset_state) {
		nan_ndp_setup_reset(nan, peer);
	} else {
		ndp_setup->status = NAN_NDP_STATUS_REJECTED;
		ndp_setup->reason = reason;
	}
}


/**
 * nan_ndp_naf_sent - Indicate a NAF has been sent
 * @nan: NAN module context from nan_init()
 * @peer: The peer with whom the NDP is being setup
 * @subtype: The NAN OUI subtype. See &enum nan_subtype
 *
 * Notification, indicating to the NDP SM to that a NAF was sent, so the
 * NDP SM could update its state.
 */
int nan_ndp_naf_sent(struct nan_data *nan, struct nan_peer *peer,
		     enum nan_subtype subtype)
{
	struct nan_ndp_setup *ndp_setup;

	if (!peer || !peer->ndp_setup.ndp)
		return -1;

	ndp_setup = &peer->ndp_setup;

	wpa_printf(MSG_DEBUG, "NAN: NDP: Tx done: state=%s (%d), status=%d",
		   nan_ndp_state_str(ndp_setup->state),
		   ndp_setup->state, ndp_setup->status);

	/*
	 * Note: Due to races between the Tx status and Rx path, it is possible
	 * that the Tx status is received after the peer response was already
	 * processed (which can result with another frame being sent). In such a
	 * case the logic above fast-forwards the state, and the transitions
	 * here need to take this into consideration.
	 */
	switch (ndp_setup->state) {
	case NAN_NDP_STATE_START:
		if (subtype == NAN_SUBTYPE_DATA_PATH_REQUEST)
			nan_ndp_set_state(nan, &peer->ndp_setup,
					  NAN_NDP_STATE_REQ_SENT);
		break;
	case NAN_NDP_STATE_REQ_RECV:
		if (subtype == NAN_SUBTYPE_DATA_PATH_RESPONSE) {
			if (ndp_setup->status == NAN_NDP_STATUS_ACCEPTED)
				nan_ndp_set_state(nan, &peer->ndp_setup,
						  NAN_NDP_STATE_DONE);
			else
				nan_ndp_set_state(nan, &peer->ndp_setup,
						  NAN_NDP_STATE_RES_SENT);
		}
		break;
	case NAN_NDP_STATE_RES_RECV:
		if (subtype == NAN_SUBTYPE_DATA_PATH_CONFIRM) {
			if (ndp_setup->status == NAN_NDP_STATUS_ACCEPTED)
				nan_ndp_set_state(nan, &peer->ndp_setup,
						  NAN_NDP_STATE_DONE);
			else
				nan_ndp_set_state(nan, &peer->ndp_setup,
						  NAN_NDP_STATE_CON_SENT);
		}
		break;
	case NAN_NDP_STATE_CON_RECV:
		if (subtype == NAN_SUBTYPE_DATA_PATH_KEY_INSTALL &&
		    ndp_setup->status == NAN_NDP_STATUS_ACCEPTED)
			nan_ndp_set_state(nan, &peer->ndp_setup,
					  NAN_NDP_STATE_DONE);
		break;
	case NAN_NDP_STATE_REQ_SENT:
	case NAN_NDP_STATE_RES_SENT:
	case NAN_NDP_STATE_CON_SENT:
	case NAN_NDP_STATE_DONE:
	default:
		break;
	}

	return 0;
}
