/*
 * wpa_supplicant - NAN IDP PASN authentication
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "common/ieee802_11_common.h"
#include "common/nan_defs.h"
#include "pasn/pasn_common.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "nan_supplicant.h"
#include "wpas_idp.h"
#include "wpas_idp_pasn.h"


#ifdef CONFIG_PASN

/**
 * idp_pasn_get_nan_attrs - Get NAN attributes from frame elements
 * @ies: Frame elements
 * @ies_len: Length of @ies
 * Returns: NAN attributes in a newly allocated buffer, or NULL if unavailable
 *
 * The NAN element may be continued in Fragment elements.
 */
static struct wpabuf * idp_pasn_get_nan_attrs(const u8 *ies, size_t ies_len)
{
	struct ieee802_11_elems elems;
	struct wpabuf *elem, *attrs;

	if (!ies ||
	    ieee802_11_parse_elems(ies, ies_len, &elems, 0) == ParseFailed ||
	    !elems.nan_ie || elems.nan_len < 4)
		return NULL;

	elem = ieee802_11_defrag(elems.nan_ie, elems.nan_len, false);
	if (!elem)
		return NULL;

	attrs = wpabuf_alloc_copy(wpabuf_head_u8(elem) + 4,
				  wpabuf_len(elem) - 4);
	wpabuf_free(elem);

	return attrs;
}


/**
 * idp_pasn_has_idp_attr - Check whether NAN attributes contain an IDP attr
 * @attrs: NAN attributes
 * Returns: Whether any IDP attribute is present
 */
static bool idp_pasn_has_idp_attr(const struct wpabuf *attrs)
{
	const u8 *pos, *end;

	if (!attrs)
		return false;

	pos = wpabuf_head_u8(attrs);
	end = pos + wpabuf_len(attrs);
	while (end - pos >= NAN_ATTR_HDR_LEN) {
		u8 id = pos[0];
		u16 len = WPA_GET_LE16(&pos[1]);

		pos += NAN_ATTR_HDR_LEN;
		if (len > end - pos)
			break;

		switch (id) {
		case NAN_ATTR_IDP_ID:
		case NAN_ATTR_IDP_CHANNEL_LIST:
		case NAN_ATTR_IDP_OPERATING_CHANNEL:
		case NAN_ATTR_IDP_TERMINATION:
		case NAN_ATTR_IDP_INFORMATION:
			return true;
		}

		pos += len;
	}

	return false;
}


/**
 * wpas_idp_pasn_is_idp_auth_frame - Check whether an Authentication frame body
 * is for IDP
 * @frame_body: Authentication frame body, starting at the fixed fields
 * @frame_body_len: Length of @frame_body
 * Returns: Whether the frame carries IDP attributes in a NAN element
 */
bool wpas_idp_pasn_is_idp_auth_frame(const u8 *frame_body,
				     size_t frame_body_len)
{
	struct wpabuf *attrs;
	bool ret;

	attrs = idp_pasn_get_nan_attrs(frame_body, frame_body_len);
	ret = idp_pasn_has_idp_attr(attrs);
	wpabuf_free(attrs);

	return ret;
}


/**
 * wpas_idp_pasn_has_session_for_peer - Check for an IDP session with a peer
 * @wpa_s: wpa_supplicant structure
 * @peer_addr: Peer NAN management interface address
 * Returns: Whether a session exists
 *
 * PASN M3 carries no NAN element, so it cannot be recognised by its contents
 * the way M1 and M2 are. Routing it relies on already having a session with
 * the sender.
 */
bool wpas_idp_pasn_has_session_for_peer(struct wpa_supplicant *wpa_s,
					const u8 *peer_addr)
{
	return wpas_idp_get_session_by_peer(wpa_s, peer_addr);
}


/**
 * wpas_idp_pasn_init - Allocate an IDP PASN handshake context
 * @wpa_s: wpa_supplicant structure
 * @session: IDP session the handshake belongs to
 * @peer_addr: Peer NAN management interface address
 * @is_initiator: Whether this device starts the handshake
 * Returns: New context, or NULL on failure
 *
 * Allocate the IDP-specific context for a PASN handshake. The PASN
 * core state is initialized separately once the keys and other PASN
 * parameters are available.
 */
struct idp_pasn_context * wpas_idp_pasn_init(struct wpa_supplicant *wpa_s,
					     struct wpas_idp_session *session,
					     const u8 *peer_addr,
					     bool is_initiator)
{
	struct idp_pasn_context *ctx;

	if (!wpa_s || !session || !peer_addr)
		return NULL;

	ctx = os_zalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->wpa_s = wpa_s;
	ctx->session = session;
	os_memcpy(ctx->peer_addr, peer_addr, ETH_ALEN);
	ctx->is_initiator = is_initiator;
	ctx->state = IDP_PASN_IDLE;

	wpa_printf(MSG_DEBUG, "IDP-PASN: Context for peer " MACSTR " as %s",
		   MAC2STR(peer_addr),
		   is_initiator ? "initiator" : "responder");

	return ctx;
}


/**
 * wpas_idp_pasn_deinit - Release an IDP PASN handshake context
 * @ctx: Context to release, may be NULL
 *
 * wpa_pasn_reset() has to run before pasn_data_deinit(), because the ECDH
 * state and the extra IEs are not released by pasn_data_deinit() itself.
 */
void wpas_idp_pasn_deinit(struct idp_pasn_context *ctx)
{
	if (!ctx)
		return;

	wpa_printf(MSG_DEBUG, "IDP-PASN: Releasing context for peer " MACSTR,
		   MAC2STR(ctx->peer_addr));

	if (ctx->pasn) {
		wpa_pasn_reset(ctx->pasn);
		pasn_data_deinit(ctx->pasn);
		ctx->pasn = NULL;
	}

	wpabuf_free(ctx->idp_req_attrs);
	wpabuf_free(ctx->idp_resp_attrs);

	os_free(ctx);
}


static int wpas_idp_pasn_send_mgmt_cb(void *ctx, const u8 *data,
				      size_t data_len, int noack,
				      unsigned int freq, unsigned int wait)
{
	struct idp_pasn_context *pctx = ctx;

	return wpa_drv_send_mlme(pctx->wpa_s, data, data_len, noack, freq,
				 wait);
}


static int wpas_idp_pasn_validate_custom_pmkid_cb(void *ctx, const u8 *addr,
						  const u8 *pmkid)
{
	/*
	 * Peer authentication is based on the NIRA nonce/tag lookup and the
	 * associated pairing key. The PASN PMKID is used only to correlate
	 * the PASN exchange, so no additional validation is needed here.
	 */
	return 0;
}


/**
 * wpas_idp_pasn_initialize - Build the PASN state for an IDP handshake
 * @ctx: IDP PASN context
 * Returns: 0 on success, -1 on failure
 *
 * Set up PASN in NAN_PASN_AUTH_MODE_PMK: the NAN pairing key cached for the
 * peer becomes the PMK, so no password is involved and the peer is
 * authenticated by having completed pairing earlier.
 */
static int wpas_idp_pasn_initialize(struct idp_pasn_context *ctx)
{
	struct wpa_supplicant *wpa_s = ctx->wpa_s;
	struct pasn_data *pasn;
	const struct wpa_dev_ik *ik = NULL;
	const u8 *nonce = NULL, *tag = NULL, *pmkid = NULL;
	int cipher;

	if (!wpa_s->nan) {
		wpa_printf(MSG_DEBUG, "IDP-PASN: NAN is not running");
		return -1;
	}

	if (ctx->pasn) {
		wpa_pasn_reset(ctx->pasn);
	} else {
		ctx->pasn = pasn_data_init();
		if (!ctx->pasn)
			return -1;
	}

	pasn = ctx->pasn;

	pasn_set_own_addr(pasn, wpa_s->own_addr);
	pasn_set_peer_addr(pasn, ctx->peer_addr);

	/*
	 * Use the cipher associated with the identity key resolved from the
	 * NIRA nonce/tag of the peer. If no NIRA information is available,
	 * fall back to the default 128-bit cipher suite.
	 */
	if (nan_peer_get_pairing_cfg(wpa_s->nan, ctx->peer_addr, &nonce,
				     &tag) && nonce && tag)
		ik = wpas_nan_find_ik_by_nonce_tag(wpa_s, ctx->peer_addr,
						   nonce, tag);
	if (ik && ik->dik_cipher != NAN_NIRA_CIPHER_VER_128)
		cipher = WPA_CIPHER_GCMP_256;
	else
		cipher = WPA_CIPHER_CCMP;

	/*
	 * PASN requires the responder to echo the PMKID received in M1. When
	 * initiating a PASN exchange, a fresh PMKID is generated for that
	 * exchange. This PMKID is used only during PASN authentication and is
	 * unrelated to the ND-PMKID derived later during IDP verification.
	 */
	if (!ctx->is_initiator && ctx->m1_pmkid_valid)
		pmkid = ctx->m1_pmkid;

	if (nan_pairing_idp_pasn_init(wpa_s->nan, pasn, ctx->peer_addr,
				      ctx->is_initiator, cipher, pmkid) < 0) {
		wpa_printf(MSG_INFO,
			   "IDP-PASN: Failed to set up PASN for peer " MACSTR,
			   MAC2STR(ctx->peer_addr));
		goto fail;
	}

	pasn_register_callbacks(pasn, ctx, wpas_idp_pasn_send_mgmt_cb,
				wpas_idp_pasn_validate_custom_pmkid_cb,
				NULL, NULL);

	wpa_printf(MSG_DEBUG, "IDP-PASN: Ready for peer " MACSTR
		   " akmp=%d cipher=%d group=%d as %s",
		   MAC2STR(ctx->peer_addr), pasn->akmp, pasn->cipher,
		   pasn->group,
		   ctx->is_initiator ? "initiator" : "responder");

	return 0;

fail:
	wpa_pasn_reset(pasn);
	pasn_data_deinit(pasn);
	ctx->pasn = NULL;

	return -1;
}


/**
 * wpas_idp_pasn_build_nan_elem - Build the NAN element for an IDP
 * Authentication frame
 * @wpa_s: wpa_supplicant structure
 * @ctx: IDP PASN context, already initialized
 * @handle: NAN service handle the session was discovered through, or 0
 * @is_responder_frame: Whether this element goes into a responder frame
 * @idp_attrs: IDP attributes to include in the NAN element
 * Returns: Newly allocated element, or NULL on failure
 *
 * Carries the cipher suite list, the NIRA identifying the pairing key,
 * and the service identifier, as in NAN pairing verification frames,
 * followed by the IDP attributes in the same NAN element.
 *
 * A responder advertises the cipher suites offered by its publish
 * service, while an initiator advertises only the cipher suite selected
 * for the handshake.
 */
static struct wpabuf *
wpas_idp_pasn_build_nan_elem(struct wpa_supplicant *wpa_s,
			     struct idp_pasn_context *ctx, int handle,
			     bool is_responder_frame,
			     const struct wpabuf *idp_attrs)
{
	struct nan_cipher_suite cs_list[NAN_CS_MAX];
	size_t cs_count = 0;
	struct wpabuf *buf, *elem;
	const u8 *npkid;

	if (!ctx->pasn || !idp_attrs)
		return NULL;

	npkid = ctx->pasn->custom_pmkid;

	buf = wpabuf_alloc(NAN_ATTR_HDR_LEN + 1 +
			   NAN_CS_MAX * sizeof(struct nan_cipher_suite) +
			   NAN_ATTR_HDR_LEN + 1 + NAN_NIRA_NONCE_LEN +
			   NAN_NIRA_TAG_LEN +
			   NAN_ATTR_HDR_LEN + NAN_SERVICE_ID_LEN +
			   wpabuf_len(idp_attrs));
	if (!buf)
		return NULL;

	if (is_responder_frame && handle > 0 && wpa_s->nan_de) {
		const int *cs_ids = nan_de_get_cipher_suites_list(wpa_s->nan_de,
								  handle);
		unsigned int i;

		for (i = 0; cs_ids && cs_ids[i] && cs_count < NAN_CS_MAX; i++) {
			if (cs_ids[i] <= NAN_CS_NONE || cs_ids[i] >= NAN_CS_MAX)
				continue;
			cs_list[cs_count].csid = cs_ids[i];
			cs_list[cs_count].instance_id = handle;
			cs_count++;
		}
	}

	if (!cs_count) {
		cs_list[0].csid = ctx->pasn->cipher == WPA_CIPHER_GCMP_256 ?
			NAN_CS_PK_PASN_256 : NAN_CS_PK_PASN_128;
		cs_list[0].instance_id = handle;
		cs_count = 1;
	}

	/*
	 * The peer cannot tell which pairing key to verify with, nor which
	 * cipher to use, if either of these is missing.
	 */
	if (nan_add_csia(buf, 0, cs_count, cs_list) < 0 ||
	    nan_add_nira(buf, &npkid[NAN_NIRA_NONCE_LEN], npkid) < 0) {
		wpabuf_free(buf);
		return NULL;
	}

	if (handle > 0 && wpa_s->nan_de) {
		const u8 *svc_id = nan_de_get_service_id(wpa_s->nan_de, handle);

		if (svc_id) {
			wpabuf_put_u8(buf, NAN_ATTR_NAN_ATTR_SERVICE_ID_LIST);
			wpabuf_put_le16(buf, NAN_SERVICE_ID_LEN);
			wpabuf_put_data(buf, svc_id, NAN_SERVICE_ID_LEN);
		}
	}

	wpabuf_put_buf(buf, idp_attrs);
	elem = wpas_idp_build_nan_elem(buf);
	wpabuf_free(buf);

	return elem;
}


/**
 * wpas_idp_pasn_auth_start - Start IDP pairing verification as the initiator
 * @wpa_s: wpa_supplicant structure
 * @peer_addr: Peer NAN management interface address
 * @freq: Frequency to send PASN M1 on
 * Returns: 0 if PASN M1 was sent, -1 on failure
 *
 * The IDP interface is created before PASN M1 is sent, because when this device
 * takes the AP role the BSSID advertised in PASN M1 is that interface's
 * address.
 */
int wpas_idp_pasn_auth_start(struct wpa_supplicant *wpa_s,
			     const u8 *peer_addr, int freq)
{
	struct wpas_idp_session *session;
	struct idp_pasn_context *ctx;
	struct wpabuf *idp_attrs, *extra_ies = NULL;
	struct hostapd_sta_add_params sta_params;
	bool separate_iface;

	if (!wpa_s || !peer_addr)
		return -1;

	session = wpas_idp_get_session_by_peer(wpa_s, peer_addr);
	if (!session) {
		wpa_printf(MSG_ERROR, "IDP-PASN: No session for peer " MACSTR,
			   MAC2STR(peer_addr));
		return -1;
	}

	/* A retry must not leave the context of the previous attempt behind */
	wpas_idp_pasn_deinit(session->pasn_ctx);
	session->pasn_ctx = NULL;

	ctx = wpas_idp_pasn_init(wpa_s, session, peer_addr, true);
	if (!ctx)
		return -1;
	session->pasn_ctx = ctx;

	if (wpas_idp_pasn_initialize(ctx) < 0) {
		wpa_printf(MSG_ERROR, "IDP-PASN: Failed to set up PASN");
		goto fail;
	}

	separate_iface = wpas_idp_need_separate_iface(wpa_s);
	if (separate_iface && !session->group_wpa_s) {
		enum wpa_driver_if_type iface_type =
			session->role == WPAS_IDP_ROLE_AP ?
			WPA_IF_AP_BSS : WPA_IF_STATION;

		if (wpas_idp_add_interface(wpa_s, session, iface_type) < 0) {
			wpa_printf(MSG_ERROR,
				   "IDP-PASN: Failed to create interface");
			goto fail;
		}
		if (!wpas_idp_init_interface(wpa_s, session)) {
			wpa_printf(MSG_ERROR,
				   "IDP-PASN: Failed to initialize interface");
			wpas_idp_remove_interface(wpa_s, session);
			goto fail;
		}
		if (session->role == WPAS_IDP_ROLE_AP)
			os_memcpy(session->bssid, session->iface_addr,
				  ETH_ALEN);
	} else if (!separate_iface) {
		session->group_wpa_s = wpa_s;
		if (session->role == WPAS_IDP_ROLE_AP)
			os_memcpy(session->bssid, wpa_s->own_addr, ETH_ALEN);
	}

	/* Pairing and IDP attributes are carried in the same NAN element */
	idp_attrs = wpas_idp_build_req_attrs(session);
	if (!idp_attrs) {
		wpa_printf(MSG_ERROR,
			   "IDP-PASN: Failed to build PASN M1 attributes");
		goto fail;
	}

	extra_ies = wpas_idp_pasn_build_nan_elem(wpa_s, ctx, session->handle,
						  false, idp_attrs);
	wpabuf_free(idp_attrs);
	if (!extra_ies) {
		wpa_printf(MSG_ERROR,
			   "IDP-PASN: Failed to build PASN M1 element");
		goto fail;
	}

	pasn_set_extra_ies(ctx->pasn, wpabuf_head_u8(extra_ies),
			   wpabuf_len(extra_ies));
	wpabuf_free(extra_ies);

	os_memset(&sta_params, 0, sizeof(sta_params));
	sta_params.addr = peer_addr;
	sta_params.flags = WPA_STA_MFP;
	sta_params.set = 1;
	if (wpa_drv_sta_add(wpa_s, &sta_params) < 0)
		wpa_printf(MSG_DEBUG, "IDP-PASN: sta_add() failed, continuing");

	if (wpa_pasn_verify(ctx->pasn, ctx->pasn->own_addr,
			    ctx->pasn->peer_addr, ctx->pasn->bssid,
			    ctx->pasn->akmp, ctx->pasn->cipher,
			    ctx->pasn->group, freq, NULL, 0, NULL, 0,
			    NULL) < 0) {
		wpa_printf(MSG_ERROR, "IDP-PASN: Failed to send PASN M1");
		goto fail;
	}

	ctx->state = IDP_PASN_M1_SENT;
	wpa_printf(MSG_DEBUG, "IDP-PASN: M1 sent to " MACSTR " on %d MHz",
		   MAC2STR(peer_addr), freq);

	return 0;

fail:
	wpas_idp_pasn_deinit(ctx);
	session->pasn_ctx = NULL;

	return -1;
}


/**
 * wpas_idp_pasn_send_reject - Refuse an incoming IDP PASN handshake
 * @wpa_s: wpa_supplicant structure
 * @peer_addr: Peer NAN management interface address
 * @m1_frame: The PASN M1 that is being refused
 * Returns: 0 if the refusal was sent, -1 on failure
 *
 * Replies to the PASN M1 with a failure status so the initiator learns
 * immediately that the request was rejected. No session is created; a temporary
 * one is used only to carry the peer address into the handshake context.
 */
int wpas_idp_pasn_send_reject(struct wpa_supplicant *wpa_s,
			      const u8 *peer_addr, struct wpabuf *m1_frame)
{
	struct idp_pasn_context *ctx;
	struct wpas_idp_session tmp_session;

	if (!wpa_s || !peer_addr || !m1_frame)
		return -1;

	os_memset(&tmp_session, 0, sizeof(tmp_session));
	tmp_session.wpa_s = wpa_s;
	os_memcpy(tmp_session.peer_addr, peer_addr, ETH_ALEN);

	ctx = wpas_idp_pasn_init(wpa_s, &tmp_session, peer_addr, false);
	if (!ctx)
		return -1;

	if (wpas_idp_pasn_initialize(ctx) < 0) {
		wpas_idp_pasn_deinit(ctx);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "IDP-PASN: Rejecting request from " MACSTR,
		   MAC2STR(peer_addr));

	handle_auth_pasn_1(ctx->pasn, wpa_s->own_addr, peer_addr,
			   (const struct ieee80211_mgmt *)
			   wpabuf_head(m1_frame),
			   wpabuf_len(m1_frame), true /* reject */);

	wpas_idp_pasn_deinit(ctx);

	return 0;
}


/**
 * wpas_idp_pasn_auth_rx - Handle a received IDP PASN Authentication frame
 * @wpa_s: wpa_supplicant structure
 * @mgmt: Received Authentication frame
 * @len: Length of @mgmt
 * @freq: Frequency the frame arrived on
 * Returns: 0 if the frame was handled, -1 otherwise
 */
int wpas_idp_pasn_auth_rx(struct wpa_supplicant *wpa_s,
			  const struct ieee80211_mgmt *mgmt, size_t len,
			  int freq)
{
	u16 auth_transaction, status_code;

	if (!wpa_s || !mgmt ||
	    len < offsetof(struct ieee80211_mgmt, u.auth.variable))
		return -1;

	if (le_to_host16(mgmt->u.auth.auth_alg) != WLAN_AUTH_PASN)
		return -1;

	auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
	status_code = le_to_host16(mgmt->u.auth.status_code);

	wpa_printf(MSG_DEBUG, "IDP-PASN: RX PASN M%u from " MACSTR " status=%u",
		   auth_transaction, MAC2STR(mgmt->sa), status_code);

	switch (auth_transaction) {
	default:
		wpa_printf(MSG_DEBUG,
			   "IDP-PASN: Unexpected transaction %u from " MACSTR,
			   auth_transaction, MAC2STR(mgmt->sa));
		return -1;
	}
}

#endif /* CONFIG_PASN */
