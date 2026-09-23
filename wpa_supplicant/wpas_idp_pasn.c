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

#endif /* CONFIG_PASN */
