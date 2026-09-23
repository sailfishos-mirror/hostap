/*
 * wpa_supplicant - NAN IDP PASN authentication
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "pasn/pasn_common.h"
#include "wpas_idp_pasn.h"


#ifdef CONFIG_PASN

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
