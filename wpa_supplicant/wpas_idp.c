/*
 * wpa_supplicant - NAN IEEE Data Path (IDP)
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "wpa_supplicant_i.h"
#include "wpas_idp.h"


/**
 * wpas_idp_get_peer_idp_addr - Get the peer's IDP interface address
 * @session: IDP session
 * Returns: Peer IDP interface address, or NULL if unavailable
 *
 * For a STA, the address is the peer AP's BSSID. For an AP, it is the
 * address of the connected peer STA.
 */
static const u8 *
wpas_idp_get_peer_idp_addr(const struct wpas_idp_session *session)
{
	if (!session)
		return NULL;

	if (session->role == WPAS_IDP_ROLE_STA &&
	    !is_zero_ether_addr(session->bssid))
		return session->bssid;

	if (session->role == WPAS_IDP_ROLE_AP &&
	    !is_zero_ether_addr(session->connected_sta_mac_addr))
		return session->connected_sta_mac_addr;

	return NULL;
}


/**
 * wpas_idp_get_session_by_peer - Find an IDP session by peer address
 * @wpa_s: wpa_supplicant context
 * @peer_addr: Peer NMI or IDP interface address
 * Returns: Matching session, or NULL if not found
 *
 * The lookup first matches the peer NMI, then the peer IDP interface address.
 */
struct wpas_idp_session *
wpas_idp_get_session_by_peer(struct wpa_supplicant *wpa_s, const u8 *peer_addr)
{
	struct wpas_idp_info *idp;
	struct wpas_idp_session *session;

	if (!wpa_s || !wpa_s->global || !wpa_s->global->idp || !peer_addr)
		return NULL;

	idp = wpa_s->global->idp;

	dl_list_for_each(session, &idp->sessions,
			 struct wpas_idp_session, list) {
		if (ether_addr_equal(session->peer_addr, peer_addr))
			return session;
	}

	dl_list_for_each(session, &idp->sessions,
			 struct wpas_idp_session, list) {
		const u8 *idp_addr = wpas_idp_get_peer_idp_addr(session);

		if (idp_addr && ether_addr_equal(idp_addr, peer_addr)) {
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u matched by IDP interface MAC address "
				   MACSTR, session->id, MAC2STR(peer_addr));
			return session;
		}
	}

	return NULL;
}


/**
 * wpas_idp_alloc_session - Allocate a new IDP session
 * @wpa_s: wpa_supplicant context
 * @peer_addr: Peer NMI address
 * @role: IDP role (AP or STA)
 * Returns: Pointer to allocated session or NULL on failure
 *
 * Allocates a session, assigns it the next session ID and appends it to the
 * global session list. Only one session per peer is allowed, so allocation
 * fails if a session for this peer already exists.
 */
struct wpas_idp_session *
wpas_idp_alloc_session(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
		       enum wpas_idp_role role)
{
	struct wpas_idp_info *idp;
	struct wpas_idp_session *session;

	if (!wpa_s || !wpa_s->global || !wpa_s->global->idp || !peer_addr) {
		wpa_printf(MSG_ERROR,
			   "IDP: Invalid parameters for session allocation");
		return NULL;
	}

	idp = wpa_s->global->idp;

	session = wpas_idp_get_session_by_peer(wpa_s, peer_addr);
	if (session) {
		wpa_printf(MSG_WARNING,
			   "IDP: Session %u already exists with peer " MACSTR,
			   session->id, MAC2STR(peer_addr));
		return NULL;
	}

	session = os_zalloc(sizeof(*session));
	if (!session) {
		wpa_printf(MSG_ERROR, "IDP: Failed to allocate session");
		return NULL;
	}

	session->id = idp->next_id++;
	session->wpa_s = wpa_s;
	os_memcpy(session->peer_addr, peer_addr, ETH_ALEN);
	session->role = role;
	session->state = IDP_STATE_NONE;

	/* -1 marks "unset" so cleanup can tell these apart from index 0 */
	session->handle = -1;
	session->network_id = -1;

	/* An AP announces its SSID unless the operator asks it not to */
	session->discoverable = true;

	dl_list_add(&idp->sessions, &session->list);

	wpa_printf(MSG_DEBUG, "IDP: Allocated session %u with peer " MACSTR
		   " role=%s", session->id, MAC2STR(peer_addr),
		   role == WPAS_IDP_ROLE_AP ? "AP" : "STA");

	return session;
}


/**
 * wpas_idp_free_session - Free an IDP session
 * @session: Session to free
 *
 * Unlinks the session from the global list, wipes the key material it holds
 * and frees it.
 */
static void wpas_idp_free_session(struct wpas_idp_session *session)
{
	if (!session)
		return;

	wpa_printf(MSG_DEBUG, "IDP: Freeing session %u peer " MACSTR,
		   session->id, MAC2STR(session->peer_addr));

	dl_list_del(&session->list);

	os_free(session);
}


/**
 * wpas_idp_init - Initialize IDP module
 * @global: Pointer to global wpa_supplicant context
 * Returns: 0 on success, -1 on failure
 */
int wpas_idp_init(struct wpa_global *global)
{
	struct wpas_idp_info *idp;

	if (!global) {
		wpa_printf(MSG_ERROR, "IDP: Invalid global context");
		return -1;
	}

	if (global->idp) {
		wpa_printf(MSG_DEBUG, "IDP: Already initialized");
		return 0;
	}

	idp = os_zalloc(sizeof(*idp));
	if (!idp) {
		wpa_printf(MSG_ERROR, "IDP: Failed to allocate context");
		return -1;
	}

	idp->global = global;
	dl_list_init(&idp->sessions);

	global->idp = idp;

	wpa_printf(MSG_DEBUG, "IDP: Module initialized");
	return 0;
}


/**
 * wpas_idp_deinit - Deinitialize IDP module
 * @global: Pointer to global wpa_supplicant context
 *
 * Frees all remaining sessions and the global IDP context.
 */
void wpas_idp_deinit(struct wpa_global *global)
{
	struct wpas_idp_info *idp;
	struct wpas_idp_session *session, *tmp;

	if (!global || !global->idp)
		return;

	idp = global->idp;

	dl_list_for_each_safe(session, tmp, &idp->sessions,
			      struct wpas_idp_session, list)
		wpas_idp_free_session(session);

	os_free(idp);
	global->idp = NULL;

	wpa_printf(MSG_DEBUG, "IDP: Module deinitialized");
}
