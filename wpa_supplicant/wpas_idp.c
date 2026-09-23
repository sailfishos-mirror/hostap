/*
 * wpa_supplicant - NAN IEEE Data Path (IDP)
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/wpabuf.h"
#include "common/ieee802_11_defs.h"
#include "common/nan_defs.h"
#include "config.h"
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


/*
 * idp_get_country_string - Fill the 3-byte country code for IDP attributes
 *
 * Uses the configured country code, or "XX" (noncountry entity) when none is
 * set. The third byte is 0x04 to indicate the global values (IEEE Std
 * 802.11-2024, Table E-4.
 */
static void idp_get_country_string(struct wpa_supplicant *wpa_s, u8 out[3])
{
	if (wpa_s && wpa_s->conf && wpa_s->conf->country[0] &&
	    wpa_s->conf->country[1]) {
		out[0] = wpa_s->conf->country[0];
		out[1] = wpa_s->conf->country[1];
	} else {
		out[0] = 'X';
		out[1] = 'X';
	}

	out[2] = 0x04;
}


/**
 * wpas_idp_build_nan_elem - Build a NAN element
 * @attrs: NAN attributes to include
 * Returns: NAN element, including any Fragment elements, or NULL on error
 *
 * Fragment elements extend the payload of the preceding Vendor Specific
 * element, as described in IEEE Std 802.11-2024, 10.28.11.
 */
struct wpabuf * wpas_idp_build_nan_elem(const struct wpabuf *attrs)
{
	struct wpabuf *buf;
	const u8 *pos;
	size_t left, len, num_frags;

	if (!attrs)
		return NULL;

	pos = wpabuf_head_u8(attrs);
	left = wpabuf_len(attrs);
	num_frags = left > 251 ? (left - 251 + 254) / 255 : 0;
	buf = wpabuf_alloc(2 + 4 + left + 2 * num_frags);
	if (!buf)
		return NULL;

	len = left > 251 ? 251 : left;
	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
	wpabuf_put_u8(buf, 4 + len);
	wpabuf_put_be32(buf, NAN_IE_VENDOR_TYPE);
	wpabuf_put_data(buf, pos, len);
	pos += len;
	left -= len;

	while (left) {
		len = left > 255 ? 255 : left;
		wpabuf_put_u8(buf, WLAN_EID_FRAGMENT);
		wpabuf_put_u8(buf, len);
		wpabuf_put_data(buf, pos, len);
		pos += len;
		left -= len;
	}

	return buf;
}


/* Build the IDP Channel List attribute */
static struct wpabuf *
idp_build_channel_list_attr(struct wpas_idp_session *session)
{
	struct wpabuf *buf;
	u8 *len_ptr;
	u8 oc, ch;

	buf = wpabuf_alloc(100);
	if (!buf)
		return NULL;

	wpabuf_put_u8(buf, NAN_ATTR_IDP_CHANNEL_LIST);
	len_ptr = wpabuf_put(buf, 2);

	idp_get_country_string(session->wpa_s, wpabuf_put(buf, 3));

	/*
	 * Fall back to 5 GHz channel 36 until channel selection completes and
	 * populates session->channel.
	 */
	if (!session->channel.operating_class) {
		oc = 115;
		ch = 36;
	} else {
		oc = session->channel.operating_class;
		ch = session->channel.channel_number;
	}

	wpabuf_put_u8(buf, oc);
	wpabuf_put_u8(buf, 1); /* number of channels */
	wpabuf_put_u8(buf, ch);

	WPA_PUT_LE16(len_ptr, wpabuf_len(buf) - NAN_ATTR_HDR_LEN);

	return buf;
}


/* Build the combined IDP attribute payload carried in PASN M1/M2 */
static struct wpabuf *
idp_build_attributes_payload(struct wpas_idp_session *session)
{
	struct wpabuf *payload, *attr;

	payload = wpabuf_alloc(300);
	if (!payload)
		return NULL;

	attr = idp_build_channel_list_attr(session);
	if (attr) {
		wpabuf_put_buf(payload, attr);
		wpabuf_free(attr);
	}

	return payload;
}


/**
 * wpas_idp_build_req_attrs - Build IDP request attributes for PASN M1
 * @session: IDP session
 * Returns: Attribute buffer, or NULL on failure
 */
struct wpabuf * wpas_idp_build_req_attrs(struct wpas_idp_session *session)
{
	if (!session)
		return NULL;

	return idp_build_attributes_payload(session);
}


/**
 * wpas_idp_build_resp_attrs - Build IDP response attributes for PASN M2
 * @session: IDP session
 * Returns: Attribute buffer, or NULL on failure
 */
struct wpabuf * wpas_idp_build_resp_attrs(struct wpas_idp_session *session)
{
	if (!session)
		return NULL;

	return idp_build_attributes_payload(session);
}


/**
 * wpas_idp_get_pending_request_by_peer - Find a pending request by peer
 * @wpa_s: wpa_supplicant context
 * @peer_addr: Peer NMI address
 * Returns: Matching pending request or NULL if not found
 */
struct wpas_idp_pending_request *
wpas_idp_get_pending_request_by_peer(struct wpa_supplicant *wpa_s,
				     const u8 *peer_addr)
{
	struct wpas_idp_pending_request *req;

	if (!wpa_s || !wpa_s->global || !wpa_s->global->idp || !peer_addr)
		return NULL;

	dl_list_for_each(req, &wpa_s->global->idp->pending_requests,
			 struct wpas_idp_pending_request, list) {
		if (ether_addr_equal(req->peer_addr, peer_addr))
			return req;
	}

	return NULL;
}


/**
 * wpas_idp_free_pending_request - Free a pending incoming PASN M1 request
 * @req: Pending request to free
 */
static void wpas_idp_free_pending_request(struct wpas_idp_pending_request *req)
{
	if (!req)
		return;

	dl_list_del(&req->list);
	wpabuf_free(req->m1_frame);
	os_free(req);
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
	dl_list_init(&idp->pending_requests);

	global->idp = idp;

	wpa_printf(MSG_DEBUG, "IDP: Module initialized");
	return 0;
}


/**
 * wpas_idp_deinit - Deinitialize IDP module
 * @global: Pointer to global wpa_supplicant context
 *
 * Frees all remaining sessions and pending requests, and the global IDP
 * context.
 */
void wpas_idp_deinit(struct wpa_global *global)
{
	struct wpas_idp_info *idp;
	struct wpas_idp_session *session, *tmp;
	struct wpas_idp_pending_request *req, *req_tmp;

	if (!global || !global->idp)
		return;

	idp = global->idp;

	dl_list_for_each_safe(session, tmp, &idp->sessions,
			      struct wpas_idp_session, list)
		wpas_idp_free_session(session);

	dl_list_for_each_safe(req, req_tmp, &idp->pending_requests,
			      struct wpas_idp_pending_request, list)
		wpas_idp_free_pending_request(req);

	os_free(idp);
	global->idp = NULL;

	wpa_printf(MSG_DEBUG, "IDP: Module deinitialized");
}
