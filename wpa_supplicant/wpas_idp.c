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
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/nan_defs.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/pmksa_cache.h"
#include "ap/hostapd.h"
#include "ap/ap_drv_ops.h"
#include "ap/wpa_auth.h"
#include "nan/nan.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "ap.h"
#include "notify.h"
#include "wpas_idp.h"
#include "wpas_idp_pasn.h"


/*
 * Lifetime and reauthentication threshold for PMKSA entries derived
 * from the PASN exchange.
 */
#define IDP_PMKSA_LIFETIME 43200
#define IDP_PMKSA_REAUTH_THRESHOLD (IDP_PMKSA_LIFETIME * 70 / 100)

/* Seconds to wait for a peer to respond a step of the termination exchange */
#define IDP_TERM_RESPONSE_TIMEOUT_SEC 5


/*
 * idp_assign_session_id - Assign an IDP Session ID for a session we serve as AP
 * @session: Session to assigned in ID for
 * Returns: Assigned session ID or 0 if an ID is not available
 *
 * The IDP Session ID, together with the initiator's data path address, uniquely
 * identifies a session. Zero is reserved, leaving values 1-255 available.
 * Assign the lowest free value and return 0 if all session IDs are in use.
 */
static u8 idp_assign_session_id(struct wpas_idp_session *session)
{
	struct wpas_idp_session *s;
	unsigned long used[256 / (8 * sizeof(unsigned long))] = { 0 };
	unsigned int i;

	if (!session->wpa_s || !session->wpa_s->global ||
	    !session->wpa_s->global->idp)
		return 0;

	dl_list_for_each(s, &session->wpa_s->global->idp->sessions,
			 struct wpas_idp_session, list) {
		if (s != session && s->idp_session_id)
			used[s->idp_session_id / (8 * sizeof(used[0]))] |=
				1UL << (s->idp_session_id %
					(8 * sizeof(used[0])));
	}

	for (i = 1; i < 256; i++) {
		if (!(used[i / (8 * sizeof(used[0]))] &
		      (1UL << (i % (8 * sizeof(used[0]))))))
			return i;
	}

	wpa_printf(MSG_INFO, "IDP: No IDP Session ID left for session %u",
		   session->id);

	return 0;
}


/**
 * wpas_idp_peer_supports_idp - Check whether a peer advertised IDP support
 * @wpa_s: Interface holding the NAN context
 * @peer_addr: Peer NAN management interface address
 * Returns: Whether the peer advertised the IDP connection capability
 */
bool wpas_idp_peer_supports_idp(struct wpa_supplicant *wpa_s,
				const u8 *peer_addr)
{
	u16 conn_capa;
	bool valid;

	if (!wpa_s || !wpa_s->nan)
		return false;
	if (nan_peer_get_conn_capa(wpa_s->nan, peer_addr,
				   &conn_capa, &valid) < 0 || !valid)
		return false;

	return !!(conn_capa & NAN_CONN_CAPA_IDP);
}


/*
 * idp_set_channel_from_freq - Settle a session's channel on a given frequency
 * @session: Session to configure
 * @freq: Frequency in MHz, or 0 if the caller did not name one
 * Returns: 0 if the channel was set, -1 if the caller should pick a default
 */
static int idp_set_channel_from_freq(struct wpas_idp_session *session, int freq)
{
	u8 op_class = 0, channel = 0;

	if (freq <= 0)
		return -1;

	if (ieee80211_freq_to_channel_ext(freq, 0, CONF_OPER_CHWIDTH_USE_HT,
					  &op_class, &channel) ==
	    NUM_HOSTAPD_MODES || !op_class || !channel) {
		wpa_printf(MSG_WARNING,
			   "IDP: Session %u: No operating class for freq %d MHz",
			   session->id, freq);
		return -1;
	}

	session->channel.channel_number = channel;
	session->channel.operating_class = op_class;

	return 0;
}


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


/*
 * Session teardown must be able to cancel pending timer callbacks
 * before freeing the session.
 */
static void idp_termination_timeout(void *eloop_ctx, void *timeout_ctx);
static void idp_term_response_tx_done(void *eloop_ctx, void *timeout_ctx);
static void idp_failure_teardown(void *eloop_ctx, void *timeout_ctx);
static void idp_term_request_timeout(void *eloop_ctx, void *timeout_ctx);


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

	/*
	 * All session releases pass through here. Cancel pending timers
	 * before freeing the session to avoid callbacks running on released
	 * memory.
	 */
	eloop_cancel_timeout(idp_termination_timeout, session, NULL);
	eloop_cancel_timeout(idp_term_response_tx_done, session, NULL);
	eloop_cancel_timeout(idp_failure_teardown, session, NULL);
	eloop_cancel_timeout(idp_term_request_timeout, session, NULL);

	os_free(session->pending_termination);
	session->pending_termination = NULL;

	wpas_idp_pasn_deinit(session->pasn_ctx);
	session->pasn_ctx = NULL;

	forced_memzero(session->pmk, sizeof(session->pmk));
	forced_memzero(session->nd_pmk, sizeof(session->nd_pmk));

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


/*
 * Build the IDP ID attribute
 *
 * Carries the BSSID, SSID, hidden-SSID indication, and IDP Session ID.
 * This attribute is transmitted only by the IDP AP, so the Session ID
 * is carried in only one direction: PASN M1 when the AP is the initiator,
 * otherwise PASN M2.
 */
static struct wpabuf *
idp_build_idp_id_attr(struct wpas_idp_session *session)
{
	struct wpabuf *buf;
	u8 *len_ptr;

	if (session->ssid_len == 0 || session->ssid_len > SSID_MAX_LEN)
		return NULL;

	/*
	 * Attr ID(1) + Length(2) + BSSID(6) + SSID Length(1) + SSID +
	 * Discoverability(1) + IDP Session ID(1)
	 */
	buf = wpabuf_alloc(NAN_ATTR_HDR_LEN + ETH_ALEN + 1 + SSID_MAX_LEN + 2);
	if (!buf)
		return NULL;

	wpabuf_put_u8(buf, NAN_ATTR_IDP_ID);
	len_ptr = wpabuf_put(buf, 2);
	wpabuf_put_data(buf, session->bssid, ETH_ALEN);
	wpabuf_put_u8(buf, session->ssid_len);
	wpabuf_put_data(buf, session->ssid, session->ssid_len);
	wpabuf_put_u8(buf, session->discoverable ? 1 : 0);
	wpabuf_put_u8(buf, session->idp_session_id);
	WPA_PUT_LE16(len_ptr, wpabuf_len(buf) - NAN_ATTR_HDR_LEN);

	return buf;
}


/* Build the IDP Operating Channel attribute */
static struct wpabuf *
idp_build_operating_channel_attr(struct wpas_idp_session *session)
{
	struct wpabuf *buf;
	u8 *len_ptr;

	buf = wpabuf_alloc(50);
	if (!buf)
		return NULL;

	wpabuf_put_u8(buf, NAN_ATTR_IDP_OPERATING_CHANNEL);
	len_ptr = wpabuf_put(buf, 2);
	wpabuf_put_data(buf, session->channel.country_string, 3);
	wpabuf_put_u8(buf, 1); /* number of operating channels */
	wpabuf_put_u8(buf, session->channel.operating_class);
	wpabuf_put_u8(buf, session->channel.channel_number);
	WPA_PUT_LE16(len_ptr, wpabuf_len(buf) - NAN_ATTR_HDR_LEN);

	return buf;
}


/**
 * idp_country_string_unset - Whether a session still has no country code
 *
 * Both channel attributes include a country code and may be present in
 * the same frame. The channel is taken from the first attribute that
 * provides one, so the country code follows the same rule rather than
 * being overwritten by a later attribute.
 */
static bool idp_country_string_unset(const struct wpas_idp_session *session)
{
	const u8 *cs = session->channel.country_string;

	return cs[0] == 0 && cs[1] == 0;
}


/**
 * idp_parse_channel_list - Parse the IDP Channel List attribute
 *
 * The attribute carries a country code followed by a sequence of
 * (operating class, channel count, channels) entries. The first advertised
 * channel is selected as the session channel, so a previously selected channel
 * is not overridden by later entries.
 */
static int idp_parse_channel_list(const u8 *data, size_t len,
				  struct wpas_idp_session *session)
{
	const u8 *pos = data;

	if (len < 3)
		return -1;

	if (idp_country_string_unset(session))
		os_memcpy(session->channel.country_string, pos, 3);
	pos += 3;
	len -= 3;

	while (len >= 2) {
		u8 oc = *pos++;
		u8 num = *pos++;

		len -= 2;
		if (len < num)
			break;

		if (num > 0 && session->channel.operating_class == 0) {
			session->channel.operating_class = oc;
			session->channel.channel_number = *pos;
			break;
		}

		pos += num;
		len -= num;
	}

	return 0;
}


/**
 * idp_parse_operating_channel - Parse the IDP Operating Channel attribute
 *
 * Carries the country code, a channel count, and that many (operating
 * class, channel) pairs. As with the channel list, a channel already recorded
 * for the session is left alone.
 */
static int
idp_parse_operating_channel(const u8 *data, size_t len,
			    struct wpas_idp_session *session)
{
	u8 num_channels;

	/* Country String(3) + Number of Operating Channels(1) */
	if (len < 4)
		return -1;

	num_channels = data[3];
	if (len < 4U + num_channels * 2)
		return -1;

	if (idp_country_string_unset(session))
		os_memcpy(session->channel.country_string, data, 3);

	if (num_channels > 0 && session->channel.operating_class == 0) {
		session->channel.operating_class = data[4];
		session->channel.channel_number = data[5];
	}

	return 0;
}


/*
 * Build the IDP attribute payload for PASN M1/M2
 *
 * The IDP ID attribute is only included when the local device takes the AP
 * role, since it advertises the BSSID and SSID the peer is expected to
 * connect to. Its presence is also what tells the peer which role to take:
 * a peer that receives IDP ID becomes the STA.
 *
 * The IDP Operating Channel attribute identifies the channel the AP has
 * settled on and it is included only by the AP.
 */
static struct wpabuf *
idp_build_attributes_payload(struct wpas_idp_session *session)
{
	struct wpabuf *payload, *attr;

	payload = wpabuf_alloc(300);
	if (!payload)
		return NULL;

	if (session->role == WPAS_IDP_ROLE_AP) {
		attr = idp_build_idp_id_attr(session);
		if (attr) {
			wpabuf_put_buf(payload, attr);
			wpabuf_free(attr);
		}
	}

	attr = idp_build_channel_list_attr(session);
	if (attr) {
		wpabuf_put_buf(payload, attr);
		wpabuf_free(attr);
	}

	if (session->role == WPAS_IDP_ROLE_AP) {
		attr = idp_build_operating_channel_attr(session);
		if (attr) {
			wpabuf_put_buf(payload, attr);
			wpabuf_free(attr);
		}
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
 * idp_parse_attributes - Parse IDP attribute TLVs into the session
 *
 * The attributes arrive as raw NAN TLVs, already extracted from the NAN
 * element in a PASN Auhentication frame. Each recognised attribute is decoded
 * into the session; unknown attributes are skipped so that a peer advertising
 * attributes we do not implement is still interoperable.
 *
 * @idp_id_present is set when the IDP ID attribute is seen, which is what
 * tells the responder which role the initiator expects it to take.
 */
static void idp_parse_attributes(const u8 *attrs, size_t attrs_len,
				 struct wpas_idp_session *session,
				 bool *idp_id_present)
{
	const u8 *pos = attrs;
	const u8 *end = attrs + attrs_len;

	if (idp_id_present)
		*idp_id_present = false;

	while (end - pos >= NAN_ATTR_HDR_LEN) {
		u8 id = *pos++;
		u16 len = WPA_GET_LE16(pos);

		pos += 2;
		if (end - pos < len)
			break;

		switch (id) {
		case NAN_ATTR_IDP_ID:
			if (len < ETH_ALEN + 1) {
				wpa_printf(MSG_DEBUG,
					   "IDP: Too short IDP ID attribute");
				break;
			}
			if (idp_id_present)
				*idp_id_present = true;
			os_memcpy(session->bssid, pos, ETH_ALEN);
			session->ssid_len = pos[ETH_ALEN];
			if (session->ssid_len <= SSID_MAX_LEN &&
			    len >= ETH_ALEN + 1 + session->ssid_len)
				os_memcpy(session->ssid, pos + ETH_ALEN + 1,
					  session->ssid_len);
			else
				session->ssid_len = 0;

			/*
			 * Discoverability and the IDP Session ID follow the
			 * SSID.
			 */
			if (len >= ETH_ALEN + 1 + session->ssid_len + 2) {
				const u8 *tail;

				tail = pos + ETH_ALEN + 1 + session->ssid_len;
				session->discoverable = tail[0] != 0;
				session->idp_session_id = tail[1];
			}
			break;
		case NAN_ATTR_IDP_CHANNEL_LIST:
			idp_parse_channel_list(pos, len, session);
			break;
		case NAN_ATTR_IDP_OPERATING_CHANNEL:
			idp_parse_operating_channel(pos, len, session);
			break;
		}

		pos += len;
	}
}


/**
 * idp_op_class_priority - Return band priority for an operating class
 * @op_class: Global operating class
 * Returns: 3 for 6 GHz, 2 for 5 GHz, 1 for 2.4 GHz, or -1 otherwise.
 */
static int idp_op_class_priority(u8 op_class)
{
	if (op_class >= 131 && op_class <= 137)
		return 3; /* 6 GHz */
	if (op_class >= 115 && op_class <= 130)
		return 2; /* 5 GHz */
	if (op_class >= 81 && op_class <= 84)
		return 1; /* 2.4 GHz */

	return -1;
}


static bool idp_chan_usable(const struct hostapd_channel_data *chan)
{
	return !(chan->flag & (HOSTAPD_CHAN_DISABLED | HOSTAPD_CHAN_NO_IR |
			       HOSTAPD_CHAN_RADAR));
}


static bool idp_freq_usable(struct wpa_supplicant *wpa_s, int freq)
{
	u16 i;

	for (i = 0; i < wpa_s->hw.num_modes; i++) {
		struct hostapd_hw_modes *mode = &wpa_s->hw.modes[i];
		int j;

		for (j = 0; j < mode->num_channels; j++) {
			struct hostapd_channel_data *chan = &mode->channels[j];

			if (chan->freq == freq)
				return idp_chan_usable(chan);
		}
	}

	return false;
}


/**
 * idp_freq_score - Rank a frequency for local IDP AP channel selection
 * @freq: Frequency in MHz
 * Returns: Score (higher is better), or -1 if the frequency cannot be used
 *
 * Higher bands are preferred. Within a band, prefer the 2.4 GHz social
 * channels 1, 6, and 11, the 5 GHz U-NII-1 channels, and the 6 GHz PSC
 * channels.
 */
static int idp_freq_score(int freq)
{
	u8 op_class = 0, channel = 0;
	int priority;
	bool preferred;

	if (ieee80211_freq_to_channel_ext(freq, 0, CONF_OPER_CHWIDTH_USE_HT,
					  &op_class, &channel) ==
	    NUM_HOSTAPD_MODES)
		return -1;

	priority = idp_op_class_priority(op_class);
	if (priority < 0)
		return -1;

	preferred = freq == 2412 || freq == 2437 || freq == 2462 ||
		(freq >= 5180 && freq <= 5240) ||
		is_6ghz_psc_frequency(freq);

	return priority * 2 + preferred;
}


/* Return the first usable entry in the driver preferred frequency list */
static int idp_select_pref_freq(struct wpa_supplicant *wpa_s)
{
	struct weighted_pcl pref_list[100];
	unsigned int size = ARRAY_SIZE(pref_list);
	unsigned int i;

	if (wpa_drv_get_pref_freq_list(wpa_s, WPA_IF_AP_BSS, &size,
				       pref_list) < 0 || !size) {
		wpa_printf(MSG_DEBUG,
			   "IDP: No preferred frequency list available from the driver");
		return 0;
	}

	for (i = 0; i < size; i++) {
		int freq = pref_list[i].freq;

		if ((pref_list[i].flag & WEIGHTED_PCL_EXCLUDE) ||
		    idp_freq_score(freq) < 0 ||
		    !idp_freq_usable(wpa_s, freq)) {
			wpa_printf(MSG_DEBUG,
				   "IDP: Driver preferred frequency %d MHz not allowed",
				   freq);
			continue;
		}

		return freq;
	}

	wpa_printf(MSG_DEBUG,
		   "IDP: All driver preferred frequencies are disallowed");
	return 0;
}


/* Return the best usable frequency in the hardware channel list */
static int idp_select_hw_freq(struct wpa_supplicant *wpa_s)
{
	int best_freq = 0, best_score = -1;
	u16 i;

	for (i = 0; i < wpa_s->hw.num_modes; i++) {
		struct hostapd_hw_modes *mode = &wpa_s->hw.modes[i];
		int j;

		for (j = 0; j < mode->num_channels; j++) {
			struct hostapd_channel_data *chan = &mode->channels[j];
			int score;

			if (!idp_chan_usable(chan))
				continue;

			score = idp_freq_score(chan->freq);
			if (score > best_score) {
				best_score = score;
				best_freq = chan->freq;
			}
		}
	}

	return best_freq;
}


/**
 * idp_select_default_channel - Select a default IDP channel
 * @session: IDP session
 * Returns: 0 on success, -1 if no usable channel is available
 *
 * Use the first usable frequency from the driver preferred frequency list,
 * if one is available. Otherwise, select the highest ranked usable channel
 * from the hardware channel list (see idp_freq_score()).
 */
static int idp_select_default_channel(struct wpas_idp_session *session)
{
	struct wpa_supplicant *wpa_s = session->wpa_s;
	u8 country[3];
	int freq;

	if (!wpa_s->hw.modes || !wpa_s->hw.num_modes) {
		wpa_printf(MSG_DEBUG, "IDP: No hardware channel list available");
		return -1;
	}

	freq = idp_select_pref_freq(wpa_s);
	if (!freq)
		freq = idp_select_hw_freq(wpa_s);
	if (!freq) {
		wpa_printf(MSG_INFO, "IDP: No usable channel for AP operation");
		return -1;
	}

	if (idp_set_channel_from_freq(session, freq) < 0)
		return -1;

	idp_get_country_string(wpa_s, country);
	os_memcpy(session->channel.country_string, country, 3);

	wpa_printf(MSG_DEBUG, "IDP: Selected channel %d MHz (class=%u ch=%u)",
		   freq, session->channel.operating_class,
		   session->channel.channel_number);
	return 0;
}


/**
 * idp_generate_ssid - Generate an SSID for an IDP AP
 * @session: IDP session
 * Returns: 0 on success, -1 on failure
 *
 * The SSID is "NAN-IDP-" followed by a random suffix so that IDP APs started
 * by different devices are unlikely to use the same SSID.
 */
static int idp_generate_ssid(struct wpas_idp_session *session)
{
	u8 rnd[4];
	int res;

	if (os_get_random(rnd, sizeof(rnd)) < 0) {
		wpa_printf(MSG_INFO,
			   "IDP: Could not generate random data for SSID");
		return -1;
	}

	res = os_snprintf((char *) session->ssid, sizeof(session->ssid),
			  "NAN-IDP-%02x%02x%02x%02x",
			  rnd[0], rnd[1], rnd[2], rnd[3]);
	if (os_snprintf_error(sizeof(session->ssid), res))
		return -1;

	session->ssid_len = res;
	return 0;
}


/**
 * wpas_idp_process_req_attrs - Process PASN M1 attributes on the responder side
 * @session: IDP session
 * @attrs: Raw NAN attribute TLVs
 * @attrs_len: Length of attrs
 * Returns: 0 on success, -1 on failure
 *
 * Determine the responder role based on the presence of the IDP ID attribute in
 * PASN M1. If the attribute is present, the initiator has provided the AP
 * identity and assumes the AP role, so the responder becomes the STA.
 * Otherwise, the initiator requests the responder to operate as the AP, and the
 * responder generates the SSID for the session.
 */
int wpas_idp_process_req_attrs(struct wpas_idp_session *session,
			       const u8 *attrs, size_t attrs_len)
{
	bool idp_id_present = false;

	if (!session)
		return -1;

	idp_parse_attributes(attrs, attrs_len, session, &idp_id_present);

	if (idp_id_present) {
		session->role = WPAS_IDP_ROLE_STA;
	} else {
		session->role = WPAS_IDP_ROLE_AP;

		if (idp_generate_ssid(session) < 0)
			return -1;

		/* The AP creates and owns the IDP Session ID sent in IDP ID. */
		session->idp_session_id = idp_assign_session_id(session);

		if (session->channel.operating_class == 0 &&
		    idp_select_default_channel(session) < 0)
			return -1;
	}

	wpa_printf(MSG_DEBUG, "IDP: Responder role: %s",
		   session->role == WPAS_IDP_ROLE_AP ? "AP" : "STA");
	return 0;
}


/**
 * wpas_idp_process_resp_attrs - Process PASN M2 attributes on the initiator
 * @session: IDP session
 * @attrs: Raw NAN attribute TLVs, or %NULL if PASN M2 carried none
 * @attrs_len: Length of attrs
 * Returns: 0 on success, -1 if the session cannot proceed
 *
 * When operating as the STA, the peer acts as the AP and must provide both the
 * BSSID and the operating channel. If either is missing, the handshake fails
 * immediately instead of timing out during association.
 */
int wpas_idp_process_resp_attrs(struct wpas_idp_session *session,
				const u8 *attrs, size_t attrs_len)
{
	if (!session)
		return -1;

	if (attrs)
		idp_parse_attributes(attrs, attrs_len, session, NULL);

	if (session->role != WPAS_IDP_ROLE_STA)
		return 0;

	if (is_zero_ether_addr(session->bssid) || session->ssid_len == 0) {
		wpa_printf(MSG_INFO,
			   "IDP: Responder did not provide BSSID/SSID");
		return -1;
	}

	if (session->channel.operating_class == 0 ||
	    session->channel.channel_number == 0) {
		wpa_printf(MSG_INFO, "IDP: Responder did not provide channel");
		return -1;
	}

	return 0;
}


/**
 * wpas_idp_set_pmk - Store PMK derived from PASN handshake
 * @session: IDP session
 * @pmk: PMK buffer
 * @pmk_len: Length of PMK, must not exceed PMK_LEN
 * Returns: 0 on success, -1 on invalid parameters
 */
int wpas_idp_set_pmk(struct wpas_idp_session *session,
		     const u8 *pmk, size_t pmk_len)
{
	if (!session || !pmk || !pmk_len || pmk_len > PMK_LEN) {
		wpa_printf(MSG_ERROR, "IDP: Invalid parameters for PMK setup");
		return -1;
	}

	os_memcpy(session->pmk, pmk, pmk_len);
	session->pmk_len = pmk_len;

	wpa_printf(MSG_DEBUG, "IDP: PMK set for session %u (len=%zu)",
		   session->id, session->pmk_len);
	wpa_hexdump_key(MSG_DEBUG, "IDP: PMK", session->pmk, session->pmk_len);

	return 0;
}


/*
 * idp_enter_peer_termination - Leave the operating state after accepting
 *
 * Handle peer-initiated termination. A three-message termination exchange
 * requires a final confirmation, while a two-message exchange completes after
 * the response is sent.
 */
static void idp_enter_peer_termination(struct wpas_idp_session *session)
{
	if (session->termination.handshake_mode == 3) {
		session->state = IDP_STATE_TERM_WAIT_CONFIRM;
		wpa_printf(MSG_DEBUG,
			   "IDP: Session %u: ACTIVE -> TERM_WAIT_CONFIRM",
			   session->id);
	} else {
		session->state = IDP_STATE_TERMINATING;
		wpa_printf(MSG_DEBUG,
			   "IDP: Session %u: ACTIVE -> TERMINATING",
			   session->id);
	}
}


/**
 * wpas_idp_state_machine - IDP session state machine
 * @session: IDP session
 * @event: Event to process
 * Returns: 0 on success, -1 on invalid session or unhandled state
 *
 * Drives state transitions for an IDP session. A state gets a case here
 * once the code that can put a session into it exists, so that every branch is
 * reachable.
 */
int wpas_idp_state_machine(struct wpas_idp_session *session,
			   enum wpas_idp_event event)
{
	if (!session) {
		wpa_printf(MSG_ERROR, "IDP: Invalid session in state machine");
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "IDP: State machine: session=%u state=%d event=%d role=%d",
		   session->id, session->state, event, session->role);

	switch (session->state) {
	case IDP_STATE_NONE:
		if (event == IDP_EVENT_INIT) {
			session->state = IDP_STATE_NEGOTIATING;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: NONE -> NEGOTIATING",
				   session->id);
		}
		break;
	case IDP_STATE_NEGOTIATING:
		if (event == IDP_EVENT_PASN_SUCCESS) {
			session->state = IDP_STATE_NEGOTIATED;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: NEGOTIATING -> NEGOTIATED",
				   session->id);

			/*
			 * Continue with role-specific setup in the same state
			 * machine invocation. PASN success is reported only
			 * once, so waiting for a separate event would leave the
			 * session unconfigured.
			 *
			 * The setup functions report failures through
			 * IDP_EVENT_FAILURE, which advances the state before
			 * they return. Any additional return value handling
			 * here is therefore limited to logging.
			 */
			if (session->role == WPAS_IDP_ROLE_AP) {
				session->state = IDP_STATE_CONFIGURING_AP;
				wpa_printf(MSG_DEBUG,
					   "IDP: Session %u: NEGOTIATED -> CONFIGURING_AP",
					   session->id);
				if (wpas_idp_setup_ap(session) < 0)
					wpa_printf(MSG_ERROR,
						   "IDP: Session %u: AP setup failed",
						   session->id);
			} else {
				session->state = IDP_STATE_CONFIGURING_STA;
				wpa_printf(MSG_DEBUG,
					   "IDP: Session %u: NEGOTIATED -> CONFIGURING_STA",
					   session->id);
				if (wpas_idp_setup_sta(session) < 0)
					wpa_printf(MSG_ERROR,
						   "IDP: Session %u: STA setup failed",
						   session->id);
			}
		} else if (event == IDP_EVENT_PASN_FAILED ||
			   event == IDP_EVENT_FAILURE) {
			session->state = IDP_STATE_TERMINATING;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: NEGOTIATING -> TERMINATING",
				   session->id);
			eloop_register_timeout(0, 0, idp_failure_teardown,
					       session, NULL);
			wpa_msg(session->wpa_s, MSG_INFO,
				IDP_EVENT_REJECTED "peer=" MACSTR " session=%u",
				MAC2STR(session->peer_addr), session->id);
		}
		break;
	case IDP_STATE_NEGOTIATED:
		/*
		 * The session passes through this state immediately after
		 * NEGOTIATING. Any event received while in this state indicates
		 * that the transition above did not execute as expected.
		 */
		wpa_printf(MSG_INFO,
			   "IDP: Session %u: event %d in NEGOTIATED state, setup was not started",
			   session->id, event);
		break;
	case IDP_STATE_CONFIGURING_AP:
		if (event == IDP_EVENT_AP_UP) {
			session->state = IDP_STATE_ACTIVE_AP;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: CONFIGURING_AP -> ACTIVE_AP",
				   session->id);
		} else if (event == IDP_EVENT_FAILURE) {
			session->state = IDP_STATE_TERMINATING;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: CONFIGURING_AP -> TERMINATING",
				   session->id);
			eloop_register_timeout(0, 0, idp_failure_teardown,
					       session, NULL);
		}
		break;
	case IDP_STATE_CONFIGURING_STA:
		if (event == IDP_EVENT_STA_CONNECTED) {
			session->state = IDP_STATE_ACTIVE_STA;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: CONFIGURING_STA -> ACTIVE_STA",
				   session->id);
		} else if (event == IDP_EVENT_FAILURE) {
			session->state = IDP_STATE_TERMINATING;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: CONFIGURING_STA -> TERMINATING",
				   session->id);
			eloop_register_timeout(0, 0, idp_failure_teardown,
					       session, NULL);
		}
		break;
	case IDP_STATE_ACTIVE_AP:
		if (event == IDP_EVENT_PEER_CONNECTED) {
			session->state = IDP_STATE_PEER_CONNECTED;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: ACTIVE_AP -> PEER_CONNECTED",
				   session->id);

			/*
			 * The AP has no local connection event. Consider the
			 * IDP link established when the peer connects and the
			 * data path is available.
			 */
			wpas_notify_idp_established(
				session->wpa_s, "ap", session->peer_addr,
				session->connected_sta_mac_addr);
		} else if (event == IDP_EVENT_TERM_REQUEST_RX) {
			idp_enter_peer_termination(session);
		} else if (event == IDP_EVENT_TERM_INITIATED) {
			session->state = IDP_STATE_TERM_WAIT_RESP;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: ACTIVE_AP -> TERM_WAIT_RESP",
				   session->id);
		} else if (event == IDP_EVENT_DISCONNECTED ||
			   event == IDP_EVENT_FAILURE) {
			session->state = IDP_STATE_TERMINATING;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: ACTIVE_AP -> TERMINATING",
				   session->id);
		}
		break;
	case IDP_STATE_ACTIVE_STA:
	case IDP_STATE_PEER_CONNECTED:
		if (event == IDP_EVENT_DISCONNECTED ||
		    event == IDP_EVENT_FAILURE) {
			session->state = IDP_STATE_TERMINATING;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: ACTIVE -> TERMINATING",
				   session->id);
		} else if (event == IDP_EVENT_TERM_REQUEST_RX) {
			idp_enter_peer_termination(session);
		} else if (event == IDP_EVENT_TERM_INITIATED) {
			session->state = IDP_STATE_TERM_WAIT_RESP;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: ACTIVE -> TERM_WAIT_RESP",
				   session->id);
		}
		break;
	case IDP_STATE_TERM_WAIT_CONFIRM:
		if (event == IDP_EVENT_TERM_CONFIRM_RX ||
		    event == IDP_EVENT_TERM_TIMEOUT ||
		    event == IDP_EVENT_FAILURE) {
			session->state = IDP_STATE_TERMINATING;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: TERM_WAIT_CONFIRM -> TERMINATING",
				   session->id);
		}
		break;
	case IDP_STATE_TERM_WAIT_RESP:
		if (event == IDP_EVENT_TERM_TIMEOUT ||
		    event == IDP_EVENT_FAILURE) {
			session->state = IDP_STATE_TERMINATING;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: TERM_WAIT_RESP -> TERMINATING",
				   session->id);
		} else if (event == IDP_EVENT_TERM_RESPONSE_RX) {
			/*
			 * The peer has agreed. Nothing else is waited for even
			 * in the three step form, because the confirm this side
			 * owes the peer is sent as part of handling the
			 * response.
			 */
			session->state = IDP_STATE_TERMINATING;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: TERM_WAIT_RESP -> TERMINATING",
				   session->id);
		}
		break;
	case IDP_STATE_TERMINATING:
		if (event == IDP_EVENT_FAILURE) {
			session->state = IDP_STATE_NONE;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: TERMINATING -> NONE",
				   session->id);
		}
		break;
	default:
		wpa_printf(MSG_WARNING, "IDP: Session %u: Unhandled state %d",
			   session->id, session->state);
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "IDP: State machine done: session=%u new_state=%d",
		   session->id, session->state);

	return 0;
}


/**
 * idp_build_idp_information_attr - Build the IDP Information attribute
 *
 * The Control field indicates which optional subfields are present. Include the
 * operating channel only when requested so the peer is not told to use a
 * channel that has not yet been selected for the session.
 */
static struct wpabuf *
idp_build_idp_information_attr(struct wpas_idp_session *session,
			       bool include_op_channel)
{
	struct wpabuf *buf;
	u8 *len_ptr, *ctrl_ptr;
	u8 control = 0;

	/* Attr ID(1) + Length(2) + Control(1) + optional channel triplet */
	buf = wpabuf_alloc(4 + 3);
	if (!buf)
		return NULL;

	wpabuf_put_u8(buf, NAN_ATTR_IDP_INFORMATION);
	len_ptr = wpabuf_put(buf, 2);
	ctrl_ptr = wpabuf_put(buf, 1);

	if (include_op_channel) {
		control |= NAN_IDP_INFO_CTRL_OP_CHAN_PRESENT;
		wpabuf_put_u8(buf, session->channel.operating_class);
		wpabuf_put_u8(buf, session->channel.channel_number);
		wpabuf_put_u8(buf, 0); /* center frequency index of the second
					* segment (80+80 MHz)*/
	}

	*ctrl_ptr = control;
	WPA_PUT_LE16(len_ptr, wpabuf_len(buf) - 3);

	return buf;
}


/**
 * wpas_idp_set_ap_beacon_elems - Advertise IDP support in the AP beacon
 * @session: IDP session in the AP role
 * Returns: 0 on success, -1 on failure
 *
 * Build a NAN element containing the Device Capability Extension and IDP
 * Information attributes and install it as AP vendor elements so it is included
 * in Beacon and Probe Response frames. This allows NAN peers to identify the
 * BSS as an IDP AP and discover the session operating channel.
 */
static int wpas_idp_set_ap_beacon_elems(struct wpas_idp_session *session)
{
	struct wpa_supplicant *ap_wpa_s;
	struct wpabuf *attrs, *info_attr, *vendor_elem;

	if (!session)
		return -1;

	ap_wpa_s = session->group_wpa_s ? session->group_wpa_s : session->wpa_s;
	if (!ap_wpa_s || !ap_wpa_s->conf)
		return -1;

	attrs = wpabuf_alloc(108);
	if (!attrs)
		return -1;

	if (session->wpa_s && session->wpa_s->nan)
		nan_add_dev_capa_ext_attr(session->wpa_s->nan, attrs);

	info_attr = idp_build_idp_information_attr(session, true);
	if (!info_attr) {
		wpabuf_free(attrs);
		return -1;
	}
	if (wpabuf_resize(&attrs, wpabuf_len(info_attr)) < 0) {
		wpabuf_free(info_attr);
		wpabuf_free(attrs);
		return -1;
	}
	wpabuf_put_buf(attrs, info_attr);
	wpabuf_free(info_attr);

	vendor_elem = wpas_idp_build_nan_elem(attrs);
	wpabuf_free(attrs);
	if (!vendor_elem)
		return -1;

	wpabuf_free(ap_wpa_s->conf->ap_vendor_elements);
	ap_wpa_s->conf->ap_vendor_elements = vendor_elem;

	wpa_printf(MSG_DEBUG, "IDP: Set AP beacon elements on '%s' (%zu bytes)",
		   ap_wpa_s->ifname, wpabuf_len(vendor_elem));

	return 0;
}


/**
 * wpas_idp_setup_ap - Start the AP for an IDP session
 * @session: IDP session
 * Returns: 0 on success, -1 on failure
 *
 * Configure and start a WPA3-SAE AP on the session interface using the
 * negotiated BSSID, SSID, and operating channel. Report the result to the state
 * machine through IDP_EVENT_AP_UP on success or IDP_EVENT_FAILURE on failure.
 */
int wpas_idp_setup_ap(struct wpas_idp_session *session)
{
	struct wpa_supplicant *iface_wpa_s;
	struct wpa_ssid *ssid_conf;
	char ssid_hex[SSID_MAX_LEN * 2 + 1];
	int freq;

	if (!session) {
		wpa_printf(MSG_ERROR, "IDP: No session for AP setup");
		return -1;
	}

	if (session->pmk_len != PMK_LEN) {
		wpa_printf(MSG_ERROR, "IDP: Session %u: no PMK for AP setup",
			   session->id);
		goto fail;
	}

	if (!session->group_wpa_s) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: no interface for AP setup",
			   session->id);
		goto fail;
	}

	if (!session->nd_pmk_valid || !session->pmkid_valid) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: no ND-PMK or PMKID for AP setup",
			   session->id);
		goto fail;
	}

	if (session->ssid_len == 0 || session->ssid_len > SSID_MAX_LEN) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: invalid SSID length %zu",
			   session->id, session->ssid_len);
		goto fail;
	}

	iface_wpa_s = session->group_wpa_s;

	/*
	 * Operating frequency comes from the negotiated operating class and
	 * channel. Fall back to a locally chosen channel if the pair does not
	 * map to a frequency in the current regulatory domain.
	 */
	freq = ieee80211_chan_to_freq(NULL, session->channel.operating_class,
				      session->channel.channel_number);
	if (freq <= 0) {
		if (idp_select_default_channel(session) < 0)
			goto fail;
		freq = ieee80211_chan_to_freq(NULL,
					      session->channel.operating_class,
					      session->channel.channel_number);
	}
	if (freq <= 0) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: no frequency for operating class=%u ch=%u",
			   session->id, session->channel.operating_class,
			   session->channel.channel_number);
		goto fail;
	}

	ssid_conf = wpa_config_add_network(iface_wpa_s->conf);
	if (!ssid_conf) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: failed to add AP network block",
			   session->id);
		goto fail;
	}

	wpa_config_set_network_defaults(ssid_conf);
	ssid_conf->mode = WPAS_MODE_AP;
	ssid_conf->disabled = 0;
	ssid_conf->eht = 1;
	ssid_conf->frequency = freq;

	/* The interface MAC address is the BSSID the peer will associate to */
	if (!is_zero_ether_addr(session->iface_addr))
		os_memcpy(session->bssid, session->iface_addr, ETH_ALEN);
	os_memcpy(ssid_conf->bssid, session->bssid, ETH_ALEN);
	ssid_conf->bssid_set = 1;

	wpa_snprintf_hex(ssid_hex, sizeof(ssid_hex), session->ssid,
			 session->ssid_len);
	if (wpa_config_set(ssid_conf, "ssid", ssid_hex, 0) < 0) {
		wpa_printf(MSG_ERROR, "IDP: Session %u: failed to set AP SSID",
			   session->id);
		goto fail_remove;
	}

	/*
	 * A session the peer was told is not discoverable keeps its SSID out
	 * of the Beacon frames, which still leaves it reachable to a peer that
	 * probes for it by name.
	 */
	ssid_conf->ignore_broadcast_ssid = session->discoverable ? 0 : 1;

	/* WPA3-SAE with CCMP and management frame protection required */
	ssid_conf->key_mgmt = WPA_KEY_MGMT_SAE;
	ssid_conf->auth_alg = WPA_AUTH_ALG_OPEN;
	ssid_conf->proto = WPA_PROTO_RSN;
	ssid_conf->pairwise_cipher = WPA_CIPHER_CCMP;
	ssid_conf->group_cipher = WPA_CIPHER_CCMP;
	ssid_conf->ieee80211w = MGMT_FRAME_PROTECTION_REQUIRED;
	ssid_conf->sae_pwe = SAE_PWE_HASH_TO_ELEMENT;

	wpa_printf(MSG_DEBUG,
		   "IDP: Session %u: AP freq=%d MHz class=%u ch=%u bssid="
		   MACSTR,
		   session->id, freq, session->channel.operating_class,
		   session->channel.channel_number, MAC2STR(session->bssid));

	/*
	 * Advertise IDP AP operation and TWT concurrency support through
	 * NAN and the AP beacon so peers can identify the BSS as an IDP
	 * AP without first establishing a NAN session.
	 */
	if (session->wpa_s->nan)
		nan_set_idp_twt_support(session->wpa_s->nan, true);

	if (wpas_idp_set_ap_beacon_elems(session) < 0) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: failed to set AP beacon elements",
			   session->id);
		goto fail_remove;
	}

	iface_wpa_s->current_ssid = ssid_conf;
	if (wpa_supplicant_create_ap(iface_wpa_s, ssid_conf) < 0) {
		wpa_printf(MSG_ERROR, "IDP: Session %u: failed to start AP",
			   session->id);
		iface_wpa_s->current_ssid = NULL;
		goto fail_remove;
	}

	wpa_printf(MSG_INFO, "IDP: AP started on interface '%s'",
		   iface_wpa_s->ifname);

	/*
	 * The peer authenticates using the ND-PMK derived from PASN, so
	 * install a PMKSA entry to allow association without performing
	 * SAE. The address the peer uses for association is not known yet,
	 * so the entry is stored under the peer NMI and it is matched by
	 * its PMKID once the peer associates.
	 */
	if (iface_wpa_s->ap_iface && iface_wpa_s->ap_iface->num_bss > 0) {
		struct hostapd_data *hapd = iface_wpa_s->ap_iface->bss[0];

		wpa_auth_pmksa_add_pmkid_only(hapd->wpa_auth,
					      session->peer_addr,
					      session->nd_pmk, PMK_LEN,
					      session->pmkid,
					      WPA_KEY_MGMT_SAE);
		hostapd_add_pmkid(hapd, session->peer_addr,
				  session->nd_pmk, PMK_LEN,
				  session->pmkid, WPA_KEY_MGMT_SAE);

		wpa_printf(MSG_DEBUG,
			   "IDP: Session %u: ND-PMK cached for peer " MACSTR,
			   session->id, MAC2STR(session->peer_addr));
	}

	wpas_idp_state_machine(session, IDP_EVENT_AP_UP);

	return 0;

fail_remove:
	wpa_config_remove_network(iface_wpa_s->conf, ssid_conf->id);
fail:
	wpas_idp_state_machine(session, IDP_EVENT_FAILURE);

	return -1;
}


/**
 * wpas_idp_setup_sta - Connect the STA for an IDP session
 * @session: IDP session in the STA role
 * Returns: 0 on success, -1 on failure
 *
 * Create a temporary network profile for the negotiated IDP AP and initiate
 * association. The profile carries no SAE credential; the STA is expected to
 * authenticate using a PMKSA derived from the PASN exchange and therefore
 * requests Open authentication to use PMKSA caching.
 */
int wpas_idp_setup_sta(struct wpas_idp_session *session)
{
	struct wpa_supplicant *iface_wpa_s;
	struct wpa_ssid *ssid_conf;
	struct rsn_pmksa_cache_entry *pmksa;
	struct os_reltime now;
	char ssid_hex[SSID_MAX_LEN * 2 + 1];

	if (!session) {
		wpa_printf(MSG_ERROR, "IDP: No session for STA setup");
		return -1;
	}

	if (session->pmk_len != PMK_LEN) {
		wpa_printf(MSG_ERROR, "IDP: Session %u: no PMK for STA setup",
			   session->id);
		goto fail;
	}

	/*
	 * A responder may create the interface only after accepting the
	 * request, so it may still need to be registered at this point.
	 */
	if (session->pending_iface_name[0] && !session->group_wpa_s &&
	    !wpas_idp_init_interface(session->wpa_s, session)) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: failed to initialize STA interface",
			   session->id);
		wpas_idp_remove_interface(session->wpa_s, session);
		goto fail;
	}

	if (!session->group_wpa_s) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: no interface for STA setup",
			   session->id);
		goto fail;
	}

	if (session->ssid_len == 0 || session->ssid_len > SSID_MAX_LEN) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: invalid SSID length %zu",
			   session->id, session->ssid_len);
		goto fail;
	}

	if (!session->nd_pmk_valid || !session->pmkid_valid) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: no ND-PMK or PMKID for STA setup",
			   session->id);
		goto fail;
	}

	iface_wpa_s = session->group_wpa_s;

	ssid_conf = wpa_config_add_network(iface_wpa_s->conf);
	if (!ssid_conf) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: failed to add STA network",
			   session->id);
		goto fail;
	}

	wpa_config_set_network_defaults(ssid_conf);
	ssid_conf->mode = WPAS_MODE_INFRA;
	ssid_conf->disabled = 0;
	ssid_conf->temporary = 1;

	if (!is_zero_ether_addr(session->bssid)) {
		os_memcpy(ssid_conf->bssid, session->bssid, ETH_ALEN);
		ssid_conf->bssid_set = 1;
	}

	wpa_snprintf_hex(ssid_hex, sizeof(ssid_hex), session->ssid,
			 session->ssid_len);
	if (wpa_config_set(ssid_conf, "ssid", ssid_hex, 0) < 0) {
		wpa_printf(MSG_ERROR, "IDP: Session %u: failed to set STA SSID",
			   session->id);
		goto fail_remove;
	}

	/*
	 * Request Open authentication since this network has no SAE credential.
	 * Association is expected to use the PMKSA derived from the PASN
	 * exchange.
	 */
	ssid_conf->key_mgmt = WPA_KEY_MGMT_SAE | WPA_KEY_MGMT_PASN;
	ssid_conf->auth_alg = WPA_AUTH_ALG_OPEN;
	ssid_conf->proto = WPA_PROTO_RSN;
	ssid_conf->pairwise_cipher = WPA_CIPHER_CCMP;
	ssid_conf->group_cipher = WPA_CIPHER_CCMP;
	ssid_conf->ieee80211w = MGMT_FRAME_PROTECTION_REQUIRED;
	ssid_conf->sae_pwe = SAE_PWE_HASH_TO_ELEMENT;

	/*
	 * If the IDP AP is known to be on a single channel, restrict scanning
	 * accordingly. This reduces scan time and avoids unnecessary disruption
	 * to NAN operation on other channels. Failure to do so is not fatal and
	 * only results in a full scan.
	 */
	if (session->channel.operating_class &&
	    session->channel.channel_number) {
		int freq;
		int *scan_freq = NULL;

		freq = ieee80211_chan_to_freq(NULL,
					      session->channel.operating_class,
					      session->channel.channel_number);

		if (freq > 0)
			scan_freq = os_zalloc(2 * sizeof(int));

		if (scan_freq) {
			scan_freq[0] = freq;
			os_free(ssid_conf->scan_freq);
			ssid_conf->scan_freq = scan_freq;
		} else {
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: STA scan could not be restricted to opclass %u ch %u",
				   session->id,
				   session->channel.operating_class,
				   session->channel.channel_number);
		}
	}

	/*
	 * Install a PMKSA entry derived from the PASN exchange. This allows
	 * association using the cached PMKSA instead of performing SAE,
	 * which has no credential for this network. Ownership of the entry
	 * is transferred to the PMKSA cache.
	 */
	if (!iface_wpa_s->wpa) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: no WPA state machine for STA setup",
			   session->id);
		goto fail_remove;
	}

	pmksa = os_zalloc(sizeof(*pmksa));
	if (!pmksa) {
		wpa_printf(MSG_ERROR,
			   "IDP: Session %u: failed to allocate STA PMKSA entry",
			   session->id);
		goto fail_remove;
	}

	os_memcpy(pmksa->aa, session->bssid, ETH_ALEN);
	os_memcpy(pmksa->spa, iface_wpa_s->own_addr, ETH_ALEN);
	os_memcpy(pmksa->pmkid, session->pmkid, PMKID_LEN);
	os_memcpy(pmksa->pmk, session->nd_pmk, PMK_LEN);
	pmksa->pmk_len = PMK_LEN;
	pmksa->akmp = WPA_KEY_MGMT_SAE;
	pmksa->network_ctx = ssid_conf;
	os_get_reltime(&now);
	pmksa->expiration = now.sec + IDP_PMKSA_LIFETIME;
	pmksa->reauth_time = now.sec + IDP_PMKSA_REAUTH_THRESHOLD;
	wpa_sm_pmksa_cache_add_entry(iface_wpa_s->wpa, pmksa);

	/*
	 * Mark the network as using a PASN-derived PMK so the connection
	 * path selects the cached PMKSA instead of SAE authentication.
	 */
	ssid_conf->pmk_valid = true;

	wpa_printf(MSG_DEBUG,
		   "IDP: Session %u: ND-PMK cached for BSSID " MACSTR,
		   session->id, MAC2STR(session->bssid));

	session->network_id = ssid_conf->id;

	iface_wpa_s->current_ssid = ssid_conf;
	wpa_supplicant_select_network(iface_wpa_s, ssid_conf);

	wpa_printf(MSG_DEBUG, "IDP: Session %u: STA connecting on '%s' to "
		   MACSTR,
		   session->id, iface_wpa_s->ifname, MAC2STR(session->bssid));

	return 0;

fail_remove:
	wpa_config_remove_network(iface_wpa_s->conf, ssid_conf->id);
fail:
	wpas_idp_state_machine(session, IDP_EVENT_FAILURE);

	return -1;
}


/**
 * wpas_idp_need_separate_iface - Check whether IDP needs its own netdev
 * @wpa_s: wpa_supplicant structure
 * Returns: Whether a separate virtual interface should be created
 *
 * Create a dedicated interface for IDP when the driver supports separate
 * management and data-path operation. Otherwise, reuse the interface on which
 * the IDP request was initiated.
 */
bool wpas_idp_need_separate_iface(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->drv_flags & (WPA_DRIVER_FLAGS_DEDICATED_P2P_DEVICE |
				WPA_DRIVER_FLAGS_P2P_MGMT_AND_NON_P2P))
		return true;

	wpa_printf(MSG_DEBUG,
		   "IDP: Driver supports concurrent operation on the same interface");

	return false;
}


/**
 * wpas_idp_add_interface - Create an IDP virtual interface
 * @wpa_s: wpa_supplicant structure
 * @session: IDP session
 * @type: Interface type, WPA_IF_AP_BSS or WPA_IF_STATION
 * Returns: 0 on success, -1 on failure
 *
 * Use a role-specific interface name derived from the session ID so concurrent
 * sessions use distinct netdevs: nan-ap<id> for the AP role and nan-sta<id> for
 * the STA role. On success, record the interface name, address, and type in the
 * session for wpas_idp_init_interface() to initialize.
 */
int wpas_idp_add_interface(struct wpa_supplicant *wpa_s,
			   struct wpas_idp_session *session,
			   enum wpa_driver_if_type type)
{
	char ifname[IFNAMSIZ];
	char force_name[IFNAMSIZ] = "";
	u8 if_addr[ETH_ALEN];
	int res;

	if (!wpa_s || !session) {
		wpa_printf(MSG_ERROR,
			   "IDP: Invalid parameters for interface creation");
		return -1;
	}

	if (type == WPA_IF_AP_BSS)
		res = os_snprintf(ifname, sizeof(ifname), "nan-ap%u",
				  session->id);
	else
		res = os_snprintf(ifname, sizeof(ifname), "nan-sta%u",
				  session->id);
	if (os_snprintf_error(sizeof(ifname), res)) {
		wpa_printf(MSG_ERROR,
			   "IDP: Interface name too long for session %u",
			   session->id);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "IDP: Creating interface %s (type=%d)",
		   ifname, type);

	if (wpa_drv_if_add(wpa_s, type, ifname, NULL, NULL, force_name,
			   if_addr, NULL) < 0) {
		wpa_printf(MSG_ERROR, "IDP: Failed to create interface %s",
			   ifname);
		return -1;
	}

	os_strlcpy(session->pending_iface_name, ifname,
		   sizeof(session->pending_iface_name));
	os_memcpy(session->pending_iface_addr, if_addr, ETH_ALEN);
	session->pending_iface_type = type;

	wpa_printf(MSG_DEBUG, "IDP: Created interface %s addr=" MACSTR,
		   ifname, MAC2STR(session->pending_iface_addr));

	return 0;
}


/**
 * wpas_idp_init_interface - Register the IDP interface with wpa_supplicant
 * @wpa_s: wpa_supplicant structure
 * @session: IDP session
 * Returns: New wpa_supplicant instance, or NULL on failure
 *
 * Attach a wpa_supplicant instance to the netdev created by
 * wpas_idp_add_interface() and record the interface details in the
 * session.
 */
struct wpa_supplicant *
wpas_idp_init_interface(struct wpa_supplicant *wpa_s,
			struct wpas_idp_session *session)
{
	struct wpa_supplicant *iface_wpa_s;
	struct wpa_interface iface;

	if (!wpa_s || !session || !session->pending_iface_name[0]) {
		wpa_printf(MSG_ERROR,
			   "IDP: Invalid parameters for interface init");
		return NULL;
	}

	wpa_printf(MSG_DEBUG, "IDP: Initializing interface %s",
		   session->pending_iface_name);

	os_memset(&iface, 0, sizeof(iface));
	iface.ifname = session->pending_iface_name;
	iface.driver = wpa_s->driver->name;
	iface.ctrl_interface = wpa_s->conf->ctrl_interface;
	iface.driver_param = wpa_s->conf->driver_param;

	iface_wpa_s = wpa_supplicant_add_iface(wpa_s->global, &iface, wpa_s);
	if (!iface_wpa_s) {
		wpa_printf(MSG_ERROR, "IDP: Failed to initialize interface %s",
			   session->pending_iface_name);
		return NULL;
	}

	session->group_wpa_s = iface_wpa_s;
	os_strlcpy(session->iface_name, session->pending_iface_name,
		   sizeof(session->iface_name));
	os_memcpy(session->iface_addr, session->pending_iface_addr, ETH_ALEN);
	session->pending_iface_name[0] = '\0';
	os_memset(session->pending_iface_addr, 0, ETH_ALEN);

	wpa_printf(MSG_DEBUG, "IDP: Initialized interface %s addr=" MACSTR,
		   session->iface_name, MAC2STR(session->iface_addr));

	return iface_wpa_s;
}


/**
 * wpas_idp_remove_interface - Tear down the IDP virtual interface
 * @wpa_s: wpa_supplicant structure
 * @session: IDP session
 *
 * Remove the wpa_supplicant interface before removing the
 * corresponding driver interface.
 */
void wpas_idp_remove_interface(struct wpa_supplicant *wpa_s,
			       struct wpas_idp_session *session)
{
	enum wpa_driver_if_type type;
	char ifname[IFNAMSIZ];

	if (!wpa_s || !session || !session->group_wpa_s ||
	    !session->iface_name[0])
		return;

	wpa_printf(MSG_DEBUG, "IDP: Removing interface %s",
		   session->iface_name);

	type = session->pending_iface_type;
	os_strlcpy(ifname, session->iface_name, sizeof(ifname));

	wpa_supplicant_remove_iface(wpa_s->global, session->group_wpa_s, 0);
	session->group_wpa_s = NULL;

	wpa_drv_if_remove(wpa_s, type, ifname);

	session->iface_name[0] = '\0';
	os_memset(session->iface_addr, 0, ETH_ALEN);
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


/**
 * idp_session_for_iface - Find the IDP session running on an interface
 * @wpa_s: Interface an event arrived on
 * Returns: Matching session, or NULL if the interface carries none
 *
 * Sessions are identified by the interface on which they operate. When multiple
 * sessions share an interface, use the reported BSSID to select the correct
 * session.
 */
static struct wpas_idp_session *
idp_session_for_iface(struct wpa_supplicant *wpa_s)
{
	struct wpas_idp_info *idp = wpa_s->global->idp;
	struct wpas_idp_session *session, *match = NULL;

	if (!idp)
		return NULL;

	dl_list_for_each(session, &idp->sessions, struct wpas_idp_session,
			 list) {
		if (session->group_wpa_s != wpa_s)
			continue;
		if (!is_zero_ether_addr(wpa_s->bssid) &&
		    ether_addr_equal(wpa_s->bssid, session->bssid))
			return session;
		if (!match)
			match = session;
	}

	return match;
}


/**
 * wpas_idp_event - Drive IDP sessions from wpa_supplicant events
 * @wpa_s: Interface the event arrived on
 * @event: Event type
 *
 * Once configured, an IDP behaves as a normal infrastructure BSS. Association
 * and disconnection events are therefore used to track when the session comes
 * up and when it terminates.
 */
void wpas_idp_event(struct wpa_supplicant *wpa_s, enum wpa_event_type event)
{
	struct wpas_idp_session *session;

	if (!wpa_s->global->idp)
		return;

	session = idp_session_for_iface(wpa_s);
	if (!session)
		return;

	switch (event) {
	case EVENT_ASSOC:
		/*
		 * Only the STA learns that the link is up through an
		 * association event. The AP reports link establishment during
		 * its own setup, and peer associations are handled separately.
		 */
		if (session->role != WPAS_IDP_ROLE_STA)
			break;

		/*
		 * Report session establishment only for the association
		 * that brings the link up.
		 */
		if (session->state != IDP_STATE_CONFIGURING_STA)
			break;

		wpas_idp_state_machine(session, IDP_EVENT_STA_CONNECTED);

		wpa_printf(MSG_DEBUG, "IDP: Session %u: STA associated to "
			   MACSTR, session->id, MAC2STR(wpa_s->bssid));

		wpas_notify_idp_established(session->wpa_s, "sta",
					    session->peer_addr, wpa_s->bssid);
		break;
	case EVENT_DISASSOC:
	case EVENT_DEAUTH:
		wpa_printf(MSG_DEBUG, "IDP: Session %u: link lost",
			   session->id);
		wpas_idp_state_machine(session, IDP_EVENT_DISCONNECTED);
		break;
	default:
		break;
	}
}


/**
 * wpas_idp_request - Request an IDP connection with a discovered NAN peer
 * @wpa_s: Interface holding the NAN context
 * @peer_addr: Peer NAN management interface address
 * @role: Role this device takes in the connection
 * @handle: NAN service handle the peer was discovered through, or 0
 * @instance_id: Peer service instance ID, or 0 if not known
 * @freq: Frequency in MHz to bring the AP up on, or 0 to select a default
 * @discoverable: Whether the AP advertises its SSID in Beacon frames
 * Returns: 0 on success, -1 on failure
 *
 * @freq and @discoverable apply only to the AP role.
 */
int wpas_idp_request(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
		     enum wpas_idp_role role, int handle, u8 instance_id,
		     int freq, bool discoverable)
{
	struct wpas_idp_session *session;
	int peer_freq;

	if (!wpa_s->global->idp) {
		wpa_printf(MSG_ERROR, "IDP: Not initialized");
		return -1;
	}

	/*
	 * A session for this peer is reused so that a repeated request does
	 * not accumulate sessions, but only while it is idle. Restarting the
	 * handshake on a session that already has a link, or is in the middle
	 * of setting one up, would rewrite the role and channel that link is
	 * running on.
	 */
	session = wpas_idp_get_session_by_peer(wpa_s, peer_addr);
	if (session && session->state != IDP_STATE_NONE) {
		wpa_printf(MSG_INFO, "IDP: Session %u with " MACSTR
			   " is busy in state %d", session->id,
			   MAC2STR(peer_addr), session->state);
		return -1;
	}

	if (!session) {
		session = wpas_idp_alloc_session(wpa_s, peer_addr, role);
		if (!session)
			return -1;
	} else {
		session->role = role;
	}

	session->handle = handle;
	session->peer_instance_id = instance_id;

	if (role == WPAS_IDP_ROLE_AP) {
		if (idp_generate_ssid(session) < 0) {
			wpas_idp_free_session(session);
			return -1;
		}

		idp_get_country_string(wpa_s, session->channel.country_string);

		session->idp_session_id = idp_assign_session_id(session);
		session->discoverable = discoverable;

		if (idp_set_channel_from_freq(session, freq) < 0 &&
		    idp_select_default_channel(session) < 0) {
			wpas_idp_free_session(session);
			return -1;
		}
	}

	wpas_idp_state_machine(session, IDP_EVENT_INIT);

	/*
	 * A peer discovered over NAN listens on the channel on which its
	 * service discovery frame was last received, so send PASN M1 there.
	 */
	peer_freq = nan_peer_get_freq(wpa_s->nan, peer_addr);
	if (wpas_idp_pasn_auth_start(wpa_s, peer_addr, peer_freq) < 0) {
		wpa_printf(MSG_INFO, "IDP: Failed to start PASN with " MACSTR
			   " on %d MHz",
			   MAC2STR(peer_addr), peer_freq);
		wpas_idp_state_machine(session, IDP_EVENT_FAILURE);
		return -1;
	}

	return 0;
}


/**
 * wpas_idp_response - Accept or reject a held IDP request from a peer
 * @wpa_s: Interface holding the NAN context
 * @peer_addr: Peer NAN management interface address
 * @accept: Whether to accept the request
 * @handle: Local NAN service handle, or 0 to keep the one the request matched
 * @freq: Frequency in MHz to bring the AP up on, or 0 to keep the one the peer
 *	proposed
 * @discoverable: 1 or 0 to set whether the AP advertises its SSID in Beacon
 *	frames, or -1 to leave it unchanged
 * Returns: 0 on success, -1 on failure
 *
 * @freq and @discoverable apply only when this device takes the AP role.
 */
int wpas_idp_response(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
		      bool accept, int handle, int freq, int discoverable)
{
	struct wpas_idp_pending_request *pending;
	struct wpas_idp_session *session;
	int ret;

	if (!wpa_s->global->idp) {
		wpa_printf(MSG_ERROR, "IDP: Not initialized");
		return -1;
	}

	pending = wpas_idp_get_pending_request_by_peer(wpa_s, peer_addr);
	if (!pending) {
		wpa_printf(MSG_INFO, "IDP: No request pending from " MACSTR,
			   MAC2STR(peer_addr));
		return -1;
	}

	if (!accept) {
		wpa_printf(MSG_DEBUG, "IDP: Rejecting request from " MACSTR,
			   MAC2STR(peer_addr));
		wpas_idp_pasn_send_reject(wpa_s, peer_addr, pending->m1_frame);
		wpas_idp_free_pending_request(pending);
		return 0;
	}

	session = wpas_idp_alloc_session(wpa_s, peer_addr,
					 pending->proposed_role);
	if (!session) {
		wpa_printf(MSG_INFO,
			   "IDP: No session available for " MACSTR,
			   MAC2STR(peer_addr));
		wpas_idp_pasn_send_reject(wpa_s, peer_addr, pending->m1_frame);
		wpas_idp_free_pending_request(pending);
		return -1;
	}

	/*
	 * An explicit handle names the local service this link belongs to.
	 * Without one the session inherits the handle the peer's request was
	 * matched against.
	 */
	session->handle = handle > 0 ? handle : pending->handle;

	if (discoverable >= 0)
		session->discoverable = discoverable != 0;

	if (session->role == WPAS_IDP_ROLE_AP)
		idp_set_channel_from_freq(session, freq);

	wpa_printf(MSG_DEBUG, "IDP: Accepting request from " MACSTR
		   " as session %u role=%s", MAC2STR(peer_addr), session->id,
		   session->role == WPAS_IDP_ROLE_AP ? "ap" : "sta");

	ret = wpas_idp_pasn_resume_m1(wpa_s, session, pending->m1_frame,
				      pending->freq);
	wpas_idp_free_pending_request(pending);

	/*
	 * A session still in NONE never started, so there is nothing for
	 * termination to tear down and it would otherwise sit in the list
	 * forever.  Anything further along has already been moved on to
	 * TERMINATING by the resume path.
	 */
	if (ret < 0 && session->state == IDP_STATE_NONE)
		wpas_idp_free_session(session);

	return ret;
}


static const char * idp_role_str(enum wpas_idp_role role)
{
	switch (role) {
	case WPAS_IDP_ROLE_AP:
		return "ap";
	case WPAS_IDP_ROLE_STA:
		return "sta";
	}

	return "unknown";
}


static const char * idp_state_str(enum idp_state state)
{
	switch (state) {
	case IDP_STATE_NONE:
		return "IDLE";
	case IDP_STATE_NEGOTIATING:
		return "NEGOTIATION_IN_PROGRESS";
	case IDP_STATE_NEGOTIATED:
		return "NEGOTIATION_DONE";
	case IDP_STATE_CONFIGURING_AP:
		return "CONFIGURING_AP";
	case IDP_STATE_CONFIGURING_STA:
		return "CONFIGURING_STA";
	case IDP_STATE_ACTIVE_AP:
		return "ACTIVE_AP";
	case IDP_STATE_ACTIVE_STA:
		return "ACTIVE_STA";
	case IDP_STATE_PEER_CONNECTED:
		return "PEER_CONNECTED";
	case IDP_STATE_TERMINATING:
		return "TERMINATING";
	case IDP_STATE_TERM_WAIT_RESP:
		return "TERMINATING_WAIT_RESP";
	case IDP_STATE_TERM_WAIT_CONFIRM:
		return "TERMINATING_WAIT_CONFIRM";
	}

	return "UNKNOWN";
}


/**
 * wpas_idp_list - Write a listing of the IDP sessions
 * @wpa_s: Interface holding the NAN context
 * @buf: Reply buffer
 * @buflen: Size of @buf
 * Returns: Number of octets written to @buf
 *
 * Report all IDP sessions with their peer, local role, and current state. Since
 * sessions are global, the same listing is returned on every interface.
 */
int wpas_idp_list(struct wpa_supplicant *wpa_s, char *buf, size_t buflen)
{
	struct wpas_idp_session *session;
	size_t len;
	int ret;

	if (!wpa_s->global->idp)
		return 0;

	ret = os_snprintf(buf, buflen, "id peer role state idp_session_id\n");
	if (os_snprintf_error(buflen, ret))
		return 0;
	len = ret;

	dl_list_for_each(session, &wpa_s->global->idp->sessions,
			 struct wpas_idp_session, list) {
		ret = os_snprintf(buf + len, buflen - len,
				  "%u " MACSTR " %s %s %u\n",
				  session->id, MAC2STR(session->peer_addr),
				  idp_role_str(session->role),
				  idp_state_str(session->state),
				  session->idp_session_id);
		if (os_snprintf_error(buflen - len, ret))
			return len;
		len += ret;
	}

	return len;
}


/**
 * wpas_idp_flush - Drop every IDP session and held request
 * @wpa_s: Interface holding the NAN context
 * Returns: 0
 *
 * Remove all IDP sessions and pending requests without notifying peers.
 * Intended for local cleanup and testing rather than normal session
 * termination.
 */
int wpas_idp_flush(struct wpa_supplicant *wpa_s)
{
	struct wpas_idp_info *idp = wpa_s->global->idp;
	struct wpas_idp_session *session, *stmp;
	struct wpas_idp_pending_request *req, *rtmp;
	unsigned int sessions = 0, requests = 0;

	if (!idp)
		return 0;

	dl_list_for_each_safe(session, stmp, &idp->sessions,
			      struct wpas_idp_session, list) {
		wpas_idp_remove_interface(wpa_s, session);
		wpas_idp_free_session(session);
		sessions++;
	}

	dl_list_for_each_safe(req, rtmp, &idp->pending_requests,
			      struct wpas_idp_pending_request, list) {
		wpas_idp_free_pending_request(req);
		requests++;
	}

	wpa_printf(MSG_DEBUG,
		   "IDP: Flushed %u session(s) and %u held request(s)",
		   sessions, requests);

	return 0;
}


#ifdef CONFIG_TESTING_OPTIONS
/**
 * wpas_idp_get_nd_pmk - Write the ND-PMK held for a peer as hex
 * @wpa_s: Interface holding the NAN context
 * @peer_addr: Peer NAN management interface address
 * @buf: Reply buffer
 * @buflen: Size of @buf
 * Returns: Number of octets written to @buf, or -1 on failure
 *
 * The ND-PMK is what a NAN data path set up over this link is keyed from, and
 * the component establishing it is not this one, so a test needs a way to read
 * it back out. Exposing keys is for testing only.
 */
int wpas_idp_get_nd_pmk(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
			char *buf, size_t buflen)
{
	struct wpas_idp_session *session;

	if (!wpa_s->global->idp)
		return -1;

	session = wpas_idp_get_session_by_peer(wpa_s, peer_addr);
	if (!session || !session->nd_pmk_valid) {
		wpa_printf(MSG_DEBUG, "IDP: No ND-PMK held for " MACSTR,
			   MAC2STR(peer_addr));
		return -1;
	}

	return wpa_snprintf_hex(buf, buflen, session->nd_pmk, PMK_LEN);
}
#endif /* CONFIG_TESTING_OPTIONS */


/**
 * idp_find_active_ap_session - Find the session whose IDP AP is up
 *
 * Only one AP is brought up at a time, so the first match is the AP this device
 * is running.
 */
static struct wpas_idp_session *
idp_find_active_ap_session(struct wpa_supplicant *wpa_s)
{
	struct wpas_idp_session *session;

	dl_list_for_each(session, &wpa_s->global->idp->sessions,
			 struct wpas_idp_session, list) {
		if (session->role != WPAS_IDP_ROLE_AP)
			continue;
		/*
		 * A peer having joined does not stop the AP, and further
		 * peers can still be told about it.
		 */
		if (session->state == IDP_STATE_ACTIVE_AP ||
		    session->state == IDP_STATE_PEER_CONNECTED)
			return session;
	}

	return NULL;
}


/**
 * wpas_idp_add_sdf_info_attr - Advertise a running IDP AP in a NAN SDF
 * @wpa_s: Interface publishing the service
 * @buf: Attribute buffer of the frame being built
 *
 * Advertise infrastructure connectivity and the operating channel in
 * service discovery so a peer can determine whether and how to start
 * an IDP session.
 *
 * Omit the attribute if there is insufficient space in the frame.
 */
void wpas_idp_add_sdf_info_attr(struct wpa_supplicant *wpa_s,
				struct wpabuf *buf)
{
	struct wpas_idp_session *session;
	struct wpabuf *attr;
	bool with_channel;

	if (!wpa_s->global->idp)
		return;

	session = idp_find_active_ap_session(wpa_s);
	if (!session)
		return;

	with_channel = session->channel.channel_number != 0;
	attr = idp_build_idp_information_attr(session, with_channel);
	if (!attr)
		return;

	if (wpabuf_tailroom(buf) < wpabuf_len(attr)) {
		wpa_printf(MSG_DEBUG,
			   "IDP: No room in SDF for IDP Information attribute");
	} else {
		wpabuf_put_buf(buf, attr);
	}

	wpabuf_free(attr);
}


/**
 * wpas_idp_sta_authorized - Indicate that a peer has joined the IDP AP
 * @wpa_s: Interface the AP is running on
 * @sta_mac: Address the peer joined with
 *
 * The AP side of an IDP link has no association of its own to report, so a
 * peer completing its own is what tells this device the data path is carrying
 * traffic. This is called from the AP's station authorization callback.
 */
void wpas_idp_sta_authorized(struct wpa_supplicant *wpa_s, const u8 *sta_mac)
{
	struct wpas_idp_session *session;

	if (!wpa_s->global->idp)
		return;

	dl_list_for_each(session, &wpa_s->global->idp->sessions,
			 struct wpas_idp_session, list) {
		if (session->group_wpa_s != wpa_s ||
		    session->role != WPAS_IDP_ROLE_AP ||
		    session->state != IDP_STATE_ACTIVE_AP)
			continue;

		wpa_printf(MSG_DEBUG,
			   "IDP: Session %u: peer joined AP as " MACSTR,
			   session->id, MAC2STR(sta_mac));

		os_memcpy(session->connected_sta_mac_addr, sta_mac, ETH_ALEN);
		wpas_idp_state_machine(session, IDP_EVENT_PEER_CONNECTED);
		return;
	}
}


/**
 * idp_complete_termination - Tear the session down and report it has terminated
 *
 * This is called when the termination exchange completes or times out.
 */
static void idp_complete_termination(struct wpas_idp_session *session)
{
	struct wpa_supplicant *wpa_s;

	if (!session || session->termination_completed)
		return;
	session->termination_completed = true;

	wpa_s = session->wpa_s;

	wpa_printf(MSG_DEBUG, "IDP: Session %u: tearing down link with " MACSTR,
		   session->id, MAC2STR(session->peer_addr));

	if (session->role == WPAS_IDP_ROLE_AP && session->pmkid_valid &&
	    session->group_wpa_s && session->group_wpa_s->ap_iface &&
	    session->group_wpa_s->ap_iface->num_bss > 0) {
		struct hostapd_data *hapd =
			session->group_wpa_s->ap_iface->bss[0];

		wpa_auth_pmksa_remove_pmkid(hapd->wpa_auth, session->pmkid);
	}

	eloop_cancel_timeout(idp_termination_timeout, session, NULL);
	eloop_cancel_timeout(idp_term_response_tx_done, session, NULL);
	eloop_cancel_timeout(idp_failure_teardown, session, NULL);
	eloop_cancel_timeout(idp_term_request_timeout, session, NULL);

	wpas_idp_pasn_deinit(session->pasn_ctx);
	session->pasn_ctx = NULL;

	if (session->role == WPAS_IDP_ROLE_AP) {
		if (session->group_wpa_s)
			wpa_supplicant_ap_deinit(session->group_wpa_s);
	} else if (session->group_wpa_s) {
		/*
		 * Disconnect before removing the interface to allow the peer
		 * AP to observe normal link termination. This is safe even if
		 * the session never established a connection.
		 */
		wpa_supplicant_deauthenticate(session->group_wpa_s,
					      WLAN_REASON_DEAUTH_LEAVING);
	}

	/*
	 * Remove the session-specific network profile. Retaining it would
	 * leave stale configuration for a peer that is no longer connected.
	 */
	if (session->network_id >= 0 && session->group_wpa_s) {
		if (wpa_config_remove_network(session->group_wpa_s->conf,
					      session->network_id) < 0)
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: network %d already gone",
				   session->id, session->network_id);
		session->network_id = -1;
	}

	if (session->group_wpa_s && session->iface_name[0]) {
		wpas_idp_remove_interface(wpa_s, session);
	} else if (session->pending_iface_name[0]) {
		/*
		 * An interface created but never handed to wpa_supplicant is
		 * only known to the driver, so it has to be removed there.
		 */
		wpa_drv_if_remove(wpa_s, session->pending_iface_type,
				  session->pending_iface_name);
		session->pending_iface_name[0] = '\0';
	}

	wpa_msg(wpa_s, MSG_INFO,
		IDP_EVENT_TERMINATED "session=%u peer=" MACSTR " reason=%d",
		session->id, MAC2STR(session->peer_addr),
		session->termination.reason);

	wpas_idp_free_session(session);
}


/*
 * idp_termination_timeout - Give up waiting for the peer to answer
 *
 * The peer may be gone, or may never have heard the request. Either way the
 * local side of the link cannot be left standing, so it is torn down.
 */
static void idp_termination_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpas_idp_session *session = eloop_ctx;

	wpa_printf(MSG_INFO, "IDP: Session %u: peer " MACSTR
		   " did not answer the termination exchange",
		   session->id, MAC2STR(session->peer_addr));

	session->termination.reason = IDP_TERM_REASON_TIMEOUT;
	wpas_idp_state_machine(session, IDP_EVENT_TERM_TIMEOUT);
	idp_complete_termination(session);
}


/*
 * idp_term_response_tx_done - Tear down after the response has gone out
 *
 * A 2-way response sent on the data path interface has to leave the device
 * before that interface is removed, and nothing reports when that has happened,
 * so teardown waits a short while for it.
 */
static void idp_term_response_tx_done(void *eloop_ctx, void *timeout_ctx)
{
	struct wpas_idp_session *session = eloop_ctx;

	wpa_printf(MSG_DEBUG,
		   "IDP: Session %u: response transmit window expired",
		   session->id);

	session->termination.wait_idp_tx = false;
	idp_complete_termination(session);
}


/*
 * idp_failure_teardown - Remove a session whose setup failed
 *
 * A session that fails during negotiation or during AP or STA setup has no
 * link to terminate with the peer, so it is torn down locally. This frees the
 * session and its interface and allows a new request with the same peer. The
 * teardown is run from the event loop since the failure is reported from
 * handlers that still use the session.
 */
static void idp_failure_teardown(void *eloop_ctx, void *timeout_ctx)
{
	struct wpas_idp_session *session = eloop_ctx;

	wpa_printf(MSG_DEBUG, "IDP: Session %u: setup failed, tearing down",
		   session->id);

	session->termination.reason = IDP_TERM_REASON_FAILURE;
	idp_complete_termination(session);
}


/* Build the IDP Termination attribute */
static struct wpabuf *
idp_build_termination_attr(struct wpas_idp_session *session,
			   enum nan_idp_term_type type,
			   enum nan_idp_term_status status,
			   u8 handshake_mode, bool ndp_transition)
{
	struct wpabuf *buf;
	u8 type_status, term_info = 0;

	/* Attr ID(1) + Length(2) + Type/Status(1) + Session ID(1) + Info(1) */
	buf = wpabuf_alloc(NAN_ATTR_HDR_LEN + 3);
	if (!buf)
		return NULL;

	wpabuf_put_u8(buf, NAN_ATTR_IDP_TERMINATION);
	wpabuf_put_le16(buf, 3);

	type_status = type | (status << NAN_IDP_TERM_STATUS_POS);
	wpabuf_put_u8(buf, type_status);

	wpabuf_put_u8(buf, session->idp_session_id);

	if (handshake_mode == 3)
		term_info |= NAN_IDP_TERM_INFO_3_WAY;
	if (ndp_transition)
		term_info |= NAN_IDP_TERM_INFO_NDP_TRANSITION;
	wpabuf_put_u8(buf, term_info);

	return buf;
}


/*
 * idp_send_termination_naf - Send a termination attribute in NAF
 *
 * Send the termination indication over both the IDP data path and NAN
 * management path. Since either path may already be unavailable, successful
 * delivery on either is sufficient.
 */
static int idp_send_termination_naf(struct wpas_idp_session *session,
				    const struct wpabuf *payload)
{
	struct wpa_supplicant *wpa_s = session->wpa_s;
	struct wpabuf *naf;
	const u8 *cluster_id;
	int ret = -1, nmi_ret;

	if (!wpa_s->nan) {
		wpa_printf(MSG_ERROR, "IDP: NAN is not running");
		return -1;
	}

	/* Category(1) + Action(1) + OUI(3) + OUI Type(1) + Subtype(1) */
	naf = wpabuf_alloc(7 + wpabuf_len(payload));
	if (!naf)
		return -1;

	wpabuf_put_u8(naf, WLAN_ACTION_PUBLIC);
	wpabuf_put_u8(naf, WLAN_PA_VENDOR_SPECIFIC);
	wpabuf_put_be24(naf, OUI_WFA);
	wpabuf_put_u8(naf, NAN_NAF_OUI_TYPE);
	wpabuf_put_u8(naf, NAN_SUBTYPE_IDP_TERMINATE);
	wpabuf_put_buf(naf, payload);

	cluster_id = nan_get_cluster_id(wpa_s->nan);

	if (session->group_wpa_s && session->group_wpa_s != wpa_s &&
	    !is_zero_ether_addr(session->iface_addr)) {
		const u8 *peer = wpas_idp_get_peer_idp_addr(session);
		u8 op_class = session->channel.operating_class;
		u8 channel = session->channel.channel_number;
		int freq = session->group_wpa_s->assoc_freq;

		if (!freq && op_class && channel)
			freq = ieee80211_chan_to_freq(NULL, op_class, channel);

		ret = wpa_drv_send_action(session->group_wpa_s, freq, 0,
					  peer ? peer : session->peer_addr,
					  session->iface_addr, cluster_id,
					  wpabuf_head(naf), wpabuf_len(naf), 1);
		if (ret < 0)
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: termination not sent on the data path",
				   session->id);
	}

	nmi_ret = nan_send_peer_naf(wpa_s->nan, session->peer_addr, naf);
	if (nmi_ret < 0)
		wpa_printf(MSG_DEBUG,
			   "IDP: Session %u: termination not sent on the management interface",
			   session->id);
	if (ret < 0)
		ret = nmi_ret;

	wpabuf_free(naf);

	return ret;
}


/**
 * wpas_idp_initiate_termination - Start tearing an IDP link down
 * @session: Session to terminate
 * @reason: Why the link is being torn down
 * @handshake_mode: 2 for request and response, 3 to also expect a confirm
 * @ndp_transition: Whether a NAN data path takes over from this link
 * Returns: 0 if the request was sent, -1 otherwise
 *
 * Request termination of the IDP session and wait for the peer's response.
 * If no response is received, the timeout handler completes local session
 * teardown.
 */
static int
wpas_idp_initiate_termination(struct wpas_idp_session *session,
			      enum wpas_idp_termination_reason reason,
			      u8 handshake_mode, bool ndp_transition)
{
	struct wpabuf *frame;
	int ret;

	if (session->termination.termination_in_progress) {
		wpa_printf(MSG_INFO, "IDP: Session %u is already terminating",
			   session->id);
		return -1;
	}

	if (handshake_mode != 2 && handshake_mode != 3) {
		wpa_printf(MSG_INFO, "IDP: Handshake mode must be 2 or 3");
		return -1;
	}

	if (session->state != IDP_STATE_ACTIVE_AP &&
	    session->state != IDP_STATE_ACTIVE_STA &&
	    session->state != IDP_STATE_PEER_CONNECTED) {
		wpa_printf(MSG_INFO,
			   "IDP: Session %u has no link to terminate (state %d)",
			   session->id, session->state);
		return -1;
	}

	os_memset(&session->termination, 0, sizeof(session->termination));
	session->termination.termination_in_progress = true;
	session->termination.is_initiator = true;
	session->termination.reason = reason;
	session->termination.handshake_mode = handshake_mode;
	session->termination.ndp_transition = ndp_transition;
	session->termination.expected_response = NAN_IDP_TERM_TYPE_RESPONSE;
	os_get_reltime(&session->termination.request_time);

	frame = idp_build_termination_attr(session, NAN_IDP_TERM_TYPE_REQUEST,
					   NAN_IDP_TERM_STATUS_CONTINUED,
					   handshake_mode, ndp_transition);
	if (!frame)
		goto fail;

	ret = idp_send_termination_naf(session, frame);
	wpabuf_free(frame);
	if (ret < 0) {
		wpa_printf(MSG_INFO,
			   "IDP: Session %u: could not send the termination request",
			   session->id);
		goto fail;
	}

	wpa_printf(MSG_INFO,
		   "IDP: Session %u: asked " MACSTR
		   " to terminate (mode=%u ndp=%d reason=%d)",
		   session->id, MAC2STR(session->peer_addr), handshake_mode,
		   ndp_transition, reason);

	wpas_idp_state_machine(session, IDP_EVENT_TERM_INITIATED);
	eloop_register_timeout(IDP_TERM_RESPONSE_TIMEOUT_SEC, 0,
			       idp_termination_timeout, session, NULL);

	return 0;

fail:
	os_memset(&session->termination, 0, sizeof(session->termination));

	return -1;
}


/*
 * idp_parse_termination_attr - Parse an IDP Termination attribute body
 * @data: Attribute body, after the identifier and length
 * @len: Length of @data
 */
static int idp_parse_termination_attr(const u8 *data, size_t len,
				      enum nan_idp_term_type *type,
				      u8 *session_id, u8 *handshake_mode,
				      bool *ndp_transition)
{
	if (len < 3) {
		wpa_printf(MSG_DEBUG,
			   "IDP: Termination attribute is %zu octets, needs 3",
			   len);
		return -1;
	}

	*type = (enum nan_idp_term_type) (data[0] & NAN_IDP_TERM_TYPE_MASK);
	*session_id = data[1];
	*handshake_mode = (data[2] & NAN_IDP_TERM_INFO_3_WAY) ? 3 : 2;
	*ndp_transition = (data[2] & NAN_IDP_TERM_INFO_NDP_TRANSITION) != 0;

	return 0;
}


/*
 * idp_process_termination_response - The peer agreed to tear the link down
 *
 * In the three step form the peer is owed a confirm, which is sent before the
 * link goes away while there is still something to send it on.
 */
static int idp_process_termination_response(struct wpas_idp_session *session,
					    u8 handshake_mode)
{
	struct wpabuf *frame;

	if (!session->termination.termination_in_progress ||
	    !session->termination.is_initiator) {
		wpa_printf(MSG_DEBUG,
			   "IDP: Session %u did not ask for termination",
			   session->id);
		return -1;
	}

	wpa_printf(MSG_INFO, "IDP: Session %u: " MACSTR " agreed to terminate",
		   session->id, MAC2STR(session->peer_addr));

	eloop_cancel_timeout(idp_termination_timeout, session, NULL);

	if (handshake_mode == 3) {
		u8 mode = session->termination.handshake_mode;
		bool ndp = session->termination.ndp_transition;

		frame = idp_build_termination_attr(
			session, NAN_IDP_TERM_TYPE_CONFIRM,
			NAN_IDP_TERM_STATUS_CONTINUED, mode, ndp);
		if (!frame)
			return -1;

		if (idp_send_termination_naf(session, frame) < 0)
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: confirm not sent",
				   session->id);
		wpabuf_free(frame);
	}

	wpas_idp_state_machine(session, IDP_EVENT_TERM_RESPONSE_RX);
	idp_complete_termination(session);

	return 0;
}


/*
 * idp_term_response_accept - Agree to a peer's termination request
 *
 * Reached when termination is accepted or times out. The session is torn down
 * in either case. If the peer does not receive the termination message, it is
 * expected to time out and clean up its own state.
 */
static int idp_term_response_accept(struct wpas_idp_session *session)
{
	struct wpabuf *frame;
	u8 handshake_mode;
	int ret;

	if (!session->pending_termination)
		return -1;

	eloop_cancel_timeout(idp_term_request_timeout, session, NULL);

	handshake_mode = session->pending_termination->mode;
	os_free(session->pending_termination);
	session->pending_termination = NULL;

	frame = idp_build_termination_attr(session, NAN_IDP_TERM_TYPE_RESPONSE,
					   NAN_IDP_TERM_STATUS_ACCEPTED,
					   session->termination.handshake_mode,
					   session->termination.ndp_transition);
	if (!frame)
		goto tear_down;

	ret = idp_send_termination_naf(session, frame);
	wpabuf_free(frame);
	if (ret < 0) {
		wpa_printf(MSG_INFO,
			   "IDP: Session %u: could not agree to termination",
			   session->id);
		goto tear_down;
	}

	wpa_printf(MSG_INFO,
		   "IDP: Session %u: agreed to terminate with " MACSTR,
		   session->id, MAC2STR(session->peer_addr));

	wpas_idp_state_machine(session, IDP_EVENT_TERM_REQUEST_RX);

	if (handshake_mode == 3) {
		session->termination.expected_response =
			NAN_IDP_TERM_TYPE_CONFIRM;
		eloop_register_timeout(IDP_TERM_RESPONSE_TIMEOUT_SEC, 0,
				       idp_termination_timeout, session, NULL);
		return 0;
	}

	/*
	 * Delay interface teardown briefly to allow the termination
	 * acknowledgment to be transmitted. Since there is no indication of
	 * when transmission completes, a short delay is used.
	 */
	if (session->group_wpa_s && session->group_wpa_s != session->wpa_s &&
	    !is_zero_ether_addr(session->iface_addr)) {
		session->termination.wait_idp_tx = true;
		eloop_register_timeout(0, 100000, idp_term_response_tx_done,
				       session, NULL);
		return 0;
	}

	idp_complete_termination(session);

	return 0;

tear_down:
	idp_complete_termination(session);

	return -1;
}


/*
 * idp_term_response_reject - Refuse a peer's termination request
 * @session: Session whose peer asked for termination
 * Returns: 0 on success, -1 if the refusal could not be built or sent
 *
 * The data path stays up, so the peer has to be told rather than left to
 * decide for itself when the silence has gone on long enough. The session
 * returns to the state it was in before the request arrived.
 */
static int idp_term_response_reject(struct wpas_idp_session *session)
{
	struct wpabuf *frame;
	int ret;

	if (!session->pending_termination)
		return -1;

	eloop_cancel_timeout(idp_term_request_timeout, session, NULL);

	frame = idp_build_termination_attr(session, NAN_IDP_TERM_TYPE_RESPONSE,
					   NAN_IDP_TERM_STATUS_REJECTED,
					   session->termination.handshake_mode,
					   session->termination.ndp_transition);

	os_free(session->pending_termination);
	session->pending_termination = NULL;
	os_memset(&session->termination, 0, sizeof(session->termination));

	if (!frame)
		return -1;

	ret = idp_send_termination_naf(session, frame);
	wpabuf_free(frame);
	if (ret < 0) {
		wpa_printf(MSG_INFO,
			   "IDP: Session %u: could not refuse termination",
			   session->id);
		return -1;
	}

	wpa_printf(MSG_INFO,
		   "IDP: Session %u: refused " MACSTR "'s termination request",
		   session->id, MAC2STR(session->peer_addr));

	return 0;
}


/*
 * idp_term_request_timeout - The operator did not answer the peer in time
 *
 * If the peer does not respond after requesting termination, treat the timeout
 * as acceptance and complete local teardown.
 */
static void idp_term_request_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpas_idp_session *session = eloop_ctx;

	if (!session->pending_termination)
		return;

	wpa_printf(MSG_INFO,
		   "IDP: Session %u: no response for termination request from "
		   MACSTR ", accepting it",
		   session->id, MAC2STR(session->peer_addr));

	idp_term_response_accept(session);
}


/*
 * idp_process_termination_request - Handle a peer termination request
 *
 * Hold the request for operator approval before responding. If no decision is
 * received within IDP_TERM_REQUEST_TIMEOUT_SEC, accept the request and proceed
 * with termination.
 */
static int idp_process_termination_request(struct wpas_idp_session *session,
					   u8 handshake_mode,
					   bool ndp_transition)
{
	struct wpas_idp_pending_termination *pending;
	enum wpas_idp_termination_reason reason;

	reason = IDP_TERM_REASON_USER_REQUEST;

	pending = os_zalloc(sizeof(*pending));
	if (!pending)
		return -1;

	wpa_printf(MSG_INFO, "IDP: Session %u: " MACSTR
		   " asked to terminate (mode=%u ndp=%d reason=%d)",
		   session->id, MAC2STR(session->peer_addr), handshake_mode,
		   ndp_transition, reason);

	session->termination.termination_in_progress = true;
	session->termination.is_initiator = false;
	session->termination.handshake_mode = handshake_mode;
	session->termination.ndp_transition = ndp_transition;
	session->termination.reason = reason;

	os_memcpy(pending->peer_addr, session->peer_addr, ETH_ALEN);
	pending->reason = reason;
	pending->mode = handshake_mode;
	pending->ndp = ndp_transition ? 1 : 0;
	pending->session_id = session->id;

	/*
	 * The same request arrives over both the data path and the management
	 * interface, so this can run twice for one request. Release anything
	 * already held and replace the wait rather than stacking a second one
	 * on top of it.
	 */
	os_free(session->pending_termination);
	session->pending_termination = pending;

	eloop_cancel_timeout(idp_term_request_timeout, session, NULL);
	eloop_register_timeout(IDP_TERM_REQUEST_TIMEOUT_SEC, 0,
			       idp_term_request_timeout, session, NULL);

	wpas_notify_idp_term_request(session->wpa_s, session->peer_addr,
				     session->id, pending->reason,
				     pending->mode, pending->ndp);

	return 0;
}


/*
 * idp_process_termination_confirm - Handle termination confirmation
 *
 * Process the final confirmation of a three-message termination exchange only
 * when the session is waiting for it. Ignore unsolicited confirmation frames.
 */
static int idp_process_termination_confirm(struct wpas_idp_session *session)
{
	if (!session->termination.termination_in_progress ||
	    session->termination.is_initiator ||
	    session->termination.expected_response !=
	    NAN_IDP_TERM_TYPE_CONFIRM) {
		wpa_printf(MSG_DEBUG,
			   "IDP: Session %u was not waiting for a termination confirm",
			   session->id);
		return -1;
	}

	wpa_printf(MSG_INFO,
		   "IDP: Session %u: " MACSTR " confirmed termination",
		   session->id, MAC2STR(session->peer_addr));

	eloop_cancel_timeout(idp_termination_timeout, session, NULL);
	wpas_idp_state_machine(session, IDP_EVENT_TERM_CONFIRM_RX);
	idp_complete_termination(session);

	return 0;
}


/*
 * idp_termination_rx - Act on a received IDP Termination attribute
 * @wpa_s: Interface the frame arrived on
 * @src: Address the frame came from
 * @attrs: Attribute area of the frame, past the Action frame header
 * @attrs_len: Length of @attrs
 *
 * The peer is identified by the address the frame came from, which may be
 * either its management interface or its end of the data path, because the
 * same frame is sent over both.
 */
static int idp_termination_rx(struct wpa_supplicant *wpa_s, const u8 *src,
			      const u8 *attrs, size_t attrs_len)
{
	struct wpas_idp_session *session;
	enum nan_idp_term_type type;
	u8 handshake_mode, session_id;
	bool ndp_transition;
	size_t attr_len;

	session = wpas_idp_get_session_by_peer(wpa_s, src);
	if (!session) {
		wpa_printf(MSG_DEBUG,
			   "IDP: No session for termination from " MACSTR,
			   MAC2STR(src));
		return -1;
	}

	/* The link is already going away; a further frame changes nothing */
	if (session->termination_completed)
		return 0;

	if (attrs_len < NAN_ATTR_HDR_LEN ||
	    attrs[0] != NAN_ATTR_IDP_TERMINATION)
		return -1;

	/*
	 * Compare the declared length against what is left rather than adding
	 * it to the position, so a length near the top of its range cannot
	 * carry the comparison past the end of the buffer.
	 */
	attr_len = WPA_GET_LE16(&attrs[1]);
	if (attr_len > attrs_len - NAN_ATTR_HDR_LEN) {
		wpa_printf(MSG_DEBUG,
			   "IDP: Termination attribute claims %zu of %zu octets",
			   attr_len, attrs_len - NAN_ATTR_HDR_LEN);
		return -1;
	}

	if (idp_parse_termination_attr(attrs + NAN_ATTR_HDR_LEN, attr_len,
				       &type, &session_id, &handshake_mode,
				       &ndp_transition) < 0)
		return -1;

	/*
	 * These frames are acted on before any of the link's own protection
	 * applies, so check that the one named is the one we have. A peer that
	 * never assigned an identifier sends zero, and the session then has
	 * nothing to compare against.
	 */
	if (session->idp_session_id && session_id &&
	    session_id != session->idp_session_id) {
		wpa_printf(MSG_DEBUG,
			   "IDP: Session %u: termination names IDP %u, not %u",
			   session->id, session_id, session->idp_session_id);
		return -1;
	}

	switch (type) {
	case NAN_IDP_TERM_TYPE_REQUEST:
		return idp_process_termination_request(session, handshake_mode,
						       ndp_transition);
	case NAN_IDP_TERM_TYPE_RESPONSE:
		return idp_process_termination_response(session,
							handshake_mode);
	case NAN_IDP_TERM_TYPE_CONFIRM:
		return idp_process_termination_confirm(session);
	default:
		wpa_printf(MSG_DEBUG,
			   "IDP: Session %u: nothing to do with termination step %u",
			   session->id, type);
		return -1;
	}
}


/**
 * wpas_idp_rx_action - Process IDP frames out of the NAF stream
 * @wpa_s: Interface the frame arrived on
 * @mgmt: The frame
 * @len: Length of @mgmt
 * Returns: 0 if the frame was an IDP frame and was consumed, -1 otherwise
 *
 * Termination is the only part of IDP carried as an Action frame; the PASN
 * exchange uses Authentication frames instead.
 */
int wpas_idp_rx_action(struct wpa_supplicant *wpa_s,
		       const struct ieee80211_mgmt *mgmt, size_t len)
{
	const u8 *payload;
	size_t payload_len;

	if (!wpa_s->global->idp || len <= IEEE80211_HDRLEN)
		return -1;

	payload = (const u8 *) &mgmt->u.action;
	payload_len = len - IEEE80211_HDRLEN;

	/* Category(1) + Action(1) + OUI(3) + OUI Type(1) + Subtype(1) */
	if (payload_len < 7 ||
	    payload[0] != WLAN_ACTION_PUBLIC ||
	    payload[1] != WLAN_PA_VENDOR_SPECIFIC ||
	    WPA_GET_BE24(&payload[2]) != OUI_WFA ||
	    payload[5] != NAN_NAF_OUI_TYPE ||
	    payload[6] != NAN_SUBTYPE_IDP_TERMINATE)
		return -1;

	idp_termination_rx(wpa_s, mgmt->sa, payload + 7, payload_len - 7);

	/*
	 * The frame was addressed to IDP, so it is consumed whether or not it
	 * could be acted on. Handing it to the NAN discovery engine as well
	 * would only have it rejected a second time.
	 */
	return 0;
}


/**
 * wpas_idp_terminate - Start tearing down the IDP link with a peer
 * @wpa_s: Interface holding the NAN context
 * @peer_addr: Peer NAN management interface address
 * @reason: Termination reason
 * @handshake_mode: 2 for a two-step exchange, 3 to also expect a confirm
 * @ndp_transition: Whether the link is giving way to a NAN data path
 * Returns: 0 on success, -1 on failure
 *
 * @handshake_mode selects whether the peer is also expected to confirm.
 * @ndp_transition says the link is giving way to a NAN data path rather than
 * simply terminating, which is something the peer may want to act on.
 */
int wpas_idp_terminate(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
		       enum wpas_idp_termination_reason reason,
		       u8 handshake_mode, bool ndp_transition)
{
	struct wpas_idp_session *session;

	if (!wpa_s->global->idp) {
		wpa_printf(MSG_INFO, "IDP: Not initialized");
		return -1;
	}

	session = wpas_idp_get_session_by_peer(wpa_s, peer_addr);
	if (!session) {
		wpa_printf(MSG_INFO, "IDP: No session with " MACSTR,
			   MAC2STR(peer_addr));
		return -1;
	}

	return wpas_idp_initiate_termination(session, reason, handshake_mode,
					    ndp_transition);
}


/**
 * wpas_idp_term_response - Answer a peer's IDP termination request
 * @wpa_s: Interface holding the NAN context
 * @peer_addr: Peer NAN management interface address
 * @accept: Whether to accept the termination
 * Returns: 0 on success, -1 on failure
 *
 * Repsond to the IDP-TERM-REQUEST event. Refusing keeps the link, but the peer
 * is under no obligation to keep its own side up, so a refusal is not a
 * guarantee the link survives.
 */
int wpas_idp_term_response(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
			   bool accept)
{
	struct wpas_idp_session *session;

	if (!wpa_s->global->idp) {
		wpa_printf(MSG_INFO, "IDP: Not initialized");
		return -1;
	}

	session = wpas_idp_get_session_by_peer(wpa_s, peer_addr);
	if (!session || !session->pending_termination) {
		wpa_printf(MSG_INFO,
			   "IDP: No termination request pending from " MACSTR,
			   MAC2STR(peer_addr));
		return -1;
	}

	if (accept)
		return idp_term_response_accept(session);

	return idp_term_response_reject(session);
}
