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
#include "ap/hostapd.h"
#include "ap/ap_drv_ops.h"
#include "ap/wpa_auth.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "ap.h"
#include "wpas_idp.h"


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
		} else if (event == IDP_EVENT_PASN_FAILED ||
			   event == IDP_EVENT_FAILURE) {
			session->state = IDP_STATE_TERMINATING;
			wpa_printf(MSG_DEBUG,
				   "IDP: Session %u: NEGOTIATING -> TERMINATING",
				   session->id);
			wpa_msg(session->wpa_s, MSG_INFO,
				IDP_EVENT_REJECTED "peer=" MACSTR " session=%u",
				MAC2STR(session->peer_addr), session->id);
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
