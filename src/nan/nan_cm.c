/*
 * Wi-Fi Aware - Connection Management
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "utils/eloop.h"
#include "nan_i.h"
#include "nan_cm.h"

/* Room for the NAF header and the Connection Management attributes */
#define NAN_CM_NAF_MAX_LEN 512


static bool nan_cm_same_ndi_pair(const struct nan_ndp *a,
				 const struct nan_ndp *b)
{
	return ether_addr_equal(a->init_ndi, b->init_ndi) &&
		ether_addr_equal(a->resp_ndi, b->resp_ndi);
}


/* Whether @ndp is the first NDP in the peer list using its NDI pair */
static bool nan_cm_first_ndp_of_pair(const struct nan_peer *peer,
				     const struct nan_ndp *ndp)
{
	struct nan_ndp *cur;

	dl_list_for_each(cur, &peer->ndps, struct nan_ndp, list) {
		if (cur == ndp)
			return true;
		if (nan_cm_same_ndi_pair(cur, ndp))
			return false;
	}

	return true;
}


int nan_cm_build_kaa(struct nan_peer *peer, struct wpabuf *buf)
{
	struct nan_ndp *ndp, *cur;
	u8 *len_ptr, *ctrl;
	unsigned int n_entries = 0;

	if (wpabuf_tailroom(buf) < NAN_ATTR_HDR_LEN + 1)
		goto fail;

	wpabuf_put_u8(buf, NAN_ATTR_KAA);
	len_ptr = wpabuf_put(buf, 2);
	ctrl = wpabuf_put(buf, 1);
	*ctrl = 0;

	/* One NDP list entry per NDI pair, listing all NDP IDs of the pair */
	dl_list_for_each(ndp, &peer->ndps, struct nan_ndp, list) {
		u8 *entry_len;

		if (!nan_cm_first_ndp_of_pair(peer, ndp))
			continue;

		if (wpabuf_tailroom(buf) < 1 + 2 * ETH_ALEN)
			goto fail;

		entry_len = wpabuf_put(buf, 1);
		*entry_len = 2 * ETH_ALEN;
		wpabuf_put_data(buf, ndp->init_ndi, ETH_ALEN);
		wpabuf_put_data(buf, ndp->resp_ndi, ETH_ALEN);

		dl_list_for_each(cur, &peer->ndps, struct nan_ndp, list) {
			if (!nan_cm_same_ndi_pair(cur, ndp))
				continue;

			if (*entry_len == 0xff || !wpabuf_tailroom(buf))
				goto fail;

			wpabuf_put_u8(buf, cur->ndp_id);
			(*entry_len)++;
		}

		wpa_printf(MSG_DEBUG,
			   "NAN CM: KAA entry init_ndi=" MACSTR " resp_ndi="
			   MACSTR " n_ndp_ids=%u",
			   MAC2STR(ndp->init_ndi), MAC2STR(ndp->resp_ndi),
			   *entry_len - 2 * ETH_ALEN);
		n_entries++;
	}

	if (n_entries)
		*ctrl |= NAN_KAA_CTRL_NDPS_PRESENT;

	WPA_PUT_LE16(len_ptr, (u8 *) wpabuf_put(buf, 0) - len_ptr - 2);

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Built KAA for peer " MACSTR
		   " ctrl=0x%02x n_entries=%u",
		   MAC2STR(peer->nmi_addr), *ctrl, n_entries);
	return 0;

fail:
	wpa_printf(MSG_INFO,
		   "NAN CM: No room for KAA for peer " MACSTR,
		   MAC2STR(peer->nmi_addr));
	return -1;
}


int nan_cm_parse_kaa(const u8 *data, size_t len, struct nan_cm_kaa *kaa)
{
	const u8 *pos = data;
	const u8 *end = data + len;

	os_memset(kaa, 0, sizeof(*kaa));

	if (len < 1) {
		wpa_printf(MSG_DEBUG, "NAN CM: KAA too short");
		return -1;
	}

	kaa->ndps_present = !!(*pos++ & NAN_KAA_CTRL_NDPS_PRESENT);
	if (!kaa->ndps_present) {
		wpa_printf(MSG_DEBUG, "NAN CM: Parsed KAA without NDP list");
		return 0;
	}

	if (pos == end) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: KAA NDP list indicated but empty");
		return -1;
	}

	while (pos < end) {
		struct nan_cm_kaa_entry *entry;
		u8 entry_len = *pos++;

		if (entry_len < 2 * ETH_ALEN || entry_len > end - pos) {
			wpa_printf(MSG_DEBUG,
				   "NAN CM: Invalid KAA NDP list entry length %u",
				   entry_len);
			return -1;
		}

		if (kaa->n_entries == NAN_CM_KAA_MAX_ENTRIES) {
			wpa_printf(MSG_DEBUG,
				   "NAN CM: Too many KAA NDP list entries");
			return -1;
		}

		entry = &kaa->entries[kaa->n_entries++];
		entry->init_ndi = pos;
		entry->resp_ndi = pos + ETH_ALEN;
		entry->ndp_ids = pos + 2 * ETH_ALEN;
		entry->n_ndp_ids = entry_len - 2 * ETH_ALEN;
		pos += entry_len;

		wpa_printf(MSG_DEBUG,
			   "NAN CM: KAA entry init_ndi=" MACSTR " resp_ndi="
			   MACSTR " n_ndp_ids=%u",
			   MAC2STR(entry->init_ndi), MAC2STR(entry->resp_ndi),
			   entry->n_ndp_ids);
	}

	wpa_printf(MSG_DEBUG, "NAN CM: Parsed KAA with %u NDP list entries",
		   kaa->n_entries);
	return 0;
}


int nan_cm_build_tna(struct wpabuf *buf, u8 ctrl, u8 reason,
		     const u8 *nd_tksa_ids, u8 n_nd_tksas)
{
	size_t len = 2;

	if (ctrl & NAN_TNA_CTRL_ND_TKSA_TERM)
		len += 1 + n_nd_tksas * NAN_ND_TKSA_IDENTITY_LEN;

	if (wpabuf_tailroom(buf) < NAN_ATTR_HDR_LEN + len) {
		wpa_printf(MSG_INFO, "NAN CM: No room for TNA");
		return -1;
	}

	wpabuf_put_u8(buf, NAN_ATTR_TNA);
	wpabuf_put_le16(buf, len);
	wpabuf_put_u8(buf, ctrl);
	wpabuf_put_u8(buf, reason);

	if (ctrl & NAN_TNA_CTRL_ND_TKSA_TERM) {
		wpabuf_put_u8(buf, n_nd_tksas);
		wpabuf_put_data(buf, nd_tksa_ids,
				n_nd_tksas * NAN_ND_TKSA_IDENTITY_LEN);
	}

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Built TNA ctrl=0x%02x reason=%u n_nd_tksas=%u",
		   ctrl, reason, n_nd_tksas);
	return 0;
}


int nan_cm_parse_tna(const u8 *data, size_t len, struct nan_cm_tna *tna)
{
	os_memset(tna, 0, sizeof(*tna));

	if (len < 2) {
		wpa_printf(MSG_DEBUG, "NAN CM: TNA too short");
		return -1;
	}

	tna->ctrl = data[0];
	tna->reason = data[1];

	if (!(tna->ctrl & (NAN_TNA_CTRL_NPKSA_TERM |
			   NAN_TNA_CTRL_NM_TKSA_TERM |
			   NAN_TNA_CTRL_ND_TKSA_TERM))) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: TNA without termination type (ctrl=0x%02x)",
			   tna->ctrl);
		return -1;
	}

	if (tna->ctrl & NAN_TNA_CTRL_ND_TKSA_TERM) {
		if (len < 3) {
			wpa_printf(MSG_DEBUG,
				   "NAN CM: TNA without ND-TKSA count");
			return -1;
		}

		tna->n_nd_tksas = data[2];
		if (len - 3 < tna->n_nd_tksas * NAN_ND_TKSA_IDENTITY_LEN) {
			wpa_printf(MSG_DEBUG,
				   "NAN CM: TNA ND-TKSA list truncated (count=%u)",
				   tna->n_nd_tksas);
			return -1;
		}
		tna->nd_tksa_ids = data + 3;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Parsed TNA ctrl=0x%02x reason=%u n_nd_tksas=%u",
		   tna->ctrl, tna->reason, tna->n_nd_tksas);
	return 0;
}


int nan_cm_build_saqa(struct wpabuf *buf, u8 dialog_token, u8 ctrl)
{
	if (wpabuf_tailroom(buf) < NAN_ATTR_HDR_LEN + 2) {
		wpa_printf(MSG_INFO, "NAN CM: No room for SAQA");
		return -1;
	}

	wpabuf_put_u8(buf, NAN_ATTR_SAQA);
	wpabuf_put_le16(buf, 2);
	wpabuf_put_u8(buf, dialog_token);
	wpabuf_put_u8(buf, ctrl);

	wpa_printf(MSG_DEBUG, "NAN CM: Built SAQA dialog_token=%u ctrl=0x%02x",
		   dialog_token, ctrl);
	return 0;
}


int nan_cm_parse_saqa(const u8 *data, size_t len, struct nan_cm_saqa *saqa)
{
	u8 type;

	if (len < 2) {
		wpa_printf(MSG_DEBUG, "NAN CM: SAQA too short");
		return -1;
	}

	saqa->dialog_token = data[0];
	saqa->ctrl = data[1];

	type = saqa->ctrl & NAN_SAQA_CTRL_TYPE_MASK;
	if (type != NAN_SAQA_CTRL_TYPE_REQUEST &&
	    type != NAN_SAQA_CTRL_TYPE_RESPONSE) {
		wpa_printf(MSG_DEBUG, "NAN CM: SAQA with unknown type %u",
			   type);
		return -1;
	}

	if (!saqa->dialog_token) {
		wpa_printf(MSG_DEBUG, "NAN CM: SAQA with zero Dialog Token");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "NAN CM: Parsed SAQA dialog_token=%u ctrl=0x%02x",
		   saqa->dialog_token, saqa->ctrl);
	return 0;
}


static bool nan_cm_rka_nd_tk(u8 ctrl)
{
	return (ctrl & NAN_RKA_CTRL_REKEY_TYPE_MASK) ==
		NAN_RKA_CTRL_REKEY_TYPE_ND_TK;
}


int nan_cm_build_rka(struct wpabuf *buf, u8 ctrl, const u8 *init_ndi,
		     const u8 *resp_ndi, u8 ndp_id)
{
	bool nd_tk = nan_cm_rka_nd_tk(ctrl);
	size_t len = 1 + (nd_tk ? NAN_ND_TKSA_IDENTITY_LEN + 1 : 0);

	if (wpabuf_tailroom(buf) < NAN_ATTR_HDR_LEN + len) {
		wpa_printf(MSG_INFO, "NAN CM: No room for RKA");
		return -1;
	}

	wpabuf_put_u8(buf, NAN_ATTR_RKA);
	wpabuf_put_le16(buf, len);
	wpabuf_put_u8(buf, ctrl);

	/* ND-TK rekey identifies the ND-TKSA and the NDP being rekeyed */
	if (nd_tk) {
		wpabuf_put_data(buf, init_ndi, ETH_ALEN);
		wpabuf_put_data(buf, resp_ndi, ETH_ALEN);
		wpabuf_put_u8(buf, ndp_id);
		wpa_printf(MSG_DEBUG,
			   "NAN CM: Built RKA ctrl=0x%02x init_ndi=" MACSTR
			   " resp_ndi=" MACSTR " ndp_id=%u",
			   ctrl, MAC2STR(init_ndi), MAC2STR(resp_ndi), ndp_id);
	} else {
		wpa_printf(MSG_DEBUG, "NAN CM: Built RKA ctrl=0x%02x", ctrl);
	}

	return 0;
}


int nan_cm_parse_rka(const u8 *data, size_t len, struct nan_cm_rka *rka)
{
	os_memset(rka, 0, sizeof(*rka));

	if (len < 1) {
		wpa_printf(MSG_DEBUG, "NAN CM: RKA too short");
		return -1;
	}

	rka->ctrl = data[0];

	if ((rka->ctrl & NAN_RKA_CTRL_MSG_TYPE_MASK) >
	    NAN_RKA_CTRL_MSG_TYPE_RESPONSE) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: RKA with unknown Message Type (ctrl=0x%02x)",
			   rka->ctrl);
		return -1;
	}

	if (!nan_cm_rka_nd_tk(rka->ctrl)) {
		wpa_printf(MSG_DEBUG, "NAN CM: Parsed RKA ctrl=0x%02x",
			   rka->ctrl);
		return 0;
	}

	if (len < 1 + NAN_ND_TKSA_IDENTITY_LEN + 1) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: RKA too short for ND-TK rekey (len=%zu)",
			   len);
		return -1;
	}

	rka->init_ndi = data + 1;
	rka->resp_ndi = data + 1 + ETH_ALEN;
	rka->ndp_id = data[1 + NAN_ND_TKSA_IDENTITY_LEN];

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Parsed RKA ctrl=0x%02x init_ndi=" MACSTR
		   " resp_ndi=" MACSTR " ndp_id=%u",
		   rka->ctrl, MAC2STR(rka->init_ndi),
		   MAC2STR(rka->resp_ndi), rka->ndp_id);
	return 0;
}


/*
 * Whether a Connection Management capability (NAN_DEV_CAPA_EXT_INFO_2_CM_*)
 * is supported by both the local device and the peer. The capabilities are
 * indicated in the Capability Info field of the DCEA (Wi-Fi Aware spec R5,
 * Table 173, b17-b21), which is not yet extended beyond b15, so none of them
 * can be used for now.
 */
static bool nan_cm_capa(const struct nan_data *nan,
			const struct nan_peer *peer, u8 capa)
{
	return false;
}


static struct wpabuf * nan_cm_alloc_naf(u8 subtype)
{
	struct wpabuf *buf;

	buf = wpabuf_alloc(NAN_CM_NAF_MAX_LEN);
	if (!buf)
		return NULL;

	/* Connection Management NAFs are protected with the NM-TK */
	wpabuf_put_u8(buf, WLAN_ACTION_PROTECTED_DUAL);
	wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);
	wpabuf_put_be24(buf, OUI_WFA);
	wpabuf_put_u8(buf, NAN_NAF_OUI_TYPE);
	wpabuf_put_u8(buf, subtype);
	return buf;
}


static int nan_cm_send_naf(struct nan_data *nan, struct nan_peer *peer,
			   struct wpabuf *buf)
{
	int ret;

	if (!nan->cfg->send_naf)
		return -1;
	ret = nan->cfg->send_naf(nan->cfg->cb_ctx, peer->nmi_addr, NULL,
				 nan->cluster_id, buf);
	if (ret)
		wpa_printf(MSG_DEBUG,
			   "NAN CM: Failed to send NAF to " MACSTR " (ret=%d)",
			   MAC2STR(peer->nmi_addr), ret);
	wpabuf_free(buf);
	return ret;
}


static int nan_cm_send_keepalive(struct nan_data *nan, struct nan_peer *peer)
{
	struct wpabuf *buf;

	buf = nan_cm_alloc_naf(NAN_SUBTYPE_CONNECTION_MGMT);
	if (!buf)
		return -1;

	if (nan_cm_build_kaa(peer, buf) < 0) {
		wpabuf_free(buf);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "NAN CM: Send Keep Alive to " MACSTR,
		   MAC2STR(peer->nmi_addr));
	return nan_cm_send_naf(nan, peer, buf);
}


static void nan_cm_ka_tx_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct nan_data *nan = eloop_ctx;
	struct nan_peer *peer = timeout_ctx;

	nan_cm_send_keepalive(nan, peer);
	eloop_register_timeout(NAN_CM_KA_INTERVAL_DEFAULT, 0,
			       nan_cm_ka_tx_timeout, nan, peer);
}


static void nan_cm_ka_rx_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct nan_data *nan = eloop_ctx;
	struct nan_peer *peer = timeout_ctx;

	wpa_printf(MSG_INFO,
		   "NAN CM: No Keep Alive from " MACSTR " within %d seconds",
		   MAC2STR(peer->nmi_addr), NAN_CM_KA_RX_TIMEOUT_DEFAULT);

	peer->cm.ka_active = false;
	eloop_cancel_timeout(nan_cm_ka_tx_timeout, nan, peer);
}


static void nan_cm_keepalive_start(struct nan_data *nan,
				   struct nan_peer *peer)
{
	if (peer->cm.ka_active)
		return;

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Start keep alive with " MACSTR
		   " (TX interval %d s, RX timeout %d s)",
		   MAC2STR(peer->nmi_addr), NAN_CM_KA_INTERVAL_DEFAULT,
		   NAN_CM_KA_RX_TIMEOUT_DEFAULT);

	peer->cm.ka_active = true;
	nan_cm_send_keepalive(nan, peer);
	eloop_register_timeout(NAN_CM_KA_INTERVAL_DEFAULT, 0,
			       nan_cm_ka_tx_timeout, nan, peer);
	eloop_register_timeout(NAN_CM_KA_RX_TIMEOUT_DEFAULT, 0,
			       nan_cm_ka_rx_timeout, nan, peer);
}


static void nan_cm_keepalive_stop(struct nan_data *nan, struct nan_peer *peer)
{
	if (!peer->cm.ka_active)
		return;

	wpa_printf(MSG_DEBUG, "NAN CM: Stop keep alive with " MACSTR,
		   MAC2STR(peer->nmi_addr));

	peer->cm.ka_active = false;
	eloop_cancel_timeout(nan_cm_ka_tx_timeout, nan, peer);
	eloop_cancel_timeout(nan_cm_ka_rx_timeout, nan, peer);
}


/**
 * nan_cm_nm_tksa_established - Handle NM-TKSA establishment with a peer
 * @nan: NAN module context from nan_init()
 * @peer: Paired peer
 *
 * Starts keep alive with the peer when both devices support the default keep
 * alive capability.
 */
void nan_cm_nm_tksa_established(struct nan_data *nan, struct nan_peer *peer)
{
	peer->cm.nm_tksa = true;

	wpa_printf(MSG_DEBUG, "NAN CM: NM-TKSA established with " MACSTR,
		   MAC2STR(peer->nmi_addr));

	if (!nan_cm_capa(nan, peer, NAN_DEV_CAPA_EXT_INFO_2_CM_DEFAULT_KA) ||
	    !nan->cfg->send_naf) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: Keep alive not supported with " MACSTR,
			   MAC2STR(peer->nmi_addr));
		return;
	}

	nan_cm_keepalive_start(nan, peer);
}


static bool nan_cm_kaa_has_ndp(const struct nan_cm_kaa *kaa,
			       const u8 *init_ndi, const u8 *resp_ndi,
			       u8 ndp_id)
{
	const struct nan_cm_kaa_entry *entry;
	unsigned int i, j;

	for (i = 0; i < kaa->n_entries; i++) {
		entry = &kaa->entries[i];
		if (!ether_addr_equal(entry->init_ndi, init_ndi) ||
		    !ether_addr_equal(entry->resp_ndi, resp_ndi))
			continue;
		for (j = 0; j < entry->n_ndp_ids; j++) {
			if (entry->ndp_ids[j] == ndp_id)
				return true;
		}
	}

	return false;
}


static bool nan_cm_local_has_ndp(const struct nan_peer *peer,
				 const u8 *init_ndi, const u8 *resp_ndi,
				 u8 ndp_id)
{
	struct nan_ndp *ndp;

	dl_list_for_each(ndp, &peer->ndps, struct nan_ndp, list) {
		if (ndp->ndp_id == ndp_id &&
		    ether_addr_equal(ndp->init_ndi, init_ndi) &&
		    ether_addr_equal(ndp->resp_ndi, resp_ndi))
			return true;
	}

	/* An NDP that is still being set up is not reported in the KAA */
	return peer->ndp_setup.ndp && peer->ndp_setup.ndp->ndp_id == ndp_id &&
		ether_addr_equal(peer->ndp_setup.ndp->init_ndi, init_ndi);
}


static void nan_cm_handle_kaa(struct nan_data *nan, struct nan_peer *peer,
			      const struct nan_cm_kaa *kaa)
{
	const struct nan_cm_kaa_entry *entry;
	struct nan_ndp *ndp, *tmp;
	unsigned int i, j;

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Keep Alive from " MACSTR " with %u NDI pairs",
		   MAC2STR(peer->nmi_addr), kaa->n_entries);

	if (!peer->cm.ka_active) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: Keep alive not active with " MACSTR
			   " - ignore KAA", MAC2STR(peer->nmi_addr));
		return;
	}

	eloop_cancel_timeout(nan_cm_ka_rx_timeout, nan, peer);
	eloop_register_timeout(NAN_CM_KA_RX_TIMEOUT_DEFAULT, 0,
			       nan_cm_ka_rx_timeout, nan, peer);

	/*
	 * Terminate local NDPs that the peer no longer reports. A KAA built by
	 * the peer before an NDP setup completed does not report the new NDP,
	 * so terminate an NDP only when it is missing from two consecutive
	 * KAAs.
	 */
	dl_list_for_each_safe(ndp, tmp, &peer->ndps, struct nan_ndp, list) {
		if (nan_cm_kaa_has_ndp(kaa, ndp->init_ndi, ndp->resp_ndi,
				       ndp->ndp_id)) {
			ndp->kaa_missing = false;
			continue;
		}

		if (!ndp->kaa_missing) {
			wpa_printf(MSG_DEBUG,
				   "NAN CM: NDP %u (init_ndi=" MACSTR
				   ") not in KAA from " MACSTR,
				   ndp->ndp_id, MAC2STR(ndp->init_ndi),
				   MAC2STR(peer->nmi_addr));
			ndp->kaa_missing = true;
			continue;
		}

		wpa_printf(MSG_DEBUG,
			   "NAN CM: NDP %u (init_ndi=" MACSTR
			   ") not in two KAAs from " MACSTR " - terminate",
			   ndp->ndp_id, MAC2STR(ndp->init_ndi),
			   MAC2STR(peer->nmi_addr));
		nan_peer_terminate_ndp(nan, peer, ndp);
	}

	/*
	 * NDPs reported by the peer but unknown locally are not terminated
	 * here as there is no local NDP state to build the termination from.
	 * The peer removes them on receiving the local KAA.
	 */
	for (i = 0; i < kaa->n_entries; i++) {
		entry = &kaa->entries[i];
		for (j = 0; j < entry->n_ndp_ids; j++) {
			if (nan_cm_local_has_ndp(peer, entry->init_ndi,
						 entry->resp_ndi,
						 entry->ndp_ids[j]))
				continue;
			wpa_printf(MSG_DEBUG,
				   "NAN CM: KAA from " MACSTR
				   " reports unknown NDP %u (init_ndi=" MACSTR
				   ")", MAC2STR(peer->nmi_addr),
				   entry->ndp_ids[j],
				   MAC2STR(entry->init_ndi));
		}
	}
}


/**
 * nan_cm_rx - Process a received Connection Management NAF
 * @nan: NAN module context from nan_init()
 * @peer: Peer that sent the frame
 * @mgmt: Received frame
 * @len: Length of @mgmt
 * Returns: 0 on success, -1 on failure
 */
int nan_cm_rx(struct nan_data *nan, struct nan_peer *peer,
	      const struct ieee80211_mgmt *mgmt, size_t len)
{
	const u8 *pos = mgmt->u.action.u.naf.variable;
	const u8 *end = (const u8 *) mgmt + len;
	struct nan_cm_kaa kaa;

	if (mgmt->u.action.category != WLAN_ACTION_PROTECTED_DUAL ||
	    !peer->cm.nm_tksa) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: Drop Connection Management NAF from "
			   MACSTR " (protected=%d nm_tksa=%d)",
			   MAC2STR(peer->nmi_addr),
			   mgmt->u.action.category ==
			   WLAN_ACTION_PROTECTED_DUAL, peer->cm.nm_tksa);
		return -1;
	}

	while (end - pos >= NAN_ATTR_HDR_LEN) {
		u8 id = pos[0];
		u16 attr_len = WPA_GET_LE16(pos + 1);

		pos += NAN_ATTR_HDR_LEN;
		if (attr_len > end - pos) {
			wpa_printf(MSG_DEBUG,
				   "NAN CM: Truncated attribute %u from "
				   MACSTR, id, MAC2STR(peer->nmi_addr));
			return -1;
		}

		switch (id) {
		case NAN_ATTR_KAA:
			if (nan_cm_parse_kaa(pos, attr_len, &kaa) < 0)
				return -1;
			nan_cm_handle_kaa(nan, peer, &kaa);
			break;
		default:
			wpa_printf(MSG_DEBUG,
				   "NAN CM: Ignore attribute %u from " MACSTR,
				   id, MAC2STR(peer->nmi_addr));
			break;
		}

		pos += attr_len;
	}

	return 0;
}


/**
 * nan_cm_peer_info - Write the Connection Management state of a peer
 * @nan: NAN module context from nan_init()
 * @addr: NMI of the peer
 * @buf: Buffer for the text output
 * @buflen: Length of @buf
 * Returns: Number of characters written or -1 on failure
 */
int nan_cm_peer_info(struct nan_data *nan, const u8 *addr, char *buf,
		     size_t buflen)
{
	struct nan_peer *peer;
	bool ka, deauth, rekey, term;
	int ret;

	peer = nan_get_peer(nan, addr);
	if (!peer)
		return -1;

	/* Capabilities that can be used with the peer */
	ka = nan_cm_capa(nan, peer, NAN_DEV_CAPA_EXT_INFO_2_CM_DEFAULT_KA);
	deauth = nan_cm_capa(nan, peer,
			     NAN_DEV_CAPA_EXT_INFO_2_CM_DEAUTH_SA_QUERY);
	rekey = nan_cm_capa(nan, peer, NAN_DEV_CAPA_EXT_INFO_2_CM_NDTK_REKEY);
	term = nan_cm_capa(nan, peer, NAN_DEV_CAPA_EXT_INFO_2_CM_TERM_NOTIF);

	ret = os_snprintf(buf, buflen,
			  "default_ka=%d\ndeauth_sa_query=%d\nndtk_rekey=%d\n"
			  "termination_notif=%d\nnm_tksa=%d\nka_active=%d\n",
			  ka, deauth, rekey, term, peer->cm.nm_tksa,
			  peer->cm.ka_active);
	if (os_snprintf_error(buflen, ret))
		return -1;
	return ret;
}


/**
 * nan_cm_deinit_peer - Release the Connection Management state of a peer
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer
 */
void nan_cm_deinit_peer(struct nan_data *nan, struct nan_peer *peer)
{
	nan_cm_keepalive_stop(nan, peer);
	os_memset(&peer->cm, 0, sizeof(peer->cm));
}
