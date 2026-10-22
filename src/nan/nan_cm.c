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
#include "pasn/pasn_common.h"
#include "nan_i.h"
#include "nan_cm.h"

/* Room for the NAF header and the Connection Management attributes */
#define NAN_CM_NAF_MAX_LEN 512

/* Time to wait for the TX status of a Termination Notification (seconds) */
#define NAN_CM_TX_STATUS_TIMEOUT 1

/* Time to wait for an SA Query Response (seconds) */
#define NAN_CM_SA_QUERY_TIMEOUT 2


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

	/*
	 * Connection Management NAFs are protected with the NM-TK. The
	 * Deauth NAF is sent without protection as the peer might no longer
	 * have the NM-TK.
	 */
	wpabuf_put_u8(buf, subtype == NAN_SUBTYPE_DEAUTH ?
		      WLAN_ACTION_PUBLIC : WLAN_ACTION_PROTECTED_DUAL);
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


static void nan_cm_delete_nm_tksa(struct nan_data *nan, struct nan_peer *peer,
				  bool locally_generated);

static void nan_cm_ka_rx_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct nan_data *nan = eloop_ctx;
	struct nan_peer *peer = timeout_ctx;

	wpa_printf(MSG_INFO,
		   "NAN CM: No Keep Alive from " MACSTR " within %d seconds",
		   MAC2STR(peer->nmi_addr), NAN_CM_KA_RX_TIMEOUT_DEFAULT);

	/*
	 * The security associations with the peer are considered lost. The
	 * peer is not responding, so delete them without notifying it.
	 */
	nan_cm_delete_nm_tksa(nan, peer, true);
}


static void nan_cm_sa_query_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct nan_data *nan = eloop_ctx;
	struct nan_peer *peer = timeout_ctx;

	wpa_printf(MSG_DEBUG,
		   "NAN CM: No SA Query Response from " MACSTR
		   " - NM-TKSA lost", MAC2STR(peer->nmi_addr));
	peer->cm.sa_query_token = 0;
	nan_cm_delete_nm_tksa(nan, peer, false);
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


static int nan_cm_send_tna(struct nan_data *nan, struct nan_peer *peer,
			   u8 ctrl, const u8 *nd_tksa_ids, u8 n_nd_tksas)
{
	struct wpabuf *buf;

	buf = nan_cm_alloc_naf(NAN_SUBTYPE_CONNECTION_MGMT);
	if (!buf)
		return -1;

	if (nan_cm_build_tna(buf, ctrl, NAN_REASON_UNSPECIFIED_REASON,
			     nd_tksa_ids, n_nd_tksas) < 0) {
		wpabuf_free(buf);
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Send Termination Notification to " MACSTR
		   " ctrl=0x%02x", MAC2STR(peer->nmi_addr), ctrl);
	return nan_cm_send_naf(nan, peer, buf);
}


static int nan_cm_send_saqa(struct nan_data *nan, struct nan_peer *peer,
			    u8 dialog_token, u8 ctrl)
{
	struct wpabuf *buf;

	buf = nan_cm_alloc_naf(NAN_SUBTYPE_CONNECTION_MGMT);
	if (!buf)
		return -1;

	if (nan_cm_build_saqa(buf, dialog_token, ctrl) < 0) {
		wpabuf_free(buf);
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Send SA Query %s to " MACSTR " dialog_token=%u",
		   (ctrl & NAN_SAQA_CTRL_TYPE_MASK) ==
		   NAN_SAQA_CTRL_TYPE_REQUEST ? "Request" : "Response",
		   MAC2STR(peer->nmi_addr), dialog_token);
	return nan_cm_send_naf(nan, peer, buf);
}


static void nan_cm_notify_terminated(struct nan_data *nan,
				     const struct nan_peer *peer,
				     enum nan_cm_sa type, const u8 *init_ndi,
				     const u8 *resp_ndi, bool locally_generated)
{
	if (nan->cfg->cm_terminated)
		nan->cfg->cm_terminated(nan->cfg->cb_ctx, peer->nmi_addr, type,
					init_ndi, resp_ndi,
					locally_generated);
}


static bool nan_cm_has_nd_tksa(const struct nan_peer *peer,
			       const u8 *init_ndi, const u8 *resp_ndi)
{
	struct nan_ndp *ndp;

	dl_list_for_each(ndp, &peer->ndps, struct nan_ndp, list) {
		if (ether_addr_equal(ndp->init_ndi, init_ndi) &&
		    ether_addr_equal(ndp->resp_ndi, resp_ndi))
			return true;
	}

	return false;
}


static void nan_cm_delete_nd_tksa(struct nan_data *nan, struct nan_peer *peer,
				  const u8 *init_ndi, const u8 *resp_ndi,
				  bool locally_generated)
{
	u8 ndis[NAN_ND_TKSA_IDENTITY_LEN];
	struct nan_ndp *ndp, *tmp;

	/* The NDIs may point to an NDP that is freed below */
	os_memcpy(ndis, init_ndi, ETH_ALEN);
	os_memcpy(ndis + ETH_ALEN, resp_ndi, ETH_ALEN);

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Delete ND-TKSA init_ndi=" MACSTR " resp_ndi="
		   MACSTR " with " MACSTR, MAC2STR(ndis),
		   MAC2STR(ndis + ETH_ALEN), MAC2STR(peer->nmi_addr));

	dl_list_for_each_safe(ndp, tmp, &peer->ndps, struct nan_ndp, list) {
		if (ether_addr_equal(ndp->init_ndi, ndis) &&
		    ether_addr_equal(ndp->resp_ndi, ndis + ETH_ALEN))
			nan_peer_terminate_ndp(nan, peer, ndp);
	}

	nan_cm_notify_terminated(nan, peer, NAN_CM_SA_ND_TKSA, ndis,
				 ndis + ETH_ALEN, locally_generated);
}


/**
 * nan_cm_terminate_nd_tksa - Terminate an ND-TKSA with a peer
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer
 * @init_ndi: Initiator NDI of the ND-TKSA
 * @resp_ndi: Responder NDI of the ND-TKSA
 * Returns: 0 on success, -1 if no NDP uses the ND-TKSA
 *
 * Terminates all NDPs established over the NDI pair. The peer is notified
 * with a Termination Notification when both devices support it.
 */
int nan_cm_terminate_nd_tksa(struct nan_data *nan, struct nan_peer *peer,
			     const u8 *init_ndi, const u8 *resp_ndi)
{
	u8 id[NAN_ND_TKSA_IDENTITY_LEN];

	if (!nan_cm_has_nd_tksa(peer, init_ndi, resp_ndi)) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: No ND-TKSA init_ndi=" MACSTR " resp_ndi="
			   MACSTR " with " MACSTR, MAC2STR(init_ndi),
			   MAC2STR(resp_ndi), MAC2STR(peer->nmi_addr));
		return -1;
	}

	/* Notify the peer while the NDPs are still in place */
	if (peer->cm.nm_tksa &&
	    nan_cm_capa(nan, peer, NAN_DEV_CAPA_EXT_INFO_2_CM_TERM_NOTIF)) {
		os_memcpy(id, init_ndi, ETH_ALEN);
		os_memcpy(id + ETH_ALEN, resp_ndi, ETH_ALEN);
		nan_cm_send_tna(nan, peer, NAN_TNA_CTRL_ND_TKSA_TERM, id, 1);
	}

	nan_cm_delete_nd_tksa(nan, peer, init_ndi, resp_ndi, true);
	return 0;
}


static void nan_cm_nm_tksa_term_timeout(void *eloop_ctx, void *timeout_ctx);

static void nan_cm_delete_nm_tksa(struct nan_data *nan, struct nan_peer *peer,
				  bool locally_generated)
{
	struct nan_ndp *ndp, *tmp;

	wpa_printf(MSG_DEBUG, "NAN CM: Delete NM-TKSA with " MACSTR,
		   MAC2STR(peer->nmi_addr));

	eloop_cancel_timeout(nan_cm_nm_tksa_term_timeout, nan, peer);
	eloop_cancel_timeout(nan_cm_sa_query_timeout, nan, peer);
	peer->cm.nm_tksa_term_pending = false;
	peer->cm.sa_query_token = 0;
	peer->cm.nm_tksa = false;
	nan_cm_keepalive_stop(nan, peer);

	/* Terminating the NM-TKSA terminates all ND-TKSAs with the peer */
	dl_list_for_each_safe(ndp, tmp, &peer->ndps, struct nan_ndp, list)
		nan_peer_terminate_ndp(nan, peer, ndp);

	nan_remove_group_keys(nan, peer);

	/* Delete the NM-TK and the PTKSA derived keys */
	if (peer->pairing.nm_tk_installed && nan->cfg->install_nm_tk)
		nan->cfg->install_nm_tk(nan->cfg->cb_ctx, peer->nmi_addr, 0,
					NULL, 0);
	peer->pairing.nm_tk_installed = false;
	forced_memzero(peer->pairing.tk, sizeof(peer->pairing.tk));
	peer->pairing.tk_len = 0;
	peer->pairing.flags &= ~NAN_PAIRING_FLAG_PAIRED;

	/* The NMI station was kept for the NM-TKSA without NDPs */
	if (dl_list_empty(&peer->ndps) && !peer->ndp_setup.ndp)
		nan_clear_peer_schedule(nan, peer);

	nan_cm_notify_terminated(nan, peer, NAN_CM_SA_NM_TKSA, NULL, NULL,
				 locally_generated);
}


static void nan_cm_nm_tksa_term_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct nan_data *nan = eloop_ctx;
	struct nan_peer *peer = timeout_ctx;

	wpa_printf(MSG_DEBUG,
		   "NAN CM: No TX status for NM-TKSA termination frame to "
		   MACSTR, MAC2STR(peer->nmi_addr));
	nan_cm_delete_nm_tksa(nan, peer, true);
}


/**
 * nan_cm_terminate_nm_tksa - Terminate the NM-TKSA with a peer
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer
 * Returns: 0 on success, -1 if no NM-TKSA is established with the peer
 *
 * Terminates all ND-TKSAs with the peer and deletes the NM-TKSA keys. When
 * both devices support termination notification, the peer is notified with a
 * Termination Notification that is protected with the NM-TK, so the keys are
 * deleted only once the frame TX status is received.
 */
int nan_cm_terminate_nm_tksa(struct nan_data *nan, struct nan_peer *peer)
{
	if (!peer->cm.nm_tksa) {
		wpa_printf(MSG_DEBUG, "NAN CM: No NM-TKSA with " MACSTR,
			   MAC2STR(peer->nmi_addr));
		return -1;
	}

	if (peer->cm.nm_tksa_term_pending)
		return 0;

	wpa_printf(MSG_DEBUG, "NAN CM: Terminate NM-TKSA with " MACSTR,
		   MAC2STR(peer->nmi_addr));

	/* No further Keep Alive messages once the NM-TKSA is terminated */
	nan_cm_keepalive_stop(nan, peer);

	if (nan_cm_capa(nan, peer, NAN_DEV_CAPA_EXT_INFO_2_CM_TERM_NOTIF) &&
	    nan_cm_send_tna(nan, peer, NAN_TNA_CTRL_NM_TKSA_TERM, NULL, 0) ==
	    0) {
		peer->cm.nm_tksa_term_pending = true;
		eloop_register_timeout(NAN_CM_TX_STATUS_TIMEOUT, 0,
				       nan_cm_nm_tksa_term_timeout, nan, peer);
		return 0;
	}

	nan_cm_delete_nm_tksa(nan, peer, true);
	return 0;
}


static void nan_cm_delete_npksa(struct nan_data *nan, struct nan_peer *peer,
				bool locally_generated)
{
	wpa_printf(MSG_DEBUG, "NAN CM: Delete NPKSA with " MACSTR,
		   MAC2STR(peer->nmi_addr));

	peer->cm.npksa = false;

	/* Delete the NPK and the PIK; the NM-TKSA and ND-TKSAs continue */
	if (peer->pairing.peer_nik_valid && nan->cfg->delete_npk)
		nan->cfg->delete_npk(nan->cfg->cb_ctx, peer->nmi_addr,
				     peer->pairing.peer_nik);
	forced_memzero(peer->pairing.peer_nik, sizeof(peer->pairing.peer_nik));
	peer->pairing.peer_nik_valid = false;

	if (nan->pik_cache)
		nan_pik_cache_remove(nan->pik_cache, peer->nmi_addr);

#ifdef CONFIG_PASN
	pasn_initiator_pmksa_cache_remove(nan->initiator_pmksa,
					  peer->nmi_addr);
	pasn_responder_pmksa_cache_remove(nan->responder_pmksa,
					  peer->nmi_addr);
#endif /* CONFIG_PASN */

	nan_cm_notify_terminated(nan, peer, NAN_CM_SA_NPKSA, NULL, NULL,
				 locally_generated);
}


/**
 * nan_cm_terminate_npksa - Terminate the NPKSA with a peer
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer
 * Returns: 0 on success, -1 if no NPKSA is established with the peer
 *
 * Deletes the NPK and the PIK of the peer. The NM-TKSA and the ND-TKSAs with
 * the peer are not affected. When both devices support termination
 * notification, the peer is notified with a Termination Notification.
 */
int nan_cm_terminate_npksa(struct nan_data *nan, struct nan_peer *peer)
{
	if (!peer->cm.npksa) {
		wpa_printf(MSG_DEBUG, "NAN CM: No NPKSA with " MACSTR,
			   MAC2STR(peer->nmi_addr));
		return -1;
	}

	wpa_printf(MSG_DEBUG, "NAN CM: Terminate NPKSA with " MACSTR,
		   MAC2STR(peer->nmi_addr));

	if (peer->cm.nm_tksa &&
	    nan_cm_capa(nan, peer, NAN_DEV_CAPA_EXT_INFO_2_CM_TERM_NOTIF))
		nan_cm_send_tna(nan, peer, NAN_TNA_CTRL_NPKSA_TERM, NULL, 0);

	nan_cm_delete_npksa(nan, peer, true);
	return 0;
}


static int nan_cm_add_pntag_irsa(struct nan_data *nan,
				 const struct nan_peer *peer,
				 struct wpabuf *buf)
{
	const struct nan_pik_cache_entry *pik;
	u8 nonce[NAN_NIRA_NONCE_LEN];
	struct wpabuf *tag;
	size_t attr_len = 1 + NAN_NIRA_NONCE_LEN + 2 + NAN_NIRA_TAG_LEN;

	pik = nan->pik_cache ? nan_pik_cache_get(nan->pik_cache,
						 peer->nmi_addr) : NULL;
	if (!pik)
		return 0;

	if (wpabuf_tailroom(buf) < NAN_ATTR_HDR_LEN + attr_len ||
	    os_get_random(nonce, sizeof(nonce)) < 0)
		return -1;

	/* The PNTag identifies the local device to the paired peer */
	tag = nan_crypto_derive_irsa_tag(pik->pik, NAN_PIK_LEN,
					 nan->cfg->nmi_addr, nonce);
	if (!tag)
		return -1;

	wpabuf_put_u8(buf, NAN_ATTR_IRSA);
	wpabuf_put_le16(buf, attr_len);
	wpabuf_put_u8(buf, NAN_IRSA_CIPHER_VER_SIPHASH_2_4);
	wpabuf_put_data(buf, nonce, NAN_NIRA_NONCE_LEN);
	wpabuf_put_u8(buf, NAN_TAG_TYPE_PN);
	wpabuf_put_u8(buf, 1);
	wpabuf_put_buf(buf, tag);
	wpabuf_free(tag);
	return 0;
}


/**
 * nan_cm_deauth - Terminate the NM-TKSA with a Deauth NAF
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer
 * @keep_nm_tksa: Keep the local NM-TKSA (testing only)
 * Returns: 0 on success, -1 on failure
 *
 * Deletes the NM-TKSA with the peer and notifies the peer with an unprotected
 * Deauth NAF carrying a TNA and, when a PIK is established with the peer, an
 * IRSA with a PNTag that identifies the local device. The NM-TKSA is deleted
 * once the frame TX status is received.
 */
int nan_cm_deauth(struct nan_data *nan, struct nan_peer *peer,
		  bool keep_nm_tksa)
{
	struct wpabuf *buf;

	if (!peer->cm.nm_tksa) {
		wpa_printf(MSG_DEBUG, "NAN CM: No NM-TKSA with " MACSTR,
			   MAC2STR(peer->nmi_addr));
		return -1;
	}

	if (!nan_cm_capa(nan, peer,
			 NAN_DEV_CAPA_EXT_INFO_2_CM_DEAUTH_SA_QUERY)) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: Deauthentication not supported with "
			   MACSTR, MAC2STR(peer->nmi_addr));
		return -1;
	}

	wpa_printf(MSG_DEBUG, "NAN CM: Send Deauthentication to " MACSTR,
		   MAC2STR(peer->nmi_addr));

	buf = nan_cm_alloc_naf(NAN_SUBTYPE_DEAUTH);
	if (!buf)
		return -1;

	if (nan_cm_build_tna(buf, NAN_TNA_CTRL_NM_TKSA_TERM,
			     NAN_REASON_UNSPECIFIED_REASON, NULL, 0) < 0 ||
	    nan_cm_add_pntag_irsa(nan, peer, buf) < 0) {
		wpabuf_free(buf);
		return -1;
	}

	/*
	 * Deleting the NM-TKSA removes the NMI station of the peer, which would
	 * drop the queued frame, so delete it once the TX status is received.
	 */
	if (nan_cm_send_naf(nan, peer, buf) < 0) {
		if (!keep_nm_tksa)
			nan_cm_delete_nm_tksa(nan, peer, true);
		return 0;
	}

	if (keep_nm_tksa) {
		wpa_printf(MSG_INFO,
			   "NAN CM: TESTING - keep NM-TKSA after Deauthentication");
		return 0;
	}

	nan_cm_keepalive_stop(nan, peer);
	peer->cm.nm_tksa_term_pending = true;
	eloop_register_timeout(NAN_CM_TX_STATUS_TIMEOUT, 0,
			       nan_cm_nm_tksa_term_timeout, nan, peer);
	return 0;
}


/* Whether a frame carries a TNA that indicates NM-TKSA termination */
static bool nan_cm_nm_tksa_term_frame(const struct ieee80211_mgmt *mgmt,
				      size_t len)
{
	const u8 *pos = mgmt->u.action.u.naf.variable;
	const u8 *end = (const u8 *) mgmt + len;

	while (end - pos >= NAN_ATTR_HDR_LEN) {
		u8 id = pos[0];
		u16 attr_len = WPA_GET_LE16(pos + 1);

		pos += NAN_ATTR_HDR_LEN;
		if (attr_len > end - pos)
			break;
		if (id == NAN_ATTR_TNA && attr_len >= 1 &&
		    (pos[0] & NAN_TNA_CTRL_NM_TKSA_TERM))
			return true;
		pos += attr_len;
	}

	return false;
}


/**
 * nan_cm_tx_status - Process TX status of a Connection Management NAF
 * @nan: NAN module context from nan_init()
 * @peer: Destination peer
 * @mgmt: Transmitted frame
 * @len: Length of @mgmt
 * @acked: Whether the frame was acknowledged
 *
 * The keys of an NM-TKSA that is being terminated are deleted once the TX
 * status of the frame that terminates it is received. The TX status of other
 * frames, e.g., a Keep Alive message sent before the termination, is ignored.
 */
void nan_cm_tx_status(struct nan_data *nan, struct nan_peer *peer,
		      const struct ieee80211_mgmt *mgmt, size_t len,
		      bool acked)
{
	if (!peer->cm.nm_tksa_term_pending ||
	    !nan_cm_nm_tksa_term_frame(mgmt, len))
		return;

	wpa_printf(MSG_DEBUG,
		   "NAN CM: NM-TKSA termination frame to " MACSTR
		   " acked=%d", MAC2STR(peer->nmi_addr), acked);
	nan_cm_delete_nm_tksa(nan, peer, true);
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


static void nan_cm_handle_tna(struct nan_data *nan, struct nan_peer *peer,
			      const struct nan_cm_tna *tna)
{
	const u8 *id;
	unsigned int i;

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Termination Notification from " MACSTR
		   " ctrl=0x%02x reason=%u", MAC2STR(peer->nmi_addr),
		   tna->ctrl, tna->reason);

	if (tna->ctrl & NAN_TNA_CTRL_ND_TKSA_TERM) {
		for (i = 0; i < tna->n_nd_tksas; i++) {
			id = tna->nd_tksa_ids + i * NAN_ND_TKSA_IDENTITY_LEN;
			if (nan_cm_has_nd_tksa(peer, id, id + ETH_ALEN))
				nan_cm_delete_nd_tksa(nan, peer, id,
						      id + ETH_ALEN, false);
			else
				wpa_printf(MSG_DEBUG,
					   "NAN CM: Unknown ND-TKSA init_ndi="
					   MACSTR " resp_ndi=" MACSTR,
					   MAC2STR(id),
					   MAC2STR(id + ETH_ALEN));
		}
	}

	if ((tna->ctrl & NAN_TNA_CTRL_NPKSA_TERM) && peer->cm.npksa)
		nan_cm_delete_npksa(nan, peer, false);

	/* NM-TKSA termination also terminates all ND-TKSAs */
	if (tna->ctrl & NAN_TNA_CTRL_NM_TKSA_TERM)
		nan_cm_delete_nm_tksa(nan, peer, false);
}


static void nan_cm_handle_saqa(struct nan_data *nan, struct nan_peer *peer,
			       const struct nan_cm_saqa *saqa)
{
	u8 ctrl;

	if ((saqa->ctrl & NAN_SAQA_CTRL_TYPE_MASK) ==
	    NAN_SAQA_CTRL_TYPE_REQUEST) {
		/*
		 * The request was received protected with the NM-TK, so the
		 * NM-TKSA is in place. Report the NPKSA only if it is.
		 */
		ctrl = NAN_SAQA_CTRL_TYPE_RESPONSE |
			(saqa->ctrl & NAN_SAQA_CTRL_NM_TKSA_QUERY);
		if ((saqa->ctrl & NAN_SAQA_CTRL_NPKSA_QUERY) && peer->cm.npksa)
			ctrl |= NAN_SAQA_CTRL_NPKSA_QUERY;
		nan_cm_send_saqa(nan, peer, saqa->dialog_token, ctrl);
		return;
	}

	if (!peer->cm.sa_query_token ||
	    saqa->dialog_token != peer->cm.sa_query_token) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: Unexpected SA Query Response from " MACSTR
			   " dialog_token=%u", MAC2STR(peer->nmi_addr),
			   saqa->dialog_token);
		return;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN CM: SA Query Response from " MACSTR
		   " - NM-TKSA is valid, ignore Deauthentication",
		   MAC2STR(peer->nmi_addr));
	peer->cm.sa_query_token = 0;
	eloop_cancel_timeout(nan_cm_sa_query_timeout, nan, peer);
}


static struct nan_ndp * nan_cm_find_ndp(struct nan_peer *peer,
					const u8 *init_ndi, const u8 *resp_ndi,
					u8 ndp_id)
{
	struct nan_ndp *ndp;

	dl_list_for_each(ndp, &peer->ndps, struct nan_ndp, list) {
		if (ndp->ndp_id == ndp_id &&
		    ether_addr_equal(ndp->init_ndi, init_ndi) &&
		    ether_addr_equal(ndp->resp_ndi, resp_ndi))
			return ndp;
	}

	return NULL;
}


static void nan_cm_handle_rka(struct nan_data *nan, struct nan_peer *peer,
			      const struct nan_cm_rka *rka)
{
	struct nan_ndp *ndp;

	/* Only ND-TK rekey is supported */
	if ((rka->ctrl & NAN_RKA_CTRL_REKEY_TYPE_MASK) !=
	    NAN_RKA_CTRL_REKEY_TYPE_ND_TK) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: Ignore unsupported rekey type in RKA ctrl=0x%02x from "
			   MACSTR, rka->ctrl, MAC2STR(peer->nmi_addr));
		return;
	}

	/*
	 * ND-TK rekey is requested in a Connection Management NAF only with an
	 * indication; the request and response are carried in the NDP setup.
	 */
	if ((rka->ctrl & NAN_RKA_CTRL_MSG_TYPE_MASK) !=
	    NAN_RKA_CTRL_MSG_TYPE_INDICATION) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: Ignore RKA ctrl=0x%02x from " MACSTR
			   " - not an indication", rka->ctrl,
			   MAC2STR(peer->nmi_addr));
		return;
	}

	if (!nan_cm_capa(nan, peer, NAN_DEV_CAPA_EXT_INFO_2_CM_NDTK_REKEY)) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: ND-TK rekey not supported with " MACSTR,
			   MAC2STR(peer->nmi_addr));
		return;
	}

	ndp = nan_cm_find_ndp(peer, rka->init_ndi, rka->resp_ndi,
			      rka->ndp_id);
	if (!ndp) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: ND-TK rekey indication from " MACSTR
			   " for unknown NDP %u (init_ndi=" MACSTR ")",
			   MAC2STR(peer->nmi_addr), rka->ndp_id,
			   MAC2STR(rka->init_ndi));
		return;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN CM: ND-TK rekey indication from " MACSTR
		   " for NDP %u (init_ndi=" MACSTR " resp_ndi=" MACSTR ")",
		   MAC2STR(peer->nmi_addr), ndp->ndp_id,
		   MAC2STR(ndp->init_ndi), MAC2STR(ndp->resp_ndi));
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
	struct nan_cm_tna tna;
	struct nan_cm_saqa saqa;
	struct nan_cm_rka rka;

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

	/* Stop processing once the NM-TKSA is terminated by the frame */
	while (end - pos >= NAN_ATTR_HDR_LEN && peer->cm.nm_tksa) {
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
		case NAN_ATTR_TNA:
			if (nan_cm_parse_tna(pos, attr_len, &tna) < 0)
				return -1;
			nan_cm_handle_tna(nan, peer, &tna);
			break;
		case NAN_ATTR_SAQA:
			if (nan_cm_parse_saqa(pos, attr_len, &saqa) < 0)
				return -1;
			nan_cm_handle_saqa(nan, peer, &saqa);
			break;
		case NAN_ATTR_RKA:
			if (nan_cm_parse_rka(pos, attr_len, &rka) < 0)
				return -1;
			nan_cm_handle_rka(nan, peer, &rka);
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


static bool nan_cm_deauth_pntag_valid(struct nan_data *nan,
				      const struct nan_peer *peer,
				      const struct nan_attrs *attrs)
{
	const struct nan_pik_cache_entry *pik;
	const u8 *pos, *end, *nonce;
	struct wpabuf *tag;
	bool valid = false;

	pik = nan->pik_cache ? nan_pik_cache_get(nan->pik_cache,
						 peer->nmi_addr) : NULL;
	if (!pik)
		return true;

	if (!attrs->irsa) {
		wpa_printf(MSG_DEBUG, "NAN CM: Deauthentication from " MACSTR
			   " without IRSA", MAC2STR(peer->nmi_addr));
		return false;
	}

	/* The IRSA was validated to hold the cipher version and a nonce */
	nonce = attrs->irsa + 1;
	pos = nonce + NAN_NIRA_NONCE_LEN;
	end = attrs->irsa + attrs->irsa_len;

	tag = nan_crypto_derive_irsa_tag(pik->pik, NAN_PIK_LEN,
					 peer->nmi_addr, nonce);
	if (!tag)
		return false;

	while (end - pos >= 2 && !valid) {
		u8 type = pos[0], count = pos[1], i;
		size_t tags_len = count * NAN_NIRA_TAG_LEN;

		pos += 2;
		if (tags_len > (size_t) (end - pos))
			break;

		for (i = 0; type == NAN_TAG_TYPE_PN && i < count && !valid; i++)
			valid = os_memcmp_const(pos + i * NAN_NIRA_TAG_LEN,
						wpabuf_head(tag),
						NAN_NIRA_TAG_LEN) == 0;
		pos += tags_len;
	}

	wpabuf_free(tag);
	if (!valid)
		wpa_printf(MSG_DEBUG,
			   "NAN CM: No valid PNTag in Deauthentication from "
			   MACSTR, MAC2STR(peer->nmi_addr));
	return valid;
}


/**
 * nan_cm_rx_deauth - Process a received Deauth NAF
 * @nan: NAN module context from nan_init()
 * @peer: Peer that sent the frame
 * @msg: Parsed frame
 * Returns: 0 on success, -1 on failure
 *
 * The frame is not protected, so the peer is first verified to have lost the
 * NM-TKSA with a protected SA Query before the NM-TKSA is deleted.
 */
int nan_cm_rx_deauth(struct nan_data *nan, struct nan_peer *peer,
		     const struct nan_msg *msg)
{
	u8 token;

	if (!peer->cm.nm_tksa || peer->cm.nm_tksa_term_pending ||
	    !nan_cm_capa(nan, peer,
			 NAN_DEV_CAPA_EXT_INFO_2_CM_DEAUTH_SA_QUERY)) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: Ignore Deauthentication from " MACSTR
			   " (nm_tksa=%d)", MAC2STR(peer->nmi_addr),
			   peer->cm.nm_tksa);
		return -1;
	}

	if (peer->cm.sa_query_token) {
		wpa_printf(MSG_DEBUG,
			   "NAN CM: SA Query already in progress with " MACSTR,
			   MAC2STR(peer->nmi_addr));
		return 0;
	}

	if (!nan_cm_deauth_pntag_valid(nan, peer, &msg->attrs))
		return -1;

	token = nan_get_next_dialog_token(nan);
	if (nan_cm_send_saqa(nan, peer, token,
			     NAN_SAQA_CTRL_TYPE_REQUEST |
			     NAN_SAQA_CTRL_NM_TKSA_QUERY) < 0)
		return -1;

	wpa_printf(MSG_DEBUG,
		   "NAN CM: Deauthentication from " MACSTR
		   " - wait %d s for SA Query Response",
		   MAC2STR(peer->nmi_addr), NAN_CM_SA_QUERY_TIMEOUT);
	peer->cm.sa_query_token = token;
	eloop_register_timeout(NAN_CM_SA_QUERY_TIMEOUT, 0,
			       nan_cm_sa_query_timeout, nan, peer);
	return 0;
}


/**
 * nan_cm_terminate - Terminate a security association with a paired peer
 * @nan: NAN module context from nan_init()
 * @addr: NMI of the peer
 * @type: Security association to terminate
 * @init_ndi: Initiator NDI of the ND-TKSA; used only with NAN_CM_SA_ND_TKSA
 * @resp_ndi: Responder NDI of the ND-TKSA; used only with NAN_CM_SA_ND_TKSA
 * Returns: 0 on success, -1 on failure
 */
int nan_cm_terminate(struct nan_data *nan, const u8 *addr,
		     enum nan_cm_sa type, const u8 *init_ndi,
		     const u8 *resp_ndi)
{
	struct nan_peer *peer;

	peer = nan_get_peer(nan, addr);
	if (!peer) {
		wpa_printf(MSG_DEBUG, "NAN CM: Peer " MACSTR " not found",
			   MAC2STR(addr));
		return -1;
	}

	switch (type) {
	case NAN_CM_SA_NPKSA:
		return nan_cm_terminate_npksa(nan, peer);
	case NAN_CM_SA_NM_TKSA:
		return nan_cm_terminate_nm_tksa(nan, peer);
	case NAN_CM_SA_ND_TKSA:
		return nan_cm_terminate_nd_tksa(nan, peer, init_ndi, resp_ndi);
	}

	return -1;
}


/**
 * nan_cm_send_deauth - Deauthenticate a paired peer
 * @nan: NAN module context from nan_init()
 * @addr: NMI of the peer
 * @keep_nm_tksa: Keep the local NM-TKSA (testing only)
 * Returns: 0 on success, -1 on failure
 */
int nan_cm_send_deauth(struct nan_data *nan, const u8 *addr, bool keep_nm_tksa)
{
	struct nan_peer *peer;

	peer = nan_get_peer(nan, addr);
	if (!peer) {
		wpa_printf(MSG_DEBUG, "NAN CM: Peer " MACSTR " not found",
			   MAC2STR(addr));
		return -1;
	}

	return nan_cm_deauth(nan, peer, keep_nm_tksa);
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
			  "termination_notif=%d\nnpksa=%d\nnm_tksa=%d\n"
			  "ka_active=%d\n",
			  ka, deauth, rekey, term, peer->cm.npksa,
			  peer->cm.nm_tksa, peer->cm.ka_active);
	if (os_snprintf_error(buflen, ret))
		return -1;
	return ret;
}


/**
 * nan_cm_unpair_peer - Clear the NM-TKSA state when a peer is unpaired
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer
 *
 * The NM-TK is removed with the NMI station of the peer. The NPKSA is not
 * affected.
 */
void nan_cm_unpair_peer(struct nan_data *nan, struct nan_peer *peer)
{
	nan_cm_keepalive_stop(nan, peer);
	eloop_cancel_timeout(nan_cm_nm_tksa_term_timeout, nan, peer);
	eloop_cancel_timeout(nan_cm_sa_query_timeout, nan, peer);
	peer->cm.nm_tksa = false;
	peer->cm.nm_tksa_term_pending = false;
	peer->cm.sa_query_token = 0;
}


/**
 * nan_cm_deinit_peer - Release the Connection Management state of a peer
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer
 */
void nan_cm_deinit_peer(struct nan_data *nan, struct nan_peer *peer)
{
	nan_cm_unpair_peer(nan, peer);
	os_memset(&peer->cm, 0, sizeof(peer->cm));
}
