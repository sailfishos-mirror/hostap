/*
 * Wi-Fi Aware - Connection Management
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "nan_i.h"
#include "nan_cm.h"


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
