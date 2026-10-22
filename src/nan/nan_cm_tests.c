/*
 * Wi-Fi Aware - Connection Management unit tests
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "nan_i.h"
#include "nan_cm.h"

static const u8 test_init_ndi[ETH_ALEN] = {
	0x02, 0x11, 0x22, 0x33, 0x44, 0x55
};
static const u8 test_resp_ndi[ETH_ALEN] = {
	0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee
};


static int test_kaa_no_ndps(void)
{
	struct nan_peer peer;
	struct nan_cm_kaa kaa;
	struct wpabuf *buf;
	const u8 *pos;
	int ret = -1;

	wpa_printf(MSG_INFO, "TEST: NAN CM KAA without NDPs");
	os_memset(&peer, 0, sizeof(peer));
	dl_list_init(&peer.ndps);

	buf = wpabuf_alloc(NAN_ATTR_HDR_LEN + 1);
	if (!buf || nan_cm_build_kaa(&peer, buf) < 0)
		goto out;

	pos = wpabuf_head_u8(buf);
	if (wpabuf_len(buf) != NAN_ATTR_HDR_LEN + 1 ||
	    pos[0] != NAN_ATTR_KAA || WPA_GET_LE16(pos + 1) != 1 ||
	    pos[3] != 0 ||
	    nan_cm_parse_kaa(pos + NAN_ATTR_HDR_LEN, 1, &kaa) < 0 ||
	    kaa.ndps_present || kaa.n_entries)
		goto out;

	/* No room for the attribute */
	wpabuf_free(buf);
	buf = wpabuf_alloc(NAN_ATTR_HDR_LEN);
	if (!buf || nan_cm_build_kaa(&peer, buf) == 0)
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: NAN CM KAA without NDPs");
	wpabuf_free(buf);
	return ret;
}


static int test_kaa_ndp_list(void)
{
	struct nan_peer peer;
	struct nan_ndp ndp[3];
	struct nan_cm_kaa kaa;
	struct wpabuf *buf;
	const u8 *pos;
	size_t len;
	int ret = -1;

	wpa_printf(MSG_INFO, "TEST: NAN CM KAA NDP list");
	os_memset(&peer, 0, sizeof(peer));
	os_memset(ndp, 0, sizeof(ndp));
	dl_list_init(&peer.ndps);

	/* Two NDPs over the same NDI pair and one over the reverse pair */
	os_memcpy(ndp[0].init_ndi, test_init_ndi, ETH_ALEN);
	os_memcpy(ndp[0].resp_ndi, test_resp_ndi, ETH_ALEN);
	ndp[0].ndp_id = 3;
	os_memcpy(ndp[1].init_ndi, test_resp_ndi, ETH_ALEN);
	os_memcpy(ndp[1].resp_ndi, test_init_ndi, ETH_ALEN);
	ndp[1].ndp_id = 9;
	os_memcpy(ndp[2].init_ndi, test_init_ndi, ETH_ALEN);
	os_memcpy(ndp[2].resp_ndi, test_resp_ndi, ETH_ALEN);
	ndp[2].ndp_id = 7;
	dl_list_add_tail(&peer.ndps, &ndp[0].list);
	dl_list_add_tail(&peer.ndps, &ndp[1].list);
	dl_list_add_tail(&peer.ndps, &ndp[2].list);

	buf = wpabuf_alloc(64);
	if (!buf || nan_cm_build_kaa(&peer, buf) < 0)
		goto out;

	pos = wpabuf_head_u8(buf);
	len = wpabuf_len(buf);
	if (len != NAN_ATTR_HDR_LEN + 1 + 2 * (1 + 2 * ETH_ALEN) + 3 ||
	    pos[0] != NAN_ATTR_KAA ||
	    WPA_GET_LE16(pos + 1) != len - NAN_ATTR_HDR_LEN ||
	    pos[3] != NAN_KAA_CTRL_NDPS_PRESENT ||
	    nan_cm_parse_kaa(pos + NAN_ATTR_HDR_LEN, len - NAN_ATTR_HDR_LEN,
			     &kaa) < 0 ||
	    !kaa.ndps_present || kaa.n_entries != 2 ||
	    !ether_addr_equal(kaa.entries[0].init_ndi, test_init_ndi) ||
	    !ether_addr_equal(kaa.entries[0].resp_ndi, test_resp_ndi) ||
	    kaa.entries[0].n_ndp_ids != 2 ||
	    kaa.entries[0].ndp_ids[0] != 3 || kaa.entries[0].ndp_ids[1] != 7 ||
	    !ether_addr_equal(kaa.entries[1].init_ndi, test_resp_ndi) ||
	    !ether_addr_equal(kaa.entries[1].resp_ndi, test_init_ndi) ||
	    kaa.entries[1].n_ndp_ids != 1 || kaa.entries[1].ndp_ids[0] != 9)
		goto out;

	/* No room for the complete NDP list */
	wpabuf_free(buf);
	buf = wpabuf_alloc(len - 1);
	if (!buf || nan_cm_build_kaa(&peer, buf) == 0)
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: NAN CM KAA NDP list");
	wpabuf_free(buf);
	return ret;
}


static int test_kaa_parse_invalid(void)
{
	u8 data[1 + (NAN_CM_KAA_MAX_ENTRIES + 1) * (1 + 2 * ETH_ALEN)];
	struct nan_cm_kaa kaa;
	unsigned int i;
	u8 *pos;

	wpa_printf(MSG_INFO, "TEST: NAN CM KAA parse invalid");

	/* Empty attribute body */
	if (nan_cm_parse_kaa(data, 0, &kaa) == 0)
		goto fail;

	/* NDP list indicated, but missing */
	data[0] = NAN_KAA_CTRL_NDPS_PRESENT;
	if (nan_cm_parse_kaa(data, 1, &kaa) == 0)
		goto fail;

	/* Entry length shorter than an NDI pair */
	data[1] = 2 * ETH_ALEN - 1;
	os_memset(&data[2], 0, 2 * ETH_ALEN - 1);
	if (nan_cm_parse_kaa(data, 2 * ETH_ALEN + 1, &kaa) == 0)
		goto fail;

	/* Entry length exceeding the attribute */
	data[1] = 2 * ETH_ALEN + 1;
	os_memset(&data[2], 0, 2 * ETH_ALEN);
	if (nan_cm_parse_kaa(data, 2 + 2 * ETH_ALEN, &kaa) == 0)
		goto fail;

	/* More NDI pair entries than supported */
	pos = &data[1];
	for (i = 0; i <= NAN_CM_KAA_MAX_ENTRIES; i++) {
		*pos++ = 2 * ETH_ALEN;
		os_memset(pos, i, 2 * ETH_ALEN);
		pos += 2 * ETH_ALEN;
	}
	if (nan_cm_parse_kaa(data, sizeof(data), &kaa) == 0)
		goto fail;
	if (nan_cm_parse_kaa(data, sizeof(data) - 1 - 2 * ETH_ALEN, &kaa) < 0 ||
	    kaa.n_entries != NAN_CM_KAA_MAX_ENTRIES)
		goto fail;

	return 0;
fail:
	wpa_printf(MSG_ERROR, "FAIL: NAN CM KAA parse invalid");
	return -1;
}


static int test_tna(void)
{
	u8 ids[2 * NAN_ND_TKSA_IDENTITY_LEN];
	struct nan_cm_tna tna;
	struct wpabuf *buf;
	const u8 *pos;
	int ret = -1;

	wpa_printf(MSG_INFO, "TEST: NAN CM TNA build/parse");
	os_memcpy(ids, test_init_ndi, ETH_ALEN);
	os_memcpy(ids + ETH_ALEN, test_resp_ndi, ETH_ALEN);
	os_memcpy(ids + NAN_ND_TKSA_IDENTITY_LEN, test_resp_ndi, ETH_ALEN);
	os_memcpy(ids + NAN_ND_TKSA_IDENTITY_LEN + ETH_ALEN, test_init_ndi,
		  ETH_ALEN);

	/* NM-TKSA termination carries no ND-TKSA list */
	buf = wpabuf_alloc(NAN_ATTR_HDR_LEN + 2);
	if (!buf ||
	    nan_cm_build_tna(buf, NAN_TNA_CTRL_NM_TKSA_TERM, 7, NULL, 0) < 0)
		goto out;
	pos = wpabuf_head_u8(buf);
	if (wpabuf_len(buf) != NAN_ATTR_HDR_LEN + 2 ||
	    pos[0] != NAN_ATTR_TNA || WPA_GET_LE16(pos + 1) != 2 ||
	    nan_cm_parse_tna(pos + NAN_ATTR_HDR_LEN, 2, &tna) < 0 ||
	    tna.ctrl != NAN_TNA_CTRL_NM_TKSA_TERM || tna.reason != 7 ||
	    tna.n_nd_tksas || tna.nd_tksa_ids)
		goto out;

	/* ND-TKSA termination with two identities */
	wpabuf_free(buf);
	buf = wpabuf_alloc(NAN_ATTR_HDR_LEN + 3 + sizeof(ids));
	if (!buf ||
	    nan_cm_build_tna(buf, NAN_TNA_CTRL_ND_TKSA_TERM, 9, ids, 2) < 0)
		goto out;
	pos = wpabuf_head_u8(buf);
	if (wpabuf_len(buf) != NAN_ATTR_HDR_LEN + 3 + sizeof(ids) ||
	    WPA_GET_LE16(pos + 1) != 3 + sizeof(ids) ||
	    nan_cm_parse_tna(pos + NAN_ATTR_HDR_LEN, 3 + sizeof(ids),
			     &tna) < 0 ||
	    tna.ctrl != NAN_TNA_CTRL_ND_TKSA_TERM || tna.reason != 9 ||
	    tna.n_nd_tksas != 2 ||
	    os_memcmp(tna.nd_tksa_ids, ids, sizeof(ids)) != 0)
		goto out;

	/* No room for the ND-TKSA list */
	wpabuf_free(buf);
	buf = wpabuf_alloc(NAN_ATTR_HDR_LEN + 3 + sizeof(ids) - 1);
	if (!buf ||
	    nan_cm_build_tna(buf, NAN_TNA_CTRL_ND_TKSA_TERM, 9, ids, 2) == 0)
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: NAN CM TNA build/parse");
	wpabuf_free(buf);
	return ret;
}


static int test_tna_parse_invalid(void)
{
	u8 data[3 + NAN_ND_TKSA_IDENTITY_LEN];
	struct nan_cm_tna tna;

	wpa_printf(MSG_INFO, "TEST: NAN CM TNA parse invalid");
	os_memset(data, 0, sizeof(data));

	/* Missing Reason Code */
	data[0] = NAN_TNA_CTRL_NM_TKSA_TERM;
	if (nan_cm_parse_tna(data, 1, &tna) == 0)
		goto fail;

	/* No termination type indicated */
	data[0] = 0;
	if (nan_cm_parse_tna(data, 2, &tna) == 0)
		goto fail;

	/* ND-TKSA termination without the ND-TKSA count */
	data[0] = NAN_TNA_CTRL_ND_TKSA_TERM;
	if (nan_cm_parse_tna(data, 2, &tna) == 0)
		goto fail;

	/* ND-TKSA count exceeding the attribute */
	data[2] = 2;
	if (nan_cm_parse_tna(data, sizeof(data), &tna) == 0)
		goto fail;

	/* An empty ND-TKSA list is valid */
	data[2] = 0;
	if (nan_cm_parse_tna(data, 3, &tna) < 0 || tna.n_nd_tksas)
		goto fail;

	return 0;
fail:
	wpa_printf(MSG_ERROR, "FAIL: NAN CM TNA parse invalid");
	return -1;
}


static int test_saqa(void)
{
	u8 req_ctrl = NAN_SAQA_CTRL_TYPE_REQUEST | NAN_SAQA_CTRL_NM_TKSA_QUERY;
	u8 data[2];
	struct nan_cm_saqa saqa;
	struct wpabuf *buf;
	const u8 *pos;
	int ret = -1;

	wpa_printf(MSG_INFO, "TEST: NAN CM SAQA build/parse");
	buf = wpabuf_alloc(NAN_ATTR_HDR_LEN + 2);
	if (!buf || nan_cm_build_saqa(buf, 0x42, req_ctrl) < 0)
		goto out;
	pos = wpabuf_head_u8(buf);
	if (wpabuf_len(buf) != NAN_ATTR_HDR_LEN + 2 ||
	    pos[0] != NAN_ATTR_SAQA || WPA_GET_LE16(pos + 1) != 2 ||
	    nan_cm_parse_saqa(pos + NAN_ATTR_HDR_LEN, 2, &saqa) < 0 ||
	    saqa.dialog_token != 0x42 || saqa.ctrl != req_ctrl)
		goto out;

	/* No room for another attribute */
	if (nan_cm_build_saqa(buf, 0x42, req_ctrl) == 0)
		goto out;

	/* Response */
	data[0] = 0x42;
	data[1] = NAN_SAQA_CTRL_TYPE_RESPONSE | NAN_SAQA_CTRL_NPKSA_QUERY;
	if (nan_cm_parse_saqa(data, 2, &saqa) < 0 ||
	    saqa.ctrl != data[1])
		goto out;

	/* Truncated, unknown type, zero Dialog Token */
	if (nan_cm_parse_saqa(data, 1, &saqa) == 0)
		goto out;
	data[1] = NAN_SAQA_CTRL_TYPE_MASK;
	if (nan_cm_parse_saqa(data, 2, &saqa) == 0)
		goto out;
	data[0] = 0;
	data[1] = NAN_SAQA_CTRL_TYPE_REQUEST;
	if (nan_cm_parse_saqa(data, 2, &saqa) == 0)
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: NAN CM SAQA build/parse");
	wpabuf_free(buf);
	return ret;
}


/**
 * nan_cm_tests - Run NAN Connection Management unit tests
 * Returns: 0 on success, -1 on failure
 */
int nan_cm_tests(void)
{
	if (test_kaa_no_ndps() || test_kaa_ndp_list() ||
	    test_kaa_parse_invalid() || test_tna() ||
	    test_tna_parse_invalid() || test_saqa())
		return -1;
	return 0;
}
