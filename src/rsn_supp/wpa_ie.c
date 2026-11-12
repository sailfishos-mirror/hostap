/*
 * wpa_supplicant - WPA/RSN IE and KDE processing
 * Copyright (c) 2003-2018, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "wpa.h"
#include "pmksa_cache.h"
#include "common/ieee802_11_defs.h"
#include "wpa_i.h"
#include "wpa_ie.h"


/**
 * wpa_parse_wpa_ie - Parse WPA/RSN IE
 * @wpa_ie: Pointer to WPA or RSN IE
 * @wpa_ie_len: Length of the WPA/RSN IE
 * @data: Pointer to data area for parsing results
 * Returns: 0 on success, -1 on failure
 *
 * Parse the contents of WPA or RSN IE and write the parsed data into data.
 */
int wpa_parse_wpa_ie(const u8 *wpa_ie, size_t wpa_ie_len,
		     struct wpa_ie_data *data)
{
	if (wpa_ie_len >= 1 && wpa_ie[0] == WLAN_EID_RSN)
		return wpa_parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, data);
	if (wpa_ie_len >= 6 && wpa_ie[0] == WLAN_EID_VENDOR_SPECIFIC &&
	    wpa_ie[1] >= 4 &&
	    WPA_GET_BE32(&wpa_ie[2]) == RSNE_OVERRIDE_IE_VENDOR_TYPE)
		return wpa_parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, data);
	if (wpa_ie_len >= 6 && wpa_ie[0] == WLAN_EID_VENDOR_SPECIFIC &&
	    wpa_ie[1] >= 4 &&
	    WPA_GET_BE32(&wpa_ie[2]) == RSNE_OVERRIDE_2_IE_VENDOR_TYPE)
		return wpa_parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, data);
	return wpa_parse_wpa_ie_wpa(wpa_ie, wpa_ie_len, data);
}


static int wpa_gen_wpa_ie_wpa(u8 *wpa_ie, size_t wpa_ie_len,
			      int pairwise_cipher, int group_cipher,
			      int key_mgmt)
{
	u8 *pos;
	struct wpa_ie_hdr *hdr;
	u32 suite;

	if (wpa_ie_len < sizeof(*hdr) + WPA_SELECTOR_LEN +
	    2 + WPA_SELECTOR_LEN + 2 + WPA_SELECTOR_LEN)
		return -1;

	hdr = (struct wpa_ie_hdr *) wpa_ie;
	hdr->elem_id = WLAN_EID_VENDOR_SPECIFIC;
	RSN_SELECTOR_PUT(hdr->oui, WPA_OUI_TYPE);
	WPA_PUT_LE16(hdr->version, WPA_VERSION);
	pos = (u8 *) (hdr + 1);

	suite = wpa_cipher_to_suite(WPA_PROTO_WPA, group_cipher);
	if (suite == 0) {
		wpa_printf(MSG_WARNING, "Invalid group cipher (%d).",
			   group_cipher);
		return -1;
	}
	RSN_SELECTOR_PUT(pos, suite);
	pos += WPA_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	suite = wpa_cipher_to_suite(WPA_PROTO_WPA, pairwise_cipher);
	if (suite == 0 ||
	    (!wpa_cipher_valid_pairwise(pairwise_cipher) &&
	     pairwise_cipher != WPA_CIPHER_NONE)) {
		wpa_printf(MSG_WARNING, "Invalid pairwise cipher (%d).",
			   pairwise_cipher);
		return -1;
	}
	RSN_SELECTOR_PUT(pos, suite);
	pos += WPA_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	if (key_mgmt == WPA_KEY_MGMT_IEEE8021X) {
		RSN_SELECTOR_PUT(pos, WPA_AUTH_KEY_MGMT_UNSPEC_802_1X);
	} else if (key_mgmt == WPA_KEY_MGMT_PSK) {
		RSN_SELECTOR_PUT(pos, WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X);
	} else if (key_mgmt == WPA_KEY_MGMT_WPA_NONE) {
		RSN_SELECTOR_PUT(pos, WPA_AUTH_KEY_MGMT_NONE);
	} else if (key_mgmt == WPA_KEY_MGMT_CCKM) {
		RSN_SELECTOR_PUT(pos, WPA_AUTH_KEY_MGMT_CCKM);
	} else {
		wpa_printf(MSG_WARNING, "Invalid key management type (%d).",
			   key_mgmt);
		return -1;
	}
	pos += WPA_SELECTOR_LEN;

	/* WPA Capabilities; use defaults, so no need to include it */

	hdr->len = (pos - wpa_ie) - 2;

	WPA_ASSERT((size_t) (pos - wpa_ie) <= wpa_ie_len);

	return pos - wpa_ie;
}


u16 rsn_supp_capab(struct wpa_sm *sm)
{
	u16 capab = 0;

	if (sm->wmm_enabled) {
		/* Advertise 16 PTKSA replay counters when using WMM */
		capab |= RSN_NUM_REPLAY_COUNTERS_16 << 2;
	}
	if (sm->mfp)
		capab |= WPA_CAPABILITY_MFPC;
	if (sm->mfp == 2)
		capab |= WPA_CAPABILITY_MFPR;
	if (sm->ocv)
		capab |= WPA_CAPABILITY_OCVC;
	if (sm->ext_key_id)
		capab |= WPA_CAPABILITY_EXT_KEY_ID_FOR_UNICAST;

	return capab;
}


int wpa_gen_wpa_ie_rsn(u8 *rsn_ie, size_t rsn_ie_len,
		       int pairwise_cipher, int group_cipher,
		       int key_mgmt, int mgmt_group_cipher,
		       struct wpa_sm *sm)
{
	u8 *pos;
	struct rsn_ie_hdr *hdr;
	u32 suite;
	size_t len;

	len = sizeof(*hdr) + RSN_SELECTOR_LEN +
		2 + RSN_SELECTOR_LEN + 2 + RSN_SELECTOR_LEN + 2;
	if (sm->cur_pmksa)
		len += 2 + PMKID_LEN;
#ifdef CONFIG_TESTING_OPTIONS
	if (!sm->cur_pmksa && wpa_sm_test_random_pmkid_count(sm) > 0)
		len += 2 + wpa_sm_test_random_pmkid_count(sm) * PMKID_LEN;
#endif /* CONFIG_TESTING_OPTIONS */
	if (rsn_ie_len < len) {
		wpa_printf(MSG_DEBUG, "RSN: Too short IE buffer (%lu bytes)",
			   (unsigned long) rsn_ie_len);
		return -1;
	}

	hdr = (struct rsn_ie_hdr *) rsn_ie;
	hdr->elem_id = WLAN_EID_RSN;
	WPA_PUT_LE16(hdr->version, RSN_VERSION);
	pos = (u8 *) (hdr + 1);

	suite = wpa_cipher_to_suite(WPA_PROTO_RSN, group_cipher);
	if (suite == 0) {
		wpa_printf(MSG_WARNING, "Invalid group cipher (%d).",
			   group_cipher);
		return -1;
	}
	RSN_SELECTOR_PUT(pos, suite);
	pos += RSN_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	suite = wpa_cipher_to_suite(WPA_PROTO_RSN, pairwise_cipher);
	if (suite == 0 ||
	    (!wpa_cipher_valid_pairwise(pairwise_cipher) &&
	     pairwise_cipher != WPA_CIPHER_NONE)) {
		wpa_printf(MSG_WARNING, "Invalid pairwise cipher (%d).",
			   pairwise_cipher);
		return -1;
	}
	RSN_SELECTOR_PUT(pos, suite);
	pos += RSN_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	if (key_mgmt == WPA_KEY_MGMT_IEEE8021X) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X);
	} else if (key_mgmt == WPA_KEY_MGMT_PSK) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X);
	} else if (key_mgmt == WPA_KEY_MGMT_CCKM) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_CCKM);
#ifdef CONFIG_IEEE80211R
	} else if (key_mgmt == WPA_KEY_MGMT_FT_IEEE8021X) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FT_802_1X);
#ifdef CONFIG_SHA384
	} else if (key_mgmt == WPA_KEY_MGMT_FT_IEEE8021X_SHA384) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FT_802_1X_SHA384);
#endif /* CONFIG_SHA384 */
	} else if (key_mgmt == WPA_KEY_MGMT_FT_PSK) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FT_PSK);
#ifdef CONFIG_PQC
	} else if ((unsigned int) key_mgmt == WPA_KEY_MGMT_FT_PQC_8021X) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FT_802_1X_PQC);
#endif /* CONFIG_PQC */
#endif /* CONFIG_IEEE80211R */
	} else if (key_mgmt == WPA_KEY_MGMT_IEEE8021X_SHA256) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_802_1X_SHA256);
	} else if (key_mgmt == WPA_KEY_MGMT_PSK_SHA256) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_PSK_SHA256);
#ifdef CONFIG_SAE
	} else if (key_mgmt == WPA_KEY_MGMT_SAE) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_SAE);
	} else if (key_mgmt == WPA_KEY_MGMT_SAE_EXT_KEY) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_SAE_EXT_KEY);
	} else if (key_mgmt == WPA_KEY_MGMT_FT_SAE) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FT_SAE);
	} else if (key_mgmt == WPA_KEY_MGMT_FT_SAE_EXT_KEY) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FT_SAE_EXT_KEY);
#endif /* CONFIG_SAE */
	} else if (key_mgmt == WPA_KEY_MGMT_IEEE8021X_SUITE_B_192) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192);
	} else if (key_mgmt == WPA_KEY_MGMT_IEEE8021X_SUITE_B) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_802_1X_SUITE_B);
#ifdef CONFIG_FILS
	} else if (key_mgmt & WPA_KEY_MGMT_FILS_SHA256) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FILS_SHA256);
	} else if (key_mgmt & WPA_KEY_MGMT_FILS_SHA384) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FILS_SHA384);
#ifdef CONFIG_IEEE80211R
	} else if (key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA256) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FT_FILS_SHA256);
	} else if (key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA384) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_FT_FILS_SHA384);
#endif /* CONFIG_IEEE80211R */
#endif /* CONFIG_FILS */
#ifdef CONFIG_OWE
	} else if (key_mgmt & WPA_KEY_MGMT_OWE) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_OWE);
#endif /* CONFIG_OWE */
#ifdef CONFIG_DPP
	} else if (key_mgmt & WPA_KEY_MGMT_DPP) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_DPP);
#endif /* CONFIG_DPP */
#ifdef CONFIG_SHA384
	} else if (key_mgmt == WPA_KEY_MGMT_IEEE8021X_SHA384) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_802_1X_SHA384);
#endif /* CONFIG_SHA384 */
#ifdef CONFIG_ENC_ASSOC
	} else if (key_mgmt == WPA_KEY_MGMT_EPPKE) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_EPPKE);
#ifdef CONFIG_PQC
	} else if (key_mgmt == WPA_KEY_MGMT_PQC_8021X) {
		RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_802_1X_PQC);
#endif /* CONFIG_PQC */
#endif /* CONFIG_ENC_ASSOC */
	} else {
		wpa_printf(MSG_WARNING, "Invalid key management type (%d).",
			   key_mgmt);
		return -1;
	}
	pos += RSN_SELECTOR_LEN;

	/* RSN Capabilities */
	WPA_PUT_LE16(pos, rsn_supp_capab(sm));
	pos += 2;

#ifdef CONFIG_TESTING_OPTIONS
	if (!sm->cur_pmksa && wpa_sm_test_random_pmkid_count(sm) > 0 &&
	    wpa_rsne_inject_random_pmkids(
		    &pos, wpa_sm_test_random_pmkid_count(sm)) < 0)
		return -1;
#endif /* CONFIG_TESTING_OPTIONS */

	if (sm->cur_pmksa) {
		/* PMKID Count (2 octets, little endian) */
		*pos++ = 1;
		*pos++ = 0;
		/* PMKID */
		os_memcpy(pos, sm->cur_pmksa->pmkid, PMKID_LEN);
		pos += PMKID_LEN;
	}

	if (wpa_cipher_valid_mgmt_group(mgmt_group_cipher)) {
		if (!sm->cur_pmksa && !wpa_sm_test_random_pmkid_count(sm)) {
			/* PMKID Count */
			WPA_PUT_LE16(pos, 0);
			pos += 2;
		}

		/* Management Group Cipher Suite */
		RSN_SELECTOR_PUT(pos, wpa_cipher_to_suite(WPA_PROTO_RSN,
							  mgmt_group_cipher));
		pos += RSN_SELECTOR_LEN;
	}

	hdr->len = (pos - rsn_ie) - 2;

	WPA_ASSERT((size_t) (pos - rsn_ie) <= rsn_ie_len);

	return pos - rsn_ie;
}


/**
 * wpa_gen_wpa_ie - Generate WPA/RSN IE based on current security policy
 * @sm: Pointer to WPA state machine data from wpa_sm_init()
 * @wpa_ie: Pointer to memory area for the generated WPA/RSN IE
 * @wpa_ie_len: Maximum length of the generated WPA/RSN IE
 * Returns: Length of the generated WPA/RSN IE or -1 on failure
 */
int wpa_gen_wpa_ie(struct wpa_sm *sm, u8 *wpa_ie, size_t wpa_ie_len)
{
	if (sm->proto == WPA_PROTO_RSN)
		return wpa_gen_wpa_ie_rsn(wpa_ie, wpa_ie_len,
					  sm->pairwise_cipher,
					  sm->group_cipher,
					  sm->key_mgmt, sm->mgmt_group_cipher,
					  sm);
	else
		return wpa_gen_wpa_ie_wpa(wpa_ie, wpa_ie_len,
					  sm->pairwise_cipher,
					  sm->group_cipher,
					  sm->key_mgmt);
}


/*
 * wpa_external_auth_add_rsne - Build an RSNE for external authentication
 * @sm: Pointer to WPA state machine data from wpa_sm_init()
 * @rsne: Buffer in which the RSNE will be written
 * @rsne_len: Length of the RSNE buffer
 * @akmp: Authentication and key management protocol
 * @pairwise_cipher: The pairwise cipher suite
 * @group_cipher: The group addressed data cipher suite
 * @group_mgmt_cipher: The group addressed management cipher suite
 * @rsn_capab: RSN capabilities field
 * @pmkid: PMKID to include in the RSNE, or %NULL if no PMKID
 * Returns: Length of the RSNE or -1 on failure
 */
int wpa_external_auth_add_rsne(struct wpa_sm *sm, u8 *rsne, size_t rsne_len,
			       int akmp, int pairwise_cipher, int group_cipher,
			       int group_mgmt_cipher, u16 rsn_capab,
			       const u8 *pmkid)
{
	struct rsn_ie_hdr *hdr;
	u32 suite;
	u8 *pos;
	size_t len;

	wpa_printf(MSG_DEBUG, "RSN: Ext-Auth: Build RSNE");

	len = sizeof(*hdr) + RSN_SELECTOR_LEN +
		2 + RSN_SELECTOR_LEN + 2 + RSN_SELECTOR_LEN + 2;
	if (pmkid)
		len += 2 + PMKID_LEN;
	if (wpa_cipher_valid_mgmt_group(group_mgmt_cipher)) {
		len += RSN_SELECTOR_LEN;
		if (!pmkid && !wpa_sm_test_random_pmkid_count(sm))
			len += 2;
	}
#ifdef CONFIG_TESTING_OPTIONS
	if (!pmkid && wpa_sm_test_random_pmkid_count(sm) > 0)
		len += 2 + wpa_sm_test_random_pmkid_count(sm) * PMKID_LEN;
#endif /* CONFIG_TESTING_OPTIONS */
	if (rsne_len < len) {
		wpa_printf(MSG_DEBUG, "Ext-Auth: Too short RSNE buffer (%lu bytes)",
			   (unsigned long) rsne_len);
		return -1;
	}

	hdr = (struct rsn_ie_hdr *) rsne;
	hdr->elem_id = WLAN_EID_RSN;
	WPA_PUT_LE16(hdr->version, RSN_VERSION);
	pos = (u8 *) (hdr + 1);

	/* Group cipher */
	suite = wpa_cipher_to_suite(WPA_PROTO_RSN, group_cipher);
	if (!suite || !wpa_cipher_valid_group(group_cipher)) {
		wpa_printf(MSG_INFO,
			   "RSN: Ext-Auth: Invalid group cipher 0x%x",
			   group_cipher);
		return -1;
	}
	RSN_SELECTOR_PUT(pos, suite);
	pos += RSN_SELECTOR_LEN;

	/* Pairwise cipher */
	WPA_PUT_LE16(pos, 1);
	pos += 2;
	suite = wpa_cipher_to_suite(WPA_PROTO_RSN, pairwise_cipher);
	if (!suite ||
	    (!wpa_cipher_valid_pairwise(pairwise_cipher) &&
	     pairwise_cipher != WPA_CIPHER_NONE)) {
		wpa_printf(MSG_INFO,
			   "RSN: Ext-Auth: Invalid pairwise cipher 0x%x",
			   pairwise_cipher);
		return -1;
	}
	RSN_SELECTOR_PUT(pos, suite);
	pos += RSN_SELECTOR_LEN;

	/* AKM suite */
	WPA_PUT_LE16(pos, 1);
	pos += 2;
	suite = wpa_akm_to_suite(akmp);
	if (!suite) {
		wpa_printf(MSG_INFO, "RSN: Ext-Auth: Invalid AKMP 0x%x", akmp);
		return -1;
	}
	RSN_SELECTOR_PUT(pos, suite);
	pos += RSN_SELECTOR_LEN;

	/* RSN Capabilities */
	WPA_PUT_LE16(pos, rsn_capab);
	pos += 2;

#ifdef CONFIG_TESTING_OPTIONS
	if (!pmkid && wpa_sm_test_random_pmkid_count(sm) > 0 &&
	    wpa_rsne_inject_random_pmkids(
		    &pos, wpa_sm_test_random_pmkid_count(sm)) < 0)
		return -1;
#endif /* CONFIG_TESTING_OPTIONS */

	if (pmkid) {
		wpa_printf(MSG_DEBUG, "RSN: Ext-Auth: Adding PMKID");
		/* PMKID Count (2 octets, little endian) */
		WPA_PUT_LE16(pos, 1);
		pos += 2;
		/* PMKID */
		os_memcpy(pos, pmkid, PMKID_LEN);
		pos += PMKID_LEN;
	}

	/* Group Management Cipher Suite */
	if (wpa_cipher_valid_mgmt_group(group_mgmt_cipher)) {
		if (!pmkid && !wpa_sm_test_random_pmkid_count(sm)) {
			/* PMKID Count */
			WPA_PUT_LE16(pos, 0);
			pos += 2;
		}

		/* Management Group Cipher Suite */
		RSN_SELECTOR_PUT(pos, wpa_cipher_to_suite(WPA_PROTO_RSN,
							  group_mgmt_cipher));
		pos += RSN_SELECTOR_LEN;
	}

	hdr->len = (pos - rsne) - 2;

	WPA_ASSERT((size_t) (pos - rsne) <= rsne_len);

	return pos - rsne;
}


/**
 * security_profile_akm_matches - Check if a profile's AKM matches key_mgmt
 * @profile_num: Security Profile number (IEEE P802.11bn/D2.0, Table 9-bb18)
 * @key_mgmt: Negotiated WPA_KEY_MGMT_* value
 * Returns whether the profile's AKM matches key_mgmt
 */
bool security_profile_akm_matches(int profile_num, int key_mgmt)
{
	const struct security_profile_entry *sp;

	sp = sec_prof_get(profile_num);
	if (!sp)
		return false;
	return key_mgmt & sp->key_mgmt;
}


/*
 * security_profile_has_eppke - Does the AP's Security Profile element bitmap
 * advertise an EPPKE profile (0, 1, or 2) usable with @ssid_key_mgmt?
 * @sp: AP's Security Profile element
 * @ssid_key_mgmt: Locally configured WPA_KEY_MGMT_* bitmask
 * Returns: Whether the matching EPPKE profile bit is set
 *
 * Unlike security_profile_get_key_mgmt(), which reports a match whenever
 * the profile's pre-authentication AKM matches an AKM bit configured locally
 * (matching profile 9/10 against SAE-EXT-KEY/FT-SAE-EXT-KEY, too), this helper
 * only considers the three EPPKE profiles themselves. It is used to decide
 * whether the AP intends EPPKE authentication for the current
 * SAE-EXT-KEY/FT-SAE-EXT-KEY connection attempt even though its RSNE does not
 * list the EPPKE AKM suite (IEEE P802.11bn/D2.0, Table 9-bb18: for profiles 1
 * and 2 the RSNE advertises only the pre-authentication AKM).
 *
 */
bool security_profile_has_eppke(const u8 *sp, int ssid_key_mgmt)
{
	u8 bitmap_len;
	const u8 *bitmap;
	int profile;

	if (!sp || sp[1] < 3)
		return false;

	bitmap_len = sp[4] & 0x0F;
	if (sp[1] < 3 + bitmap_len)
		return false;

	bitmap = sp + 5;

	for (profile = SEC_PROF_EPPKE_NO_AUTH;
	     profile <= SEC_PROF_EPPKE_FT_SAE && profile < bitmap_len * 8;
	     profile++) {
		if (!(bitmap[profile / 8] & BIT(profile % 8)))
			continue;
		if (security_profile_akm_matches(profile, ssid_key_mgmt))
			return true;
	}

	return false;
}


/*
 * security_profile_select - Map parameters to a unique profile
 * @akmp: Negotiated AKM (WPA_KEY_MGMT_*)
 * @pairwise_cipher: Negotiated pairwise cipher (WPA_CIPHER_*)
 * @eap_over_auth: true when EAP is carried over Authentication frames
 *                 (i.e., derive_ptk / eap_over_auth_frame is active).
 *                 Used to disambiguate 802.1X _AUTH profiles (3-7) from the
 *                 corresponding non-_AUTH profiles (11-15) that share the
 *                 same AKM.  Must be false for non-802.1X AKMs.
 * @eppke: Whether EPPKE is used
 * @enabled_profiles: -1 terminated array of enabled security profile numbers
 *     or NULL.
 * @bitmap: AP's Security Profile Bitmap (from the Security Profile element)
 * @bitmap_len: Length of @bitmap in bytes
 * Returns: Selected profile number (0-119) on success, -1 if no match found.
 *
 * This is the authoritative function for profile selection. It resolves all
 * ambiguities that arise when multiple profiles share the same AKM:
 *
 *   EPPKE profiles (0, 1, 2):
 *     Disambiguated by @akmp itself - the driver already carries the
 *     pre-authentication AKM in the akmp field. Per IEEE P802.11bn/D2.0,
 *     Table 9-bb18, the AKMP for profiles 1 and 2 refers specifically
 *     to the EXT_KEY (hash-to-element) AKM variants, not the legacy ones:
 *       WPA_KEY_MGMT_EPPKE          -> Profile 0 (EPPKE_NO_AUTH)
 *       WPA_KEY_MGMT_SAE_EXT_KEY    -> Profile 1 (EPPKE_SAE)
 *       WPA_KEY_MGMT_FT_SAE_EXT_KEY -> Profile 2 (EPPKE_FT_SAE)
 *
 *   802.1X _AUTH vs non-_AUTH profiles (3-7 vs 11-15):
 *     Disambiguated by @eap_over_auth:
 *       true  -> _AUTH profiles (EAP over Authentication frames)
 *       false -> non-_AUTH profiles (EAP in EAPOL frames)
 *     Callers derive this flag from negotiated parameters and local
 *     capabilities.
 */
const struct security_profile_entry *
security_profile_select(int akmp, int pairwise_cipher,
			bool eap_over_auth, bool eppke,
			const int *enabled_profiles,
			const u8 *bitmap, size_t bitmap_len)
{
	unsigned int profile;
	const struct security_profile_entry *sp;

	if (!bitmap || bitmap_len == 0)
		return NULL;

	/* All defined profiles (0-15) require GCMP-256 as pairwise cipher */
	if (pairwise_cipher != WPA_CIPHER_GCMP_256)
		return NULL;

	for (profile = 0;
	     profile <= SEC_PROF_MAX && profile < bitmap_len * 8;
	     profile++) {
		u8 byte = bitmap[profile / 8];

		/* Skip profiles not advertised by the AP */
		if (!(byte & BIT(profile % 8)))
			continue;

		sp = sec_prof_get(profile);
		if (!sp)
			continue;

		/* PQC security profiles need to be explicitly enabled */
		if (sec_prof_pqc(profile) &&
		    !sec_prof_list_includes(enabled_profiles, profile))
			continue;

		/* Check AKM match using the per-profile mapping */
		if (!(akmp & sp->key_mgmt))
			continue;

		/*
		 * Disambiguate 802.1X _AUTH profiles (EAP over Authentication
		 * frames) from non-_AUTH profiles (EAP in EAPOL frames). Both
		 * groups share the same AKM, so eap_over_auth is the only
		 * distinguishing parameter available.
		 *
		 * _AUTH profiles  (3-7): require eap_over_auth == true
		 * non-_AUTH profiles (11-15): require eap_over_auth == false
		 */
		if ((eap_over_auth && !sp->ieee8021x_auth_frame) ||
		    (!eap_over_auth && sp->ieee8021x_auth_frame))
			continue;

		/* Handle the profile 1 vs. 9 based on whether EPPKE is used */
		if (sp->key_mgmt == (WPA_KEY_MGMT_EPPKE |
				     WPA_KEY_MGMT_SAE_EXT_KEY) &&
		    sp->assoc_frame_encrypt != eppke)
			continue;

		return sp;
	}

	return NULL;
}


int wpa_gen_rsnxe(struct wpa_sm *sm, u8 *rsnxe, size_t rsnxe_len)
{
	u8 *pos = rsnxe;
	u64 capab, tmp;
	size_t flen;

	capab = wpa_sm_get_rsnxe_capab(sm);

	if (!capab)
		return 0; /* no supported extended RSN capabilities */
	tmp = capab;
	flen = 0;
	while (tmp) {
		flen++;
		tmp >>= 8;
	}
	if (rsnxe_len < 2 + flen)
		return -1;
	capab |= flen - 1; /* bit 0-3 = Field length (n - 1) */

	*pos++ = WLAN_EID_RSNX;
	*pos++ = flen;
	while (capab) {
		*pos++ = capab & 0xff;
		capab >>= 8;
	}

	return pos - rsnxe;
}


/*
 * wpa_sm_get_rsnxe_capab - Compute Extended RSN Capabilities value from wpa_sm
 * @sm: WPA state machine
 * Returns the Extended RSN Capabilities value that wpa_gen_rsnxe() encodes into
 * the Extended RSN Capabilities field of the RSNXE, without the length prefix
 * bits (bits 0-3) being set. The caller is responsible for inserting the length
 * prefix before encoding.
 *
 * This is the single source of extended RSN capabilities. Both wpa_gen_rsnxe()
 * and security_profile_build_sta() call this function to guarantee that the
 * RSNXE and the Security Profile element's Extended RSN Capabilities field
 * always carry identical values.
 */
u64 wpa_sm_get_rsnxe_capab(struct wpa_sm *sm)
{
	u64 capab = 0;

	if (wpa_key_mgmt_sae(sm->key_mgmt) &&
	    (sm->sae_pwe == SAE_PWE_HASH_TO_ELEMENT ||
	     sm->sae_pwe == SAE_PWE_BOTH || sm->sae_pk)) {
		capab |= BIT(WLAN_RSNX_CAPAB_SAE_H2E);
#ifdef CONFIG_SAE_PK
		if (sm->sae_pk)
			capab |= BIT(WLAN_RSNX_CAPAB_SAE_PK);
#endif /* CONFIG_SAE_PK */
	}

	if (sm->secure_ltf)
		capab |= BIT(WLAN_RSNX_CAPAB_SECURE_LTF);
	if (sm->secure_rtt)
		capab |= BIT(WLAN_RSNX_CAPAB_SECURE_RTT);
	if (sm->prot_range_neg)
		capab |= BIT(WLAN_RSNX_CAPAB_URNM_MFPR);
	if (sm->prot_range_neg_x20)
		capab |= BIT(WLAN_RSNX_CAPAB_URNM_MFPR_X20);
	if (sm->ssid_protection)
		capab |= BIT(WLAN_RSNX_CAPAB_SSID_PROTECTION);
	if (sm->spp_amsdu)
		capab |= BIT(WLAN_RSNX_CAPAB_SPP_A_MSDU);
	if (sm->sae_pw_id_change)
		capab |= BIT_ULL(WLAN_RSNX_CAPAB_SAE_PW_ID_CHANGE);
#ifdef CONFIG_ENC_ASSOC
	if (sm->assoc_encryption)
		capab |= BIT(WLAN_RSNX_CAPAB_ASSOC_FRAME_ENCRYPTION) |
			BIT(WLAN_RSNX_CAPAB_KEK_IN_PASN);
#endif /* CONFIG_ENC_ASSOC */
#ifdef CONFIG_PMKSA_PRIVACY
	if (sm->pmksa_privacy)
		capab |= BIT(WLAN_RSNX_CAPAB_PMKSA_CACHING_PRIVACY);
#endif /* CONFIG_PMKSA_PRIVACY */
#ifdef CONFIG_IEEE8021X_AUTH
	if (wpa_key_mgmt_wpa_ieee8021x(sm->key_mgmt &
				       ~WPA_KEY_MGMT_IEEE8021X) &&
	     sm->eap_over_auth_frame)
		capab |= BIT(WLAN_RSNX_CAPAB_802_1X_IN_AUTH_FRAMES);
#endif /* CONFIG_IEEE8021X_AUTH */

	return capab;
}


/**
 * security_profile_build_sta - Build Security Profile element for STA TX
 * @sm: WPA state machine - same instance used by wpa_gen_wpa_ie_rsn() and
 *      wpa_gen_rsnxe(). All capability fields are derived from local state,
 *      not from the AP's advertised Security Profile element.
 * @selected_profile_num: Single profile number the STA has selected (0-119).
 *      Only this profile's bit is set in the Security Profile Bitmap
 *      (IEEE P802.11bn/D2.0, 37.33).
 * @buf: Output buffer
 * @buf_len: Size of output buffer
 * Returns: Number of bytes written, or -1 on error.
 *
 * Thin wrapper over security_profile_build() for the SME-in-wpa_supplicant
 * case: derives RSN Capabilities from rsn_supp_capab(sm) - the same function
 * used by wpa_gen_wpa_ie_rsn() — and RSNXE from wpa_gen_rsnxe(sm, ...) - the
 * same helper used to build the STA's actual RSNXE - so the Security Profile
 * element always carries capability values identical to the STA's RSNE and
 * RSNXE (IEEE P802.11bn/D2.0, 9.4.2.369).
 */
int security_profile_build_sta(struct wpa_sm *sm,
			       int selected_profile_num,
			       u8 *buf, size_t buf_len)
{
	u16 rsn_caps;
	u8 rsnxe[257];
	int rsnxe_len;

	if (!sm)
		return -1;

	/*
	 * Reduced RSN Capabilities (IEEE P802.11bn/D2.0, Figure 9-aa75) is
	 * derived from rsn_supp_capab(sm) - the same function used by
	 * wpa_gen_wpa_ie_rsn() - so this field always matches the RSN
	 * Capabilities field in the STA's RSNE.
	 *
	 * Extended RSN Capabilities (IEEE P802.11bn/D2.0, Table 9-408) is
	 * derived from the full RSNXE built by wpa_gen_rsnxe(sm, ...) - the
	 * same helper used to build the STA's actual RSNXE - so this field
	 * always matches the STA's RSNXE.
	 */
	rsn_caps = rsn_supp_capab(sm);

	rsnxe_len = wpa_gen_rsnxe(sm, rsnxe, sizeof(rsnxe));
	if (rsnxe_len < 0)
		return -1;

	return security_profile_build(rsn_caps,
				      rsnxe_len > 0 ? rsnxe : NULL,
				      (size_t) rsnxe_len,
				      selected_profile_num, buf, buf_len);
}


/**
 * security_profile_build - Build Security Profile element from explicit
 *                          RSN Capabilities and RSNXE inputs
 * @rsn_capab: RSN Capabilities field value (WPA_CAPABILITY_* bits), in the
 *      same wire format as written by wpa_gen_wpa_ie_rsn() / passed to
 *      wpa_external_auth_add_rsne(). For the SME-in-wpa_supplicant path this is
 *      rsn_supp_capab(sm); for external authentication (SME-in-driver) this
 *      is the driver-provided rsn_capab value (e.g., struct external_auth /
 *      struct wpa_pasn_auth_work rsn_capab field) that was actually placed
 *      in the negotiated RSNE.
 * @rsnxe_ie: Full RSNXE (starting at the Element ID octet, i.e.
 *      EID + Length + body) that was actually negotiated/sent, or %NULL if
 *      no RSNXE is present. For the SME-in-wpa_supplicant path this is
 *      generated fresh via wpa_gen_rsnxe(sm, ...); for external authentication
 *      this is the driver-provided RSNXE (e.g.,
 *      struct external_auth::rsnxe_data or the awork/sme ext_rsnxe buffer) that
 *      were copied verbatim into the actual Authentication/(Re)Association
 *      Request frame.
 * @rsnxe_len: Length of @rsnxe in bytes, or 0 if @rsnxe is %NULL.
 * @selected_profile_num: Single profile number the STA has selected (0-119).
 *      Only this profile's bit is set in the Security Profile Bitmap.
 * @buf: Output buffer
 * @buf_len: Size of output buffer
 * Returns: Number of bytes written, or -1 on error.
 *
 * This is the single authoritative, driver-agnostic core builder for the
 * Security Profile element (IEEE P802.11bn/D2.0, 9.4.2.369, Figure 9-aa74,
 * 37.33, Table 9-bb18).
 *
 * Because the Extended RSN Capabilities field of the Security Profile
 * element uses the identical wire format as the RSNXE body (length prefix in
 * bits 0-3 of the first octet), the RSNXE body bytes are copied verbatim from
 * @rsnxe without any re-derivation. This guarantees the Security Profile
 * element always reflects exactly what was negotiated/sent - whether that
 * negotiation happened in wpa_sm (SME-in-wpa_supplicant) or in the driver
 * (external authentication) - rather than re-deriving capabilities from
 * local wpa_sm state that may not reflect the driver's actual negotiation.
 */
int security_profile_build(u16 rsn_capab, const u8 *rsnxe, size_t rsnxe_len,
			   int selected_profile_num, u8 *buf, size_t buf_len)
{
	u8 *pos = buf;
	u8 *len_pos;
	u8 reduced_rsn_caps = 0;
	const u8 *ext_rsn_body;
	size_t ext_rsn_len;
	size_t bitmap_len;
	size_t total;
	static const u8 ext_rsn_min[1] = { 0 };

	if (selected_profile_num < 0 || selected_profile_num > SEC_PROF_MAX)
		return -1;

	/* Reduced RSN Capabilities (Figure 9-aa75): B0=ExtKeyID, B1=OCVC */
	if (rsn_capab & WPA_CAPABILITY_EXT_KEY_ID_FOR_UNICAST)
		reduced_rsn_caps |= SEC_PROF_REDUCED_RSN_CAPA_EXT_KEY_ID;
	if (rsn_capab & WPA_CAPABILITY_OCVC)
		reduced_rsn_caps |= SEC_PROF_REDUCED_RSN_CAPA_OCVC;

	/*
	 * Extended RSN Capabilities (Table 9-408): copy the RSNXE body
	 * verbatim from the actually negotiated/sent RSNXE (skip the
	 * EID + Length header of @rsnxe_ie). If no RSNXE is present, encode
	 * the minimum 1-octet field with all bits (including the length
	 * prefix) set to 0, per Table 9-408.
	 */
	if (rsnxe && rsnxe_len >= 2 && rsnxe[1] > 0 &&
	    rsnxe_len >= (size_t) (2 + rsnxe[1])) {
		ext_rsn_body = rsnxe + 2;
		ext_rsn_len = rsnxe[1];
	} else {
		ext_rsn_body = ext_rsn_min;
		ext_rsn_len = sizeof(ext_rsn_min);
	}

	/*
	 * Security Profile Bitmap: one bit per profile number.
	 * Only the selected profile's bit is set (37.33).
	 * Profile numbers 0-7 fit in 1 octet, 8-15 in 2 octets, etc.
	 */
	bitmap_len = (size_t) (selected_profile_num / 8) + 1;

	/* EID(1) + Len(1) + EID_EXT(1) + ReducedRSNCaps(1) +
	 * SecProfInd(1) + bitmap(bitmap_len) + ext_rsn(ext_rsn_len) */
	total = 2 + 1 + 1 + 1 + bitmap_len + ext_rsn_len;
	if (buf_len < total)
		return -1;

	*pos++ = WLAN_EID_EXTENSION;
	len_pos = pos++; /* Length - filled in at end */
	/* Element ID Extension */
	*pos++ = WLAN_EID_EXT_SECURITY_PROFILE;

	/* Reduced RSN Capabilities (1 octet, IEEE P802.11bn/D2.0,
	 * Figure 9-aa75) */
	*pos++ = reduced_rsn_caps;

	/*
	 * Security Profile Indication (1 octet, IEEE P802.11bn/D2.0,
	 * Figure 9-aa76):
	 * B0-B3 = Number Of Octets Of Security Profile Bitmap
	 * B4-B7 = Number Of Vendor Specific Security Profiles (0 here)
	 */
	*pos++ = (u8) (bitmap_len & 0x0F);

	/* Security Profile Bitmap: bit X = 1 for selected_profile_num */
	os_memset(pos, 0, bitmap_len);
	pos[selected_profile_num / 8] |= BIT(selected_profile_num % 8);
	pos += bitmap_len;

	/* Vendor Specific Security Profile List: empty (0 vendor profiles) */

	/* Extended RSN Capabilities (variable, IEEE P802.11bn/D2.0,
	 * Table 9-408): verbatim copy */
	os_memcpy(pos, ext_rsn_body, ext_rsn_len);
	pos += ext_rsn_len;

	/* Fill the Length field (excludes EID and Length bytes, includes
	 * EID_EXT) */
	*len_pos = (u8) (pos - len_pos - 1);

	return pos - buf;
}


/**
 * security_profile_build_empty - Build Security Profile element indicating no
 *                                security profile
 * @buf: Output buffer
 * @buf_len: Size of output buffer
 * Returns: Number of bytes written, or -1 on error.
 *
 * Used by a non-AP STA with security profiles activated when the AP does not
 * advertise a Security Profile element. In such an element, the Reduced RSN
 * Capabilities field is reserved, the Security Profile Indication field
 * indicates no Security Profile Bitmap and no vendor specific security
 * profiles, and the Field Length subfield of the Extended RSN Capabilities
 * field is set to 0 with the remaining bits reserved (IEEE P802.11bn/D2.1,
 * 12.2.6).
 */
int security_profile_build_empty(u8 *buf, size_t buf_len)
{
	u8 *pos = buf;

	/* EID(1) + Len(1) + EID_EXT(1) + ReducedRSNCaps(1) +
	 * SecProfInd(1) + ExtRSNCaps(1) */
	if (buf_len < 6)
		return -1;

	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 4;
	*pos++ = WLAN_EID_EXT_SECURITY_PROFILE;
	*pos++ = 0; /* Reduced RSN Capabilities: reserved */
	*pos++ = 0; /* Security Profile Indication: no security profiles */
	*pos++ = 0; /* Extended RSN Capabilities: Field Length 0, reserved */

	return pos - buf;
}
