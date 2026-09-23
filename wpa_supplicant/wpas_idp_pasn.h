/*
 * wpa_supplicant - NAN IDP PASN authentication context
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPAS_IDP_PASN_H
#define WPAS_IDP_PASN_H

struct wpa_supplicant;
struct wpas_idp_session;
struct pasn_data;
struct ieee80211_mgmt;

#ifdef CONFIG_PASN

/**
 * enum idp_pasn_state - IDP PASN handshake state
 */
enum idp_pasn_state {
	IDP_PASN_IDLE,
	IDP_PASN_M1_SENT,
	IDP_PASN_M2_SENT,
	IDP_PASN_COMPLETED,
	IDP_PASN_FAILED,
};


/**
 * struct idp_pasn_context - IDP PASN handshake context
 *
 * Tracks a single IDP PASN handshake. The PASN core maintains the cryptographic
 * state; this structure stores only the IDP-specific information needed for
 * attribute generation and session matching.
 */
struct idp_pasn_context {
	struct wpa_supplicant *wpa_s;
	struct wpas_idp_session *session;

	/* Core PASN data, owns all crypto state */
	struct pasn_data *pasn;

	u8 peer_addr[ETH_ALEN];

	/* Role in the handshake */
	bool is_initiator;

	enum idp_pasn_state state;

	/* IDP attributes carried in the Authentication frames */
	struct wpabuf *idp_req_attrs;
	struct wpabuf *idp_resp_attrs;

	/* PMKID from PASN M1, kept by the responder to copy into PASN M2 */
	u8 m1_pmkid[PMKID_LEN];
	bool m1_pmkid_valid;
};

struct idp_pasn_context * wpas_idp_pasn_init(struct wpa_supplicant *wpa_s,
					     struct wpas_idp_session *session,
					     const u8 *peer_addr,
					     bool is_initiator);
void wpas_idp_pasn_deinit(struct idp_pasn_context *ctx);

bool wpas_idp_pasn_is_idp_auth_frame(const u8 *frame_body,
				     size_t frame_body_len);
bool wpas_idp_pasn_has_session_for_peer(struct wpa_supplicant *wpa_s,
					const u8 *peer_addr);
int wpas_idp_pasn_auth_start(struct wpa_supplicant *wpa_s,
			     const u8 *peer_addr, int freq);
int wpas_idp_pasn_resume_m1(struct wpa_supplicant *wpa_s,
			    struct wpas_idp_session *session,
			    const struct wpabuf *m1_frame, int freq);
int wpas_idp_pasn_send_reject(struct wpa_supplicant *wpa_s,
			      const u8 *peer_addr, struct wpabuf *m1_frame);
int wpas_idp_pasn_auth_rx(struct wpa_supplicant *wpa_s,
			  const struct ieee80211_mgmt *mgmt, size_t len,
			  int freq);

#else /* CONFIG_PASN */

static inline void wpas_idp_pasn_deinit(struct idp_pasn_context *ctx)
{
}

#endif /* CONFIG_PASN */

#endif /* WPAS_IDP_PASN_H */
