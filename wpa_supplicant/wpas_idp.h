/*
 * wpa_supplicant - NAN IEEE Data Path (IDP)
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPAS_IDP_H
#define WPAS_IDP_H

struct wpa_global;

/**
 * struct wpas_idp_info - Global IDP context
 */
struct wpas_idp_info {
	struct wpa_global *global;
};

int wpas_idp_init(struct wpa_global *global);
void wpas_idp_deinit(struct wpa_global *global);

#endif /* WPAS_IDP_H */
