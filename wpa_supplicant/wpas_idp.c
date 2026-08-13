/*
 * wpa_supplicant - NAN IEEE Data Path (IDP)
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "wpa_supplicant_i.h"
#include "wpas_idp.h"


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

	global->idp = idp;

	wpa_printf(MSG_DEBUG, "IDP: Module initialized");
	return 0;
}


/**
 * wpas_idp_deinit - Deinitialize IDP module
 * @global: Pointer to global wpa_supplicant context
 */
void wpas_idp_deinit(struct wpa_global *global)
{
	struct wpas_idp_info *idp;

	if (!global || !global->idp)
		return;

	idp = global->idp;

	os_free(idp);
	global->idp = NULL;

	wpa_printf(MSG_DEBUG, "IDP: Module deinitialized");
}
