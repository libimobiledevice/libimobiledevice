/*
 * screenshotr.c
 * com.apple.mobile.screenshotr service implementation.
 *
 * Copyright (c) 2010 Nikias Bassen All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <plist/plist.h>
#include <string.h>
#include <stdlib.h>

#include "screenshotr.h"
#include "device_link_service.h"
#include "common/debug.h"

#define SCREENSHOTR_VERSION_INT1 300
#define SCREENSHOTR_VERSION_INT2 0

/**
 * Convert a device_link_service_error_t value to a screenshotr_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An device_link_service_error_t error code
 *
 * @return A matching screenshotr_error_t error code,
 *     SCREENSHOTR_E_UNKNOWN_ERROR otherwise.
 */
static screenshotr_error_t screenshotr_error(device_link_service_error_t err)
{
	switch (err) {
		case DEVICE_LINK_SERVICE_E_SUCCESS:
			return SCREENSHOTR_E_SUCCESS;
		case DEVICE_LINK_SERVICE_E_INVALID_ARG:
			return SCREENSHOTR_E_INVALID_ARG;
		case DEVICE_LINK_SERVICE_E_PLIST_ERROR:
			return SCREENSHOTR_E_PLIST_ERROR;
		case DEVICE_LINK_SERVICE_E_MUX_ERROR:
			return SCREENSHOTR_E_MUX_ERROR;
		case DEVICE_LINK_SERVICE_E_BAD_VERSION:
			return SCREENSHOTR_E_BAD_VERSION;
		default:
			break;
	}
	return SCREENSHOTR_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API screenshotr_error_t screenshotr_client_new(idevice_t device, lockdownd_service_descriptor_t service,
					   screenshotr_client_t * client)
{
	if (!device || !service || service->port == 0 || !client || *client)
		return SCREENSHOTR_E_INVALID_ARG;

	device_link_service_client_t dlclient = NULL;
	screenshotr_error_t ret = screenshotr_error(device_link_service_client_new(device, service, &dlclient));
	if (ret != SCREENSHOTR_E_SUCCESS) {
		return ret;
	}

	screenshotr_client_t client_loc = (screenshotr_client_t) malloc(sizeof(struct screenshotr_client_private));
	client_loc->parent = dlclient;

	/* perform handshake */
	ret = screenshotr_error(device_link_service_version_exchange(dlclient, SCREENSHOTR_VERSION_INT1, SCREENSHOTR_VERSION_INT2));
	if (ret != SCREENSHOTR_E_SUCCESS) {
		debug_info("version exchange failed, error %d", ret);
		screenshotr_client_free(client_loc);
		return ret;
	}

	*client = client_loc;

	return ret;
}

LIBIMOBILEDEVICE_API screenshotr_error_t screenshotr_client_start_service(idevice_t device, screenshotr_client_t * client, const char* label)
{
	screenshotr_error_t err = SCREENSHOTR_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, SCREENSHOTR_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(screenshotr_client_new), &err);
	return err;
}

LIBIMOBILEDEVICE_API screenshotr_error_t screenshotr_client_free(screenshotr_client_t client)
{
	if (!client)
		return SCREENSHOTR_E_INVALID_ARG;
	device_link_service_disconnect(client->parent, NULL);
	screenshotr_error_t err = screenshotr_error(device_link_service_client_free(client->parent));
	free(client);
	return err;
}

LIBIMOBILEDEVICE_API screenshotr_error_t screenshotr_take_screenshot(screenshotr_client_t client, char **imgdata, uint64_t *imgsize)
{
	if (!client || !client->parent || !imgdata)
		return SCREENSHOTR_E_INVALID_ARG;

	screenshotr_error_t res = SCREENSHOTR_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "MessageType", plist_new_string("ScreenShotRequest"));

	res = screenshotr_error(device_link_service_send_process_message(client->parent, dict));
	plist_free(dict);
	if (res != SCREENSHOTR_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	dict = NULL;
	res = screenshotr_error(device_link_service_receive_process_message(client->parent, &dict));
	if (res != SCREENSHOTR_E_SUCCESS) {
		debug_info("could not get screenshot data, error %d", res);
		goto leave;
	}
	if (!dict) {
		debug_info("did not receive screenshot data!");
		res = SCREENSHOTR_E_PLIST_ERROR;
		goto leave;
	}

	plist_t node = plist_dict_get_item(dict, "MessageType");
	char *strval = NULL;
	plist_get_string_val(node, &strval);
	if (!strval || strcmp(strval, "ScreenShotReply")) {
		debug_info("invalid screenshot data received!");
		res = SCREENSHOTR_E_PLIST_ERROR;
		goto leave;
	}
	node = plist_dict_get_item(dict, "ScreenShotData");
	if (!node || plist_get_node_type(node) != PLIST_DATA) {
		debug_info("no PNG data received!");
		res = SCREENSHOTR_E_PLIST_ERROR;
		goto leave;
	}

	plist_get_data_val(node, imgdata, imgsize);
	res = SCREENSHOTR_E_SUCCESS;

leave:
	if (dict)
		plist_free(dict);

	return res;
}
