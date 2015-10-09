/*
 * sbservices.c
 * com.apple.springboardservices service implementation.
 *
 * Copyright (c) 2009 Nikias Bassen, All Rights Reserved.
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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <plist/plist.h>

#include "sbservices.h"
#include "property_list_service.h"
#include "common/debug.h"

/**
 * Locks an sbservices client, used for thread safety.
 *
 * @param client sbservices client to lock.
 */
static void sbservices_lock(sbservices_client_t client)
{
	debug_info("Locked");
	mutex_lock(&client->mutex);
}

/**
 * Unlocks an sbservices client, used for thread safety.
 *
 * @param client sbservices client to unlock
 */
static void sbservices_unlock(sbservices_client_t client)
{
	debug_info("Unlocked");
	mutex_unlock(&client->mutex);
}

/**
 * Convert a property_list_service_error_t value to a sbservices_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err A property_list_service_error_t error code
 *
 * @return A matching sbservices_error_t error code,
 *     SBSERVICES_E_UNKNOWN_ERROR otherwise.
 */
static sbservices_error_t sbservices_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return SBSERVICES_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return SBSERVICES_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return SBSERVICES_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return SBSERVICES_E_CONN_FAILED;
		default:
			break;
	}
	return SBSERVICES_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API sbservices_error_t sbservices_client_new(idevice_t device, lockdownd_service_descriptor_t service, sbservices_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	sbservices_error_t err = sbservices_error(property_list_service_client_new(device, service, &plistclient));
	if (err != SBSERVICES_E_SUCCESS) {
		return err;
	}

	sbservices_client_t client_loc = (sbservices_client_t) malloc(sizeof(struct sbservices_client_private));
	client_loc->parent = plistclient;
	mutex_init(&client_loc->mutex);

	*client = client_loc;
	return SBSERVICES_E_SUCCESS;
}

LIBIMOBILEDEVICE_API sbservices_error_t sbservices_client_start_service(idevice_t device, sbservices_client_t * client, const char* label)
{
	sbservices_error_t err = SBSERVICES_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, SBSERVICES_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(sbservices_client_new), &err);
	return err;
}

LIBIMOBILEDEVICE_API sbservices_error_t sbservices_client_free(sbservices_client_t client)
{
	if (!client)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t err = sbservices_error(property_list_service_client_free(client->parent));
	client->parent = NULL;
	mutex_destroy(&client->mutex);
	free(client);

	return err;
}

LIBIMOBILEDEVICE_API sbservices_error_t sbservices_get_icon_state(sbservices_client_t client, plist_t *state, const char *format_version)
{
	if (!client || !client->parent || !state)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "command", plist_new_string("getIconState"));
	if (format_version) {
		plist_dict_set_item(dict, "formatVersion", plist_new_string(format_version));
	}

	sbservices_lock(client);

	res = sbservices_error(property_list_service_send_binary_plist(client->parent, dict));
	if (res != SBSERVICES_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		goto leave_unlock;
	}
	plist_free(dict);
	dict = NULL;

	res = sbservices_error(property_list_service_receive_plist(client->parent, state));
	if (res != SBSERVICES_E_SUCCESS) {
		debug_info("could not get icon state, error %d", res);
		if (*state) {
			plist_free(*state);
			*state = NULL;
		}
	}

leave_unlock:
	if (dict) {
		plist_free(dict);
	}
	sbservices_unlock(client);
	return res;
}

LIBIMOBILEDEVICE_API sbservices_error_t sbservices_set_icon_state(sbservices_client_t client, plist_t newstate)
{
	if (!client || !client->parent || !newstate)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "command", plist_new_string("setIconState"));
	plist_dict_set_item(dict, "iconState", plist_copy(newstate));

	sbservices_lock(client);

	res = sbservices_error(property_list_service_send_binary_plist(client->parent, dict));
	if (res != SBSERVICES_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
	}
	/* NO RESPONSE */

	if (dict) {
		plist_free(dict);
	}
	sbservices_unlock(client);
	return res;
}

LIBIMOBILEDEVICE_API sbservices_error_t sbservices_get_icon_pngdata(sbservices_client_t client, const char *bundleId, char **pngdata, uint64_t *pngsize)
{
	if (!client || !client->parent || !bundleId || !pngdata)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "command", plist_new_string("getIconPNGData"));
	plist_dict_set_item(dict, "bundleId", plist_new_string(bundleId));

	sbservices_lock(client);

	res = sbservices_error(property_list_service_send_binary_plist(client->parent, dict));
	if (res != SBSERVICES_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		goto leave_unlock;
	}
	plist_free(dict);

	dict = NULL;
	res = sbservices_error(property_list_service_receive_plist(client->parent, &dict));
	if (res	== SBSERVICES_E_SUCCESS) {
		plist_t node = plist_dict_get_item(dict, "pngData");
		if (node) {
			plist_get_data_val(node, pngdata, pngsize);
		}
	}

leave_unlock:
	if (dict) {
		plist_free(dict);
	}
	sbservices_unlock(client);
	return res;
}

LIBIMOBILEDEVICE_API sbservices_error_t sbservices_get_interface_orientation(sbservices_client_t client, sbservices_interface_orientation_t* interface_orientation)
{
	if (!client || !client->parent || !interface_orientation)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "command", plist_new_string("getInterfaceOrientation"));

	sbservices_lock(client);

	res = sbservices_error(property_list_service_send_binary_plist(client->parent, dict));
	if (res != SBSERVICES_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		goto leave_unlock;
	}
	plist_free(dict);
	dict = NULL;

	res = sbservices_error(property_list_service_receive_plist(client->parent, &dict));
	if (res	== SBSERVICES_E_SUCCESS) {
		plist_t node = plist_dict_get_item(dict, "interfaceOrientation");
		if (node) {
			uint64_t value = SBSERVICES_INTERFACE_ORIENTATION_UNKNOWN;
			plist_get_uint_val(node, &value);
			*interface_orientation = (sbservices_interface_orientation_t)value;
		}
	}

leave_unlock:
	if (dict) {
		plist_free(dict);
	}
	sbservices_unlock(client);
	return res;
}

LIBIMOBILEDEVICE_API sbservices_error_t sbservices_get_home_screen_wallpaper_pngdata(sbservices_client_t client, char **pngdata, uint64_t *pngsize)
{
	if (!client || !client->parent || !pngdata)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "command", plist_new_string("getHomeScreenWallpaperPNGData"));

	sbservices_lock(client);

	res = sbservices_error(property_list_service_send_binary_plist(client->parent, dict));
	if (res != SBSERVICES_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		goto leave_unlock;
	}
	plist_free(dict);

	dict = NULL;
	res = sbservices_error(property_list_service_receive_plist(client->parent, &dict));
	if (res	== SBSERVICES_E_SUCCESS) {
		plist_t node = plist_dict_get_item(dict, "pngData");
		if (node) {
			plist_get_data_val(node, pngdata, pngsize);
		}
	}

leave_unlock:
	if (dict) {
		plist_free(dict);
	}
	sbservices_unlock(client);
	return res;
}
