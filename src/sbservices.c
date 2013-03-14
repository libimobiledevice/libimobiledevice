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
#include "debug.h"

/**
 * Locks an sbservices client, used for thread safety.
 *
 * @param client sbservices client to lock.
 */
static void sbs_lock(sbservices_client_t client)
{
	debug_info("SBServices: Locked");
#ifdef WIN32
	EnterCriticalSection(&client->mutex);
#else
	pthread_mutex_lock(&client->mutex);
#endif
}

/**
 * Unlocks an sbservices client, used for thread safety.
 * 
 * @param client sbservices client to unlock
 */
static void sbs_unlock(sbservices_client_t client)
{
	debug_info("SBServices: Unlocked");
#ifdef WIN32
	LeaveCriticalSection(&client->mutex);
#else
	pthread_mutex_unlock(&client->mutex);
#endif
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

/**
 * Connects to the springboardservices service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     sbservices_client_t upon successful return.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client is NULL, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_client_new(idevice_t device, lockdownd_service_descriptor_t service, sbservices_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	sbservices_error_t err = sbservices_error(property_list_service_client_new(device, service, &plistclient));
	if (err != SBSERVICES_E_SUCCESS) {
		return err;
	}

	sbservices_client_t client_loc = (sbservices_client_t) malloc(sizeof(struct sbservices_client_private));
	client_loc->parent = plistclient;
#ifdef WIN32
	InitializeCriticalSection(&client_loc->mutex);
#else
	pthread_mutex_init(&client_loc->mutex, NULL);
#endif

	*client = client_loc;
	return SBSERVICES_E_SUCCESS;
}

/**
 * Disconnects an sbservices client from the device and frees up the
 * sbservices client data.
 *
 * @param client The sbservices client to disconnect and free.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client is NULL, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_client_free(sbservices_client_t client)
{
	if (!client)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t err = sbservices_error(property_list_service_client_free(client->parent));
	client->parent = NULL;
#ifdef WIN32
	DeleteCriticalSection(&client->mutex);
#else
	pthread_mutex_destroy(&client->mutex);
#endif
	free(client);

	return err;
}

/**
 * Gets the icon state of the connected device.
 *
 * @param client The connected sbservices client to use.
 * @param state Pointer that will point to a newly allocated plist containing
 *     the current icon state. It is up to the caller to free the memory.
 * @param format_version A string to be passed as formatVersion along with
 *     the request, or NULL if no formatVersion should be passed. This is only
 *     supported since iOS 4.0 so for older firmware versions this must be set
 *     to NULL.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client or state is invalid, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_get_icon_state(sbservices_client_t client, plist_t *state, const char *format_version)
{
	if (!client || !client->parent || !state)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("getIconState"));
	if (format_version) {
		plist_dict_insert_item(dict, "formatVersion", plist_new_string(format_version));
	}

	sbs_lock(client);

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
	sbs_unlock(client);
	return res;
}

/**
 * Sets the icon state of the connected device.
 *
 * @param client The connected sbservices client to use.
 * @param newstate A plist containing the new iconstate.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client or newstate is NULL, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_set_icon_state(sbservices_client_t client, plist_t newstate)
{
	if (!client || !client->parent || !newstate)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("setIconState"));
	plist_dict_insert_item(dict, "iconState", plist_copy(newstate));

	sbs_lock(client);

	res = sbservices_error(property_list_service_send_binary_plist(client->parent, dict));
	if (res != SBSERVICES_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
	}
	/* NO RESPONSE */

	if (dict) {
		plist_free(dict);
	}
	sbs_unlock(client);
	return res;
}

/**
 * Get the icon of the specified app as PNG data.
 *
 * @param client The connected sbservices client to use.
 * @param bundleId The bundle identifier of the app to retrieve the icon for.
 * @param pngdata Pointer that will point to a newly allocated buffer
 *     containing the PNG data upon successful return. It is up to the caller
 *     to free the memory.
 * @param pngsize Pointer to a uint64_t that will be set to the size of the
 *     buffer pngdata points to upon successful return.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client, bundleId, or pngdata are invalid, or an SBSERVICES_E_* error
 *     code otherwise.
 */
sbservices_error_t sbservices_get_icon_pngdata(sbservices_client_t client, const char *bundleId, char **pngdata, uint64_t *pngsize)
{
	if (!client || !client->parent || !bundleId || !pngdata)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("getIconPNGData"));
	plist_dict_insert_item(dict, "bundleId", plist_new_string(bundleId));

	sbs_lock(client);

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
	sbs_unlock(client);
	return res;
}

/**
 * Gets the interface orientation of the device.
 *
 * @param client The connected sbservices client to use.
 * @param interface_orientation The interface orientation upon successful return.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client or state is invalid, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_get_interface_orientation(sbservices_client_t client, sbservices_interface_orientation_t* interface_orientation)
{
	if (!client || !client->parent || !interface_orientation)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("getInterfaceOrientation"));

	sbs_lock(client);

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
	sbs_unlock(client);
	return res;
}

/**
 * Get the home screen wallpaper as PNG data.
 *
 * @param client The connected sbservices client to use.
 * @param pngdata Pointer that will point to a newly allocated buffer
 *     containing the PNG data upon successful return. It is up to the caller
 *     to free the memory.
 * @param pngsize Pointer to a uint64_t that will be set to the size of the
 *     buffer pngdata points to upon successful return.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client or pngdata are invalid, or an SBSERVICES_E_* error
 *     code otherwise.
 */
sbservices_error_t sbservices_get_home_screen_wallpaper_pngdata(sbservices_client_t client, char **pngdata, uint64_t *pngsize)
{
	if (!client || !client->parent || !pngdata)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("getHomeScreenWallpaperPNGData"));

	sbs_lock(client);

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
	sbs_unlock(client);
	return res;
}
