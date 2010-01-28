/*
 * sbservices.c
 * SpringBoard Services implementation.
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
#include <arpa/inet.h>
#include <plist/plist.h>

#include "sbservices.h"
#include "property_list_service.h"
#include "debug.h"

/** Locks an sbservices client, done for thread safety stuff.
 *
 * @param client The sbservices client to lock.
 */
static void sbs_lock(sbservices_client_t client)
{
	debug_info("SBServices: Locked");
	g_mutex_lock(client->mutex);
}

/** Unlocks an sbservices client, done for thread safety stuff.
 * 
 * @param client The sbservices client to unlock
 */
static void sbs_unlock(sbservices_client_t client)
{
	debug_info("SBServices: Unlocked");
	g_mutex_unlock(client->mutex);
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
 * Creates a new sbservices client.
 *
 * @param device The device to connect to.
 * @param port The port on device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     sbservices_client_t upon successful return.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client is NULL, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_client_new(idevice_t device, uint16_t port, sbservices_client_t *client)
{
	/* makes sure thread environment is available */
	if (!g_thread_supported())
		g_thread_init(NULL);

	if (!device)
		return SBSERVICES_E_INVALID_ARG;

	property_list_service_client_t plistclient = NULL;
	sbservices_error_t err = sbservices_error(property_list_service_client_new(device, port, &plistclient));
	if (err != SBSERVICES_E_SUCCESS) {
		return err;
	}

	sbservices_client_t client_loc = (sbservices_client_t) malloc(sizeof(struct sbservices_client_int));
	client_loc->parent = plistclient;
	client_loc->mutex = g_mutex_new();

	*client = client_loc;
	return SBSERVICES_E_SUCCESS;
}

/**
 * Frees an sbservices client.
 *
 * @param client The sbservices client to free.
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
	if (client->mutex) {
		g_mutex_free(client->mutex);
	}
	free(client);

	return err;
}

/**
 * Gets the icon state of the connected device.
 *
 * @param client The connected sbservices client to use.
 * @param state Pointer that will point to a newly allocated plist containing
 *     the current icon state. It is up to the caller to free the memory.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client or state is invalid, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_get_icon_state(sbservices_client_t client, plist_t *state)
{
	if (!client || !client->parent || !state)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("getIconState"));

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
	// NO RESPONSE

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

