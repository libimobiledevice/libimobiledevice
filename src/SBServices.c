/*
 * SBServices.c
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

#include "SBServices.h"
#include "property_list_service.h"
#include "utils.h"

/** Locks an sbservices client, done for thread safety stuff.
 *
 * @param client The sbservices client to lock.
 */
static void sbs_lock(sbservices_client_t client)
{
	log_debug_msg("SBServices: Locked\n");
	g_mutex_lock(client->mutex);
}

/** Unlocks an sbservices client, done for thread safety stuff.
 * 
 * @param client The sbservices client to unlock
 */
static void sbs_unlock(sbservices_client_t client)
{
	log_debug_msg("SBServices: Unlocked\n");
	g_mutex_unlock(client->mutex);
}

sbservices_error_t sbservices_client_new(iphone_device_t device, int dst_port, sbservices_client_t *client)
{
	/* makes sure thread environment is available */
	if (!g_thread_supported())
		g_thread_init(NULL);

	if (!device)
		return SBSERVICES_E_INVALID_ARG;

	property_list_service_client_t plistclient = NULL;
	if (property_list_service_client_new(device, dst_port, &plistclient) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return SBSERVICES_E_CONN_FAILED;
	}

	sbservices_client_t client_loc = (sbservices_client_t) malloc(sizeof(struct sbservices_client_int));
	client_loc->parent = plistclient;
	client_loc->mutex = g_mutex_new();

	*client = client_loc;
	return SBSERVICES_E_SUCCESS;
}

sbservices_error_t sbservices_client_free(sbservices_client_t client)
{
	if (!client)
		return SBSERVICES_E_INVALID_ARG;

	property_list_service_client_free(client->parent);
	client->parent = NULL;
	if (client->mutex) {
		g_mutex_free(client->mutex);
	}
	free(client);

	return SBSERVICES_E_SUCCESS;
}

sbservices_error_t sbservices_get_icon_state(sbservices_client_t client, plist_t *state)
{
	if (!client || !client->parent || !state)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("getIconState"));

	sbs_lock(client);

	if (property_list_service_send_binary_plist(client->parent, dict) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		log_debug_msg("%s: could not send plist\n", __func__);
		goto leave_unlock;
	}
	plist_free(dict);
	dict = NULL;

	if (property_list_service_receive_plist(client->parent, state) == PROPERTY_LIST_SERVICE_E_SUCCESS) {
		res = SBSERVICES_E_SUCCESS;
	} else {
		log_debug_msg("%s: could not get icon state!\n", __func__);
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

sbservices_error_t sbservices_set_icon_state(sbservices_client_t client, plist_t newstate)
{
	if (!client || !client->parent || !newstate)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("setIconState"));
	plist_dict_insert_item(dict, "iconState", plist_copy(newstate));

	sbs_lock(client);

	if (property_list_service_send_binary_plist(client->parent, dict) != IPHONE_E_SUCCESS) {
		log_debug_msg("%s: could not send plist\n", __func__);
		goto leave_unlock;
	}
	// NO RESPONSE

leave_unlock:
	if (dict) {
		plist_free(dict);
	}
	sbs_unlock(client);
	return res;
}

sbservices_error_t sbservices_get_icon_pngdata(sbservices_client_t client, const char *bundleId, char **pngdata, uint64_t *pngsize)
{
	if (!client || !client->parent || !pngdata)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("getIconPNGData"));
	plist_dict_insert_item(dict, "bundleId", plist_new_string(bundleId));

	sbs_lock(client);

	if (property_list_service_send_binary_plist(client->parent, dict) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		log_debug_msg("%s: could not send plist\n", __func__);
		goto leave_unlock;
	}
	plist_free(dict);

	dict = NULL;
	if (property_list_service_receive_plist(client->parent, &dict) == PROPERTY_LIST_SERVICE_E_SUCCESS) {
		plist_t node = plist_dict_get_item(dict, "pngData");
		if (node) {
			plist_get_data_val(node, pngdata, pngsize);
		}
		res = SBSERVICES_E_SUCCESS;
	}

leave_unlock:
	if (dict) {
		plist_free(dict);
	}
	sbs_unlock(client);
	return res;

}

