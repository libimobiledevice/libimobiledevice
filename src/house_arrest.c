/*
 * house_arrest.c
 * com.apple.mobile.house_arrest service implementation.
 *
 * Copyright (c) 2010 Nikias Bassen, All Rights Reserved.
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

#include "house_arrest.h"
#include "property_list_service.h"
#include "afc.h"
#include "common/debug.h"

/**
 * Convert a property_list_service_error_t value to a house_arrest_error_t
 * value. Used internally to get correct error codes.
 *
 * @param err A property_list_service_error_t error code
 *
 * @return A matching house_arrest_error_t error code,
 *     HOUSE_ARREST_E_UNKNOWN_ERROR otherwise.
 */
static house_arrest_error_t house_arrest_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return HOUSE_ARREST_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return HOUSE_ARREST_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return HOUSE_ARREST_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return HOUSE_ARREST_E_CONN_FAILED;
		default:
			break;
	}
	return HOUSE_ARREST_E_UNKNOWN_ERROR;
}

house_arrest_error_t house_arrest_client_new(idevice_t device, lockdownd_service_descriptor_t service, house_arrest_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	house_arrest_error_t err = house_arrest_error(property_list_service_client_new(device, service, &plistclient));
	if (err != HOUSE_ARREST_E_SUCCESS) {
		return err;
	}

	house_arrest_client_t client_loc = (house_arrest_client_t) malloc(sizeof(struct house_arrest_client_private));
	client_loc->parent = plistclient;
	client_loc->mode = HOUSE_ARREST_CLIENT_MODE_NORMAL;

	*client = client_loc;
	return HOUSE_ARREST_E_SUCCESS;
}

house_arrest_error_t house_arrest_client_start_service(idevice_t device, house_arrest_client_t * client, const char* label)
{
	house_arrest_error_t err = HOUSE_ARREST_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, HOUSE_ARREST_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(house_arrest_client_new), &err);
	return err;
}

house_arrest_error_t house_arrest_client_free(house_arrest_client_t client)
{
	if (!client)
		return HOUSE_ARREST_E_INVALID_ARG;

	house_arrest_error_t err = HOUSE_ARREST_E_SUCCESS;
	if (client->parent && client->parent->parent->connection) {
		house_arrest_error(property_list_service_client_free(client->parent));
	}
	client->parent = NULL;
	free(client);

	return err;
}

house_arrest_error_t house_arrest_send_request(house_arrest_client_t client, plist_t dict)
{
	if (!client || !client->parent || !dict)
		return HOUSE_ARREST_E_INVALID_ARG;
	if (plist_get_node_type(dict) != PLIST_DICT)
		return HOUSE_ARREST_E_PLIST_ERROR;
	if (client->mode != HOUSE_ARREST_CLIENT_MODE_NORMAL)
		return HOUSE_ARREST_E_INVALID_MODE;

	house_arrest_error_t res = house_arrest_error(property_list_service_send_xml_plist(client->parent, dict));
	if (res != HOUSE_ARREST_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
	}
	return res;
}

house_arrest_error_t house_arrest_send_command(house_arrest_client_t client, const char *command, const char *appid)
{
	if (!client || !client->parent || !command || !appid)
		return HOUSE_ARREST_E_INVALID_ARG;
	if (client->mode != HOUSE_ARREST_CLIENT_MODE_NORMAL)
		return HOUSE_ARREST_E_INVALID_MODE;

	house_arrest_error_t res = HOUSE_ARREST_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string(command));
	plist_dict_set_item(dict, "Identifier", plist_new_string(appid));

	res = house_arrest_send_request(client, dict);

	plist_free(dict);

	return res;
}

house_arrest_error_t house_arrest_get_result(house_arrest_client_t client, plist_t *dict)
{
	if (!client || !client->parent)
		return HOUSE_ARREST_E_INVALID_ARG;
	if (client->mode != HOUSE_ARREST_CLIENT_MODE_NORMAL)
		return HOUSE_ARREST_E_INVALID_MODE;

	house_arrest_error_t res = house_arrest_error(property_list_service_receive_plist(client->parent, dict));
	if (res != HOUSE_ARREST_E_SUCCESS) {
		debug_info("could not get result, error %d", res);
		if (*dict) {
			plist_free(*dict);
			*dict = NULL;
		}
	}
	return res;
}

afc_error_t afc_client_new_from_house_arrest_client(house_arrest_client_t client, afc_client_t *afc_client)
{
	if (!client || !client->parent || (client->mode == HOUSE_ARREST_CLIENT_MODE_AFC)) {
		return AFC_E_INVALID_ARG;
	}
	afc_error_t err = afc_client_new_with_service_client(client->parent->parent, afc_client);
	if (err == AFC_E_SUCCESS) {
		client->mode = HOUSE_ARREST_CLIENT_MODE_AFC;
	}
	return err;
}
