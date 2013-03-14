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
#include "debug.h"

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

/**
 * Connects to the house_arrest service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     housearrest_client_t upon successful return.
 *
 * @return HOUSE_ARREST_E_SUCCESS on success, HOUSE_ARREST_E_INVALID_ARG when
 *     client is NULL, or an HOUSE_ARREST_E_* error code otherwise.
 */
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

/**
 * Disconnects an house_arrest client from the device and frees up the
 * house_arrest client data.
 *
 * @note After using afc_client_new_from_house_arrest_client(), make sure
 *     you call afc_client_free() before calling this function to ensure
 *     a proper cleanup. Do not call this function if you still need to
 *     perform AFC operations since it will close the connection.
 *
 * @param client The house_arrest client to disconnect and free.
 *
 * @return HOUSE_ARREST_E_SUCCESS on success, HOUSE_ARREST_E_INVALID_ARG when
 *     client is NULL, or an HOUSE_ARREST_E_* error code otherwise.
 */
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

/**
 * Sends a generic request to the connected house_arrest service.
 *
 * @param client The house_arrest client to use.
 * @param dict The request to send as a plist of type PLIST_DICT.
 *
 * @note If this function returns HOUSE_ARREST_E_SUCCESS it does not mean
 *     that the request was successful. To check for success or failure you
 *     need to call house_arrest_get_result().
 * @see house_arrest_get_result
 *
 * @return HOUSE_ARREST_E_SUCCESS if the request was successfully sent,
 *     HOUSE_ARREST_E_INVALID_ARG if client or dict is invalid,
 *     HOUSE_ARREST_E_PLIST_ERROR if dict is not a plist of type PLIST_DICT,
 *     HOUSE_ARREST_E_INVALID_MODE if the client is not in the correct mode,
 *     or HOUSE_ARREST_E_CONN_FAILED if a connection error occured.
 */
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

/**
 * Send a command to the connected house_arrest service.
 * Calls house_arrest_send_request() internally.
 *
 * @param client The house_arrest client to use.
 * @param command The command to send. Currently, only VendContainer and
 *     VendDocuments are known.
 * @param appid The application identifier to pass along with the .
 *
 * @note If this function returns HOUSE_ARREST_E_SUCCESS it does not mean
 *     that the command was successful. To check for success or failure you
 *     need to call house_arrest_get_result().
 * @see house_arrest_get_result
 *
 * @return HOUSE_ARREST_E_SUCCESS if the command was successfully sent,
 *     HOUSE_ARREST_E_INVALID_ARG if client, command, or appid is invalid,
 *     HOUSE_ARREST_E_INVALID_MODE if the client is not in the correct mode,
 *     or HOUSE_ARREST_E_CONN_FAILED if a connection error occured.
 */
house_arrest_error_t house_arrest_send_command(house_arrest_client_t client, const char *command, const char *appid)
{
	if (!client || !client->parent || !command || !appid)
                return HOUSE_ARREST_E_INVALID_ARG;
	if (client->mode != HOUSE_ARREST_CLIENT_MODE_NORMAL)
		return HOUSE_ARREST_E_INVALID_MODE;

	house_arrest_error_t res = HOUSE_ARREST_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "Command", plist_new_string(command));
	plist_dict_insert_item(dict, "Identifier", plist_new_string(appid));

	res = house_arrest_send_request(client, dict);

	plist_free(dict);

	return res;
}

/**
 * Retrieves the result of a previously sent house_arrest_request_* request.
 *
 * @param client The house_arrest client to use
 * @param dict Pointer that will be set to a plist containing the result to
 *     the last performed operation. It holds a key 'Status' with the value
 *     'Complete' on success or a key 'Error' with an error description as
 *     value. The caller is responsible for freeing the returned plist.
 *
 * @return HOUSE_ARREST_E_SUCCESS if a result plist was retrieved,
 *     HOUSE_ARREST_E_INVALID_ARG if client is invalid,
 *     HOUSE_ARREST_E_INVALID_MODE if the client is not in the correct mode,
 *     or HOUSE_ARREST_E_CONN_FAILED if a connection error occured.
 */
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

/**
 * Creates an AFC client using the given house_arrest client's connection
 * allowing file access to a specific application directory requested by
 * functions like house_arrest_request_vendor_documents().
 *
 * @param client The house_arrest client to use.
 * @param afc_client Pointer that will be set to a newly allocated afc_client_t
 *     upon successful return.
 *
 * @note After calling this function the house_arrest client will go in an
 *     AFC mode that will only allow calling house_arrest_client_free().
 *     Only call house_arrest_client_free() if all AFC operations have
 *     completed since it will close the connection.
 *
 * @return AFC_E_SUCCESS if the afc client was successfully created,
 *     AFC_E_INVALID_ARG if client is invalid or was already used to create
 *     an afc client, or an AFC_E_* error code returned by
 *     afc_client_new_with_service_client().
 */
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
