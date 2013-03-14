 /* 
 * file_relay.c
 * com.apple.mobile.file_relay service implementation.
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
#include "file_relay.h"
#include "property_list_service.h"
#include "debug.h"

/**
 * Connects to the file_relay service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Reference that will point to a newly allocated
 *     file_relay_client_t upon successful return.
 *
 * @return FILE_RELAY_E_SUCCESS on success,
 *     FILE_RELAY_E_INVALID_ARG when one of the parameters is invalid,
 *     or FILE_RELAY_E_MUX_ERROR when the connection failed.
 */
file_relay_error_t file_relay_client_new(idevice_t device, lockdownd_service_descriptor_t service, file_relay_client_t *client)
{
	if (!device || !service || service->port == 0 || !client || *client) {
		return FILE_RELAY_E_INVALID_ARG;
	}

	property_list_service_client_t plistclient = NULL;
	if (property_list_service_client_new(device, service, &plistclient) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return FILE_RELAY_E_MUX_ERROR;
	}

	/* create client object */
	file_relay_client_t client_loc = (file_relay_client_t) malloc(sizeof(struct file_relay_client_private));
	client_loc->parent = plistclient;

	/* all done, return success */
	*client = client_loc;
	return FILE_RELAY_E_SUCCESS;
}

/**
 * Disconnects a file_relay client from the device and frees up the file_relay
 * client data.
 *
 * @param client The file_relay client to disconnect and free.
 *
 * @return FILE_RELAY_E_SUCCESS on success,
 *     FILE_RELAY_E_INVALID_ARG when one of client or client->parent
 *     is invalid, or FILE_RELAY_E_UNKNOWN_ERROR when the was an error
 *     freeing the parent property_list_service client.
 */
file_relay_error_t file_relay_client_free(file_relay_client_t client)
{
	if (!client)
		return FILE_RELAY_E_INVALID_ARG;

	if (property_list_service_client_free(client->parent) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return FILE_RELAY_E_UNKNOWN_ERROR;
	}
	return FILE_RELAY_E_SUCCESS;
}

/**
 * Request data for the given sources.
 *
 * @param client The connected file_relay client.
 * @param sources A NULL-terminated list of sources to retrieve.
 *     Valid sources are:
 *     - AppleSupport
 *     - Network
 *     - VPN
 *     - WiFi
 *     - UserDatabases
 *     - CrashReporter
 *     - tmp
 *     - SystemConfiguration
 * @param connection The connection that has to be used for receiving the 
 *     data using idevice_connection_receive(). The connection will be closed
 *     automatically by the device, but use file_relay_client_free() to clean
 *     up properly.
 *
 * @note WARNING: Don't call this function without reading the data afterwards.
 *     A directory mobile_file_relay.XXXX used for creating the archive will
 *     remain in the /tmp directory otherwise.
 *
 * @return FILE_RELAY_E_SUCCESS on succes, FILE_RELAY_E_INVALID_ARG when one or
 *     more parameters are invalid, FILE_RELAY_E_MUX_ERROR if a communication
 *     error occurs, FILE_RELAY_E_PLIST_ERROR when the received result is NULL
 *     or is not a valid plist, FILE_RELAY_E_INVALID_SOURCE if one or more
 *     sources are invalid, FILE_RELAY_E_STAGING_EMPTY if no data is available
 *     for the given sources, or FILE_RELAY_E_UNKNOWN_ERROR otherwise.
 */
file_relay_error_t file_relay_request_sources(file_relay_client_t client, const char **sources, idevice_connection_t *connection)
{
	if (!client || !client->parent || !sources || !sources[0]) {
		return FILE_RELAY_E_INVALID_ARG;
	}
	*connection = NULL;
	file_relay_error_t err = FILE_RELAY_E_UNKNOWN_ERROR;
	/* set up request plist */
	plist_t array = plist_new_array();
	int i = 0;
	while (sources[i]) {
		plist_array_append_item(array, plist_new_string(sources[i]));
		i++;
	}	
	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "Sources", array);

	if (property_list_service_send_xml_plist(client->parent, dict) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		debug_info("ERROR: Could not send request to device!");
		err = FILE_RELAY_E_MUX_ERROR;
		goto leave;
	}
	plist_free(dict);

	dict = NULL;
	if (property_list_service_receive_plist_with_timeout(client->parent, &dict, 60000) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		debug_info("ERROR: Could not receive answer from device!");
		err = FILE_RELAY_E_MUX_ERROR;
		goto leave;
	}

	if (!dict) {
		debug_info("ERROR: Did not receive any plist!");
		err = FILE_RELAY_E_PLIST_ERROR;
		goto leave;
	}

	plist_t error = plist_dict_get_item(dict, "Error");
	if (error) {
		char *errmsg = NULL;
		plist_get_string_val(error, &errmsg);
		if (errmsg) {
			if (!strcmp(errmsg, "InvalidSource")) {
				debug_info("ERROR: One or more given sources are invalid!");
				err = FILE_RELAY_E_INVALID_SOURCE;
			} else if (!strcmp(errmsg, "StagingEmpty")) {
				debug_info("ERROR: StagingEmpty - No data available!");
				err = FILE_RELAY_E_STAGING_EMPTY;
			} else {
				debug_info("ERROR: Unknown error '%s'", errmsg);
			}
			free(errmsg);
		} else {
			debug_info("ERROR: Could not get error message!");
		}
		goto leave;
	}

	plist_t status = plist_dict_get_item(dict, "Status");
	if (!status) {
		debug_info("ERROR: Unexpected plist received!");
		debug_plist(dict);
		err = FILE_RELAY_E_PLIST_ERROR;
		goto leave;
	}

	char *ack = NULL;
	plist_get_string_val(status, &ack);
	if (!ack) {
		debug_info("ERROR: Could not get 'Acknowledged' string!");
		goto leave;
	}

	if (strcmp(ack, "Acknowledged")) {
		debug_info("ERROR: Did not receive 'Acknowledged' but '%s'", ack);
		goto leave;
	}
	free(ack);
	err = FILE_RELAY_E_SUCCESS;

	*connection = client->parent->parent->connection;

leave:
	if (dict) {
		plist_free(dict);
	}
	return err;
}
