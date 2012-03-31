 /* 
 * diagnostics_relay.c
 * com.apple.mobile.diagnostics_relay service implementation.
 * 
 * Copyright (c) 2012 Martin Szulecki, All Rights Reserved.
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
#include "diagnostics_relay.h"
#include "property_list_service.h"
#include "debug.h"

#define RESULT_SUCCESS 0
#define RESULT_FAILURE 1

/**
 * Internally used function for checking the result from a service response
 * plist to a previously sent request.
 *
 * @param dict The plist to evaluate.
 * @param query_match Name of the request to match or NULL if no match is
 *        required.
 *
 * @return RESULT_SUCCESS when the result is 'Success',
 *         RESULT_FAILURE when the result is 'Failure',
 *         or a negative value if an error occured during evaluation.
 */
static int diagnostics_relay_check_result(plist_t dict, const char *query_match)
{
	int ret = -1;

	plist_t query_node = plist_dict_get_item(dict, "Request");
	if (!query_node) {
		return ret;
	}
	if (plist_get_node_type(query_node) != PLIST_STRING) {
		return ret;
	} else {
		char *query_value = NULL;
		plist_get_string_val(query_node, &query_value);
		if (!query_value) {
			return ret;
		}
		if (query_match && (strcmp(query_value, query_match) != 0)) {
			free(query_value);
			return ret;
		}
		free(query_value);
	}

	plist_t result_node = plist_dict_get_item(dict, "Status");
	if (!result_node)
		return ret;

	plist_type result_type = plist_get_node_type(result_node);
	if (result_type == PLIST_STRING) {
		char *result_value = NULL;

		plist_get_string_val(result_node, &result_value);

		if (result_value) {
			if (!strcmp(result_value, "Success")) {
				ret = RESULT_SUCCESS;
			} else if (!strcmp(result_value, "Failure")) {
				ret = RESULT_FAILURE;
			} else {
				debug_info("ERROR: unknown result value '%s'", result_value);
			}
		}
		if (result_value)
			free(result_value);
	}
	return ret;
}

/**
 * Connects to the diagnostics_relay service on the specified device.
 *
 * @param device The device to connect to.
 * @param port Destination port (usually given by lockdownd_start_service).
 * @param client Reference that will point to a newly allocated
 *     diagnostics_relay_client_t upon successful return.
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *     DIAGNOSTICS_RELAY_E_INVALID_ARG when one of the parameters is invalid,
 *     or DIAGNOSTICS_RELAY_E_MUX_ERROR when the connection failed.
 */
diagnostics_relay_error_t diagnostics_relay_client_new(idevice_t device, uint16_t port, diagnostics_relay_client_t *client)
{
	if (!device || port == 0 || !client || *client) {
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;
	}

	property_list_service_client_t plistclient = NULL;
	if (property_list_service_client_new(device, port, &plistclient) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return DIAGNOSTICS_RELAY_E_MUX_ERROR;
	}

	/* create client object */
	diagnostics_relay_client_t client_loc = (diagnostics_relay_client_t) malloc(sizeof(struct diagnostics_relay_client_private));
	client_loc->parent = plistclient;

	/* all done, return success */
	*client = client_loc;
	return DIAGNOSTICS_RELAY_E_SUCCESS;
}

/**
 * Disconnects a diagnostics_relay client from the device and frees up the 
 * diagnostics_relay client data.
 *
 * @param client The diagnostics_relay client to disconnect and free.
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *     DIAGNOSTICS_RELAY_E_INVALID_ARG when one of client or client->parent
 *     is invalid, or DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR when the was an
 *     error freeing the parent property_list_service client.
 */
diagnostics_relay_error_t diagnostics_relay_client_free(diagnostics_relay_client_t client)
{
	if (!client)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	if (property_list_service_client_free(client->parent) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	}
	return DIAGNOSTICS_RELAY_E_SUCCESS;
}

/**
 * Receives a plist from the service.
 *
 * @param client The diagnostics_relay client
 * @param plist The plist to store the received data
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client or plist is NULL
 */
static diagnostics_relay_error_t diagnostics_relay_receive(diagnostics_relay_client_t client, plist_t *plist)
{
	if (!client || !plist || (plist && *plist))
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	property_list_service_error_t err;

	err = property_list_service_receive_plist(client->parent, plist);
	if (err != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	}

	if (!*plist)
		ret = DIAGNOSTICS_RELAY_E_PLIST_ERROR;

	return ret;
}

/**
 * Sends a plist to the service.
 *
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The diagnostics_relay client
 * @param plist The plist to send
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client or plist is NULL
 */
static diagnostics_relay_error_t diagnostics_relay_send(diagnostics_relay_client_t client, plist_t plist)
{
	if (!client || !plist)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	idevice_error_t err;

	err = property_list_service_send_xml_plist(client->parent, plist);
	if (err != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	}
	return ret;
}

/**
 * Sends the Goodbye request signaling the end of communication.
 *
 * @param client The diagnostics_relay client
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client is NULL,
 *  DIAGNOSTICS_RELAY_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
diagnostics_relay_error_t diagnostics_relay_goodbye(diagnostics_relay_client_t client)
{
	if (!client)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "Request", plist_new_string("Goodbye"));

	ret = diagnostics_relay_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = diagnostics_relay_receive(client, &dict);
	if (!dict) {
		debug_info("did not get goodbye response back");
		return DIAGNOSTICS_RELAY_E_PLIST_ERROR;
	}

	if (diagnostics_relay_check_result(dict, "Goodbye") == RESULT_SUCCESS) {
		debug_info("success");
		ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;
	return ret;
}

diagnostics_relay_error_t diagnostics_relay_request_diagnostics(diagnostics_relay_client_t client, plist_t* diagnostics)
{
	if (!client || diagnostics == NULL)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
/*
	Provides a diagnostics interface. Some stuff is only available on iOS 5+

	Protocol:

		Request:
			<key>Request</key><string>IORegistry</string>
			[<key>CurrentPlane</key><string>IODeviceTree</string>]
		Response:
			[Diagnostics]
				IORegistry
					...
			Status
				"Success" | "UnknownRequest"
			[ErrorCode]
				%d

	Unknown Strings:

	? IO80211Interface
	? InternalBuild
	? DisplayFail
	? DisplayPass
	? WaitForDisconnect

	Known/Tested Requests:

	// wifi: Show wifi status
	plist_dict_insert_item(dict,"Request", plist_new_string("WiFi"));

	// gas_gauge: Show battery load cycles and more
	plist_dict_insert_item(dict,"Request", plist_new_string("GasGauge"));
	plist_dict_insert_item(dict,"Request", plist_new_string("NAND"));
	plist_dict_insert_item(dict,"Request", plist_new_string("Sleep"));
	plist_dict_insert_item(dict,"Request", plist_new_string("Shutdown"));
	plist_dict_insert_item(dict,"Request", plist_new_string("Restart"));

	// obliberate: Wipe data on device
	// @note: Currently yields: "iPhone mobile_diagnostics_relay[253] <Error>: do_obliterate: obliteration denied: not running internal build."
	plist_dict_insert_item(dict,"Request", plist_new_string("Obliterate"));
	? DataPartitionOnly
	? ObliterationType
	? ObliterateDataPartition
	? ObliterationTypeWipeAndBrick
	? DisplayProgressBar
	? SkipDataObliteration
	? ObliterationMessage

	// mobile_gestalt: read out managed keys
	plist_t keys = plist_new_array();
	plist_array_append_item(keys, plist_new_string("UserAssignedDeviceName"));
	plist_array_append_item(keys, plist_new_string("BasebandSecurityInfo"));
	plist_array_append_item(keys, plist_new_string("BasebandSerialNumber"));
	plist_array_append_item(keys, plist_new_string("MyPhoneNumber"));
	plist_array_append_item(keys, plist_new_string("SNUM"));
	plist_dict_insert_item(dict,"MobileGestaltKeys", keys);
	plist_dict_insert_item(dict,"Request", plist_new_string("MobileGestalt"));

	// io registry: dump by plane or name and class
	plist_dict_insert_item(dict,"CurrentPlane", plist_new_string("IODeviceTree"));
	or
	plist_dict_insert_item(dict,"EntryName", plist_new_string("baseband"));
	plist_dict_insert_item(dict,"EntryClass", plist_new_string("IOPlatformDevice"));
	plist_dict_insert_item(dict,"Request", plist_new_string("IORegistry"));
*/
	plist_dict_insert_item(dict,"Request", plist_new_string("IORegistry"));
	plist_dict_insert_item(dict,"CurrentPlane", plist_new_string(""));
	ret = diagnostics_relay_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = diagnostics_relay_receive(client, &dict);
	if (!dict) {
		debug_info("did not get response back");
		return DIAGNOSTICS_RELAY_E_PLIST_ERROR;
	}

	if (diagnostics_relay_check_result(dict, "Diagnostics") == RESULT_SUCCESS) {
		debug_info("success");
		ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	}
	if (ret != DIAGNOSTICS_RELAY_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_t value_node = plist_dict_get_item(dict, "Diagnostics");
	if (value_node) {
		debug_info("has a value");
		*diagnostics = plist_copy(value_node);
	}

	plist_free(dict);
	return ret;
}
