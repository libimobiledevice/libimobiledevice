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
#include "common/debug.h"

#define RESULT_SUCCESS 0
#define RESULT_FAILURE 1
#define RESULT_UNKNOWN_REQUEST 2

/**
 * Internally used function for checking the result from a service response
 * plist to a previously sent request.
 *
 * @param dict The plist to evaluate.
 *
 * @return RESULT_SUCCESS when the result is 'Success',
 *         RESULT_FAILURE when the result is 'Failure',
 *         or a negative value if an error occured during evaluation.
 */
static int diagnostics_relay_check_result(plist_t dict)
{
	int ret = -1;

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
			} else if (!strcmp(result_value, "UnknownRequest")) {
				ret = RESULT_UNKNOWN_REQUEST;
			} else {
				debug_info("ERROR: unknown result value '%s'", result_value);
			}
		}
		if (result_value)
			free(result_value);
	}
	return ret;
}

diagnostics_relay_error_t diagnostics_relay_client_new(idevice_t device, lockdownd_service_descriptor_t service, diagnostics_relay_client_t *client)
{
	if (!device || !service || service->port == 0 || !client || *client) {
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;
	}

	property_list_service_client_t plistclient = NULL;
	if (property_list_service_client_new(device, service, &plistclient) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return DIAGNOSTICS_RELAY_E_MUX_ERROR;
	}

	/* create client object */
	diagnostics_relay_client_t client_loc = (diagnostics_relay_client_t) malloc(sizeof(struct diagnostics_relay_client_private));
	client_loc->parent = plistclient;

	/* all done, return success */
	*client = client_loc;
	return DIAGNOSTICS_RELAY_E_SUCCESS;
}

diagnostics_relay_error_t diagnostics_relay_client_start_service(idevice_t device, diagnostics_relay_client_t * client, const char* label)
{
	diagnostics_relay_error_t err = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, DIAGNOSTICS_RELAY_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(diagnostics_relay_client_new), &err);
	return err;
}

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

diagnostics_relay_error_t diagnostics_relay_goodbye(diagnostics_relay_client_t client)
{
	if (!client)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Request", plist_new_string("Goodbye"));

	ret = diagnostics_relay_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = diagnostics_relay_receive(client, &dict);
	if (!dict) {
		debug_info("did not get goodbye response back");
		return DIAGNOSTICS_RELAY_E_PLIST_ERROR;
	}

	int check = diagnostics_relay_check_result(dict);
	if (check == RESULT_SUCCESS) {
		ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	} else if (check == RESULT_UNKNOWN_REQUEST) {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_REQUEST;
	} else {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	}

	plist_free(dict);
	dict = NULL;
	return ret;
}

diagnostics_relay_error_t diagnostics_relay_sleep(diagnostics_relay_client_t client)
{
	if (!client)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();

	plist_dict_set_item(dict,"Request", plist_new_string("Sleep"));
	ret = diagnostics_relay_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = diagnostics_relay_receive(client, &dict);
	if (!dict) {
		return DIAGNOSTICS_RELAY_E_PLIST_ERROR;
	}

	int check = diagnostics_relay_check_result(dict);
	if (check == RESULT_SUCCESS) {
		ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	} else if (check == RESULT_UNKNOWN_REQUEST) {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_REQUEST;
	} else {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	}

	plist_free(dict);
	return ret;
}

static diagnostics_relay_error_t internal_diagnostics_relay_action(diagnostics_relay_client_t client, const char* name, int flags)
{
	if (!client)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict,"Request", plist_new_string(name));

	if (flags & DIAGNOSTICS_RELAY_ACTION_FLAG_WAIT_FOR_DISCONNECT) {
		plist_dict_set_item(dict, "WaitForDisconnect", plist_new_bool(1));
	}

	if (flags & DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_PASS) {
		plist_dict_set_item(dict, "DisplayPass", plist_new_bool(1));
	}

	if (flags & DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_FAIL) {
		plist_dict_set_item(dict, "DisplayFail", plist_new_bool(1));
	}

	ret = diagnostics_relay_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = diagnostics_relay_receive(client, &dict);
	if (!dict) {
		return DIAGNOSTICS_RELAY_E_PLIST_ERROR;
	}

	int check = diagnostics_relay_check_result(dict);
	if (check == RESULT_SUCCESS) {
		ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	} else if (check == RESULT_UNKNOWN_REQUEST) {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_REQUEST;
	} else {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	}

	plist_free(dict);
	return ret;
}

diagnostics_relay_error_t diagnostics_relay_restart(diagnostics_relay_client_t client, int flags)
{
	return internal_diagnostics_relay_action(client, "Restart", flags);
}

diagnostics_relay_error_t diagnostics_relay_shutdown(diagnostics_relay_client_t client, int flags)
{
	return internal_diagnostics_relay_action(client, "Shutdown", flags);
}

diagnostics_relay_error_t diagnostics_relay_request_diagnostics(diagnostics_relay_client_t client, const char* type, plist_t* diagnostics)
{
	if (!client || diagnostics == NULL)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict,"Request", plist_new_string(type));
	ret = diagnostics_relay_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = diagnostics_relay_receive(client, &dict);
	if (!dict) {
		return DIAGNOSTICS_RELAY_E_PLIST_ERROR;
	}

	int check = diagnostics_relay_check_result(dict);
	if (check == RESULT_SUCCESS) {
		ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	} else if (check == RESULT_UNKNOWN_REQUEST) {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_REQUEST;
	} else {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	}

	if (ret != DIAGNOSTICS_RELAY_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_t value_node = plist_dict_get_item(dict, "Diagnostics");
	if (value_node) {
		*diagnostics = plist_copy(value_node);
	}

	plist_free(dict);
	return ret;
}

diagnostics_relay_error_t diagnostics_relay_query_mobilegestalt(diagnostics_relay_client_t client, plist_t keys, plist_t* result)
{
	if (!client || plist_get_node_type(keys) != PLIST_ARRAY || result == NULL)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict,"MobileGestaltKeys", plist_copy(keys));
	plist_dict_set_item(dict,"Request", plist_new_string("MobileGestalt"));
	ret = diagnostics_relay_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = diagnostics_relay_receive(client, &dict);
	if (!dict) {
		return DIAGNOSTICS_RELAY_E_PLIST_ERROR;
	}

	int check = diagnostics_relay_check_result(dict);
	if (check == RESULT_SUCCESS) {
		ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	} else if (check == RESULT_UNKNOWN_REQUEST) {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_REQUEST;
	} else {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	}

	if (ret != DIAGNOSTICS_RELAY_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_t value_node = plist_dict_get_item(dict, "Diagnostics");
	if (value_node) {
		*result = plist_copy(value_node);
	}

	plist_free(dict);
	return ret;
}

diagnostics_relay_error_t diagnostics_relay_query_ioregistry_entry(diagnostics_relay_client_t client, const char* name, const char* class, plist_t* result)
{
	if (!client || (name == NULL && class == NULL) || result == NULL)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	if (name)
		plist_dict_set_item(dict,"EntryName", plist_new_string(name));
	if (class)
		plist_dict_set_item(dict,"EntryClass", plist_new_string(class));
	plist_dict_set_item(dict,"Request", plist_new_string("IORegistry"));
	ret = diagnostics_relay_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = diagnostics_relay_receive(client, &dict);
	if (!dict) {
		return DIAGNOSTICS_RELAY_E_PLIST_ERROR;
	}

	int check = diagnostics_relay_check_result(dict);
	if (check == RESULT_SUCCESS) {
		ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	} else if (check == RESULT_UNKNOWN_REQUEST) {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_REQUEST;
	} else {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	}

	if (ret != DIAGNOSTICS_RELAY_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_t value_node = plist_dict_get_item(dict, "Diagnostics");
	if (value_node) {
		*result = plist_copy(value_node);
	}

	plist_free(dict);
	return ret;
}

diagnostics_relay_error_t diagnostics_relay_query_ioregistry_plane(diagnostics_relay_client_t client, const char* plane, plist_t* result)
{
	if (!client || plane == NULL || result == NULL)
		return DIAGNOSTICS_RELAY_E_INVALID_ARG;

	diagnostics_relay_error_t ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict,"CurrentPlane", plist_new_string(plane));
	plist_dict_set_item(dict,"Request", plist_new_string("IORegistry"));
	ret = diagnostics_relay_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = diagnostics_relay_receive(client, &dict);
	if (!dict) {
		return DIAGNOSTICS_RELAY_E_PLIST_ERROR;
	}

	int check = diagnostics_relay_check_result(dict);
	if (check == RESULT_SUCCESS) {
		ret = DIAGNOSTICS_RELAY_E_SUCCESS;
	} else if (check == RESULT_UNKNOWN_REQUEST) {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_REQUEST;
	} else {
		ret = DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR;
	}

	if (ret != DIAGNOSTICS_RELAY_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_t value_node = plist_dict_get_item(dict, "Diagnostics");
	if (value_node) {
		*result = plist_copy(value_node);
	}

	plist_free(dict);
	return ret;
}
