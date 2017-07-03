/*
 * mobileactivation.c
 * com.apple.mobileactivationd service implementation.
 *
 * Copyright (c) 2016-2017 Nikias Bassen, All Rights Reserved.
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
#include "mobileactivation.h"
#include "property_list_service.h"
#include "common/debug.h"

/**
 * Convert a property_list_service_error_t value to a mobileactivation_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An property_list_service_error_t error code
 *
 * @return A matching mobileactivation_error_t error code,
 *     MOBILEACTIVATION_E_UNKNOWN_ERROR otherwise.
 */
static mobileactivation_error_t mobileactivation_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return MOBILEACTIVATION_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return MOBILEACTIVATION_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return MOBILEACTIVATION_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return MOBILEACTIVATION_E_MUX_ERROR;
		default:
			break;
	}
	return MOBILEACTIVATION_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API mobileactivation_error_t mobileactivation_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobileactivation_client_t *client)
{
	if (!device || !service || service->port == 0 || !client || *client) {
		return MOBILEACTIVATION_E_INVALID_ARG;
	}

	property_list_service_client_t plistclient = NULL;
	if (property_list_service_client_new(device, service, &plistclient) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return MOBILEACTIVATION_E_MUX_ERROR;
	}

	/* create client object */
	mobileactivation_client_t client_loc = (mobileactivation_client_t) malloc(sizeof(struct mobileactivation_client_private));
	client_loc->parent = plistclient;

	/* all done, return success */
	*client = client_loc;
	return MOBILEACTIVATION_E_SUCCESS;
}

LIBIMOBILEDEVICE_API mobileactivation_error_t mobileactivation_client_start_service(idevice_t device, mobileactivation_client_t * client, const char* label)
{
	mobileactivation_error_t err = MOBILEACTIVATION_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, MOBILEACTIVATION_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(mobileactivation_client_new), &err);
	return err;
}

LIBIMOBILEDEVICE_API mobileactivation_error_t mobileactivation_client_free(mobileactivation_client_t client)
{
	if (!client)
		return MOBILEACTIVATION_E_INVALID_ARG;

	if (property_list_service_client_free(client->parent) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return MOBILEACTIVATION_E_UNKNOWN_ERROR;
	}
	free(client);
	return MOBILEACTIVATION_E_SUCCESS;
}

static plist_t plist_data_from_plist(plist_t plist)
{
	plist_t result = NULL;
	char *xml = NULL;
	uint32_t xml_len = 0;
	plist_to_xml(plist, &xml, &xml_len);
	result = plist_new_data(xml, xml_len);
	free(xml);
	return result;
}

static mobileactivation_error_t mobileactivation_check_result(plist_t dict, const char *command)
{
	mobileactivation_error_t ret = MOBILEACTIVATION_E_UNKNOWN_ERROR;

	if (!dict || plist_get_node_type(dict) != PLIST_DICT) {
		return MOBILEACTIVATION_E_PLIST_ERROR;
	}

	plist_t err_node = plist_dict_get_item(dict, "Error");
	if (!err_node) {
		return MOBILEACTIVATION_E_SUCCESS;
	} else {
		char *errmsg = NULL;
		plist_get_string_val(err_node, &errmsg);
		debug_info("ERROR: %s: %s", command, errmsg);
		ret = MOBILEACTIVATION_E_REQUEST_FAILED;
		free(errmsg);
	}
	return ret;
}

static mobileactivation_error_t mobileactivation_send_command(mobileactivation_client_t client, const char* command, plist_t value, plist_t *result)
{
	if (!client || !command || !result)
		return MOBILEACTIVATION_E_INVALID_ARG;

	mobileactivation_error_t ret = MOBILEACTIVATION_E_UNKNOWN_ERROR;
	*result = NULL;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string(command));
	if (value) {
		plist_dict_set_item(dict, "Value", plist_copy(value));
	}

	ret = mobileactivation_error(property_list_service_send_binary_plist(client->parent, dict));
	plist_free(dict);
	dict = NULL;

	ret = mobileactivation_error(property_list_service_receive_plist(client->parent, &dict));
	if (!dict) {
		debug_info("ERROR: Did not get reply for %s command", command);
		return MOBILEACTIVATION_E_PLIST_ERROR;
	}

	*result = dict;
	return mobileactivation_check_result(dict, command);
}

LIBIMOBILEDEVICE_API mobileactivation_error_t mobileactivation_get_activation_state(mobileactivation_client_t client, plist_t *state)
{
	if (!client || !state)
		return MOBILEACTIVATION_E_INVALID_ARG;

	plist_t result = NULL;
	mobileactivation_error_t ret = mobileactivation_send_command(client, "GetActivationStateRequest", NULL, &result);
	if (ret == MOBILEACTIVATION_E_SUCCESS) {
		plist_t node = plist_dict_get_item(result, "Value");
		if (!node) {
			debug_info("ERROR: GetActivationStateRequest command returned success but has no value in reply");
			ret = MOBILEACTIVATION_E_UNKNOWN_ERROR;
		} else {
			*state = plist_copy(node);
		}
	}
	plist_free(result);
	result = NULL;

	return ret;
}

LIBIMOBILEDEVICE_API mobileactivation_error_t mobileactivation_create_activation_session_info(mobileactivation_client_t client, plist_t *blob)
{
	if (!client || !blob)
		return MOBILEACTIVATION_E_INVALID_ARG;

	plist_t result = NULL;
	mobileactivation_error_t ret = mobileactivation_send_command(client, "CreateTunnel1SessionInfoRequest", NULL, &result);
	if (ret == MOBILEACTIVATION_E_SUCCESS) {
		plist_t node = plist_dict_get_item(result, "Value");
		if (!node) {
			debug_info("ERROR: CreateTunnel1SessionInfoRequest command returned success but has no value in reply");
			ret = MOBILEACTIVATION_E_UNKNOWN_ERROR;
		} else {
			*blob = plist_copy(node);
		}
	}

	return ret;
}

LIBIMOBILEDEVICE_API mobileactivation_error_t mobileactivation_create_activation_info(mobileactivation_client_t client, plist_t *info)
{
	if (!client || !info)
		return MOBILEACTIVATION_E_INVALID_ARG;

	plist_t result = NULL;
	mobileactivation_error_t ret = mobileactivation_send_command(client, "CreateActivationInfoRequest", NULL, &result);
	if (ret == MOBILEACTIVATION_E_SUCCESS) {
		plist_t node = plist_dict_get_item(result, "Value");
		if (!node) {
			debug_info("ERROR: CreateActivationInfoRequest command returned success but has no value in reply");
			ret = MOBILEACTIVATION_E_UNKNOWN_ERROR;
		} else {
			*info = plist_copy(node);
		}
	}
	plist_free(result);
	result = NULL;

	return ret;
}

LIBIMOBILEDEVICE_API mobileactivation_error_t mobileactivation_create_activation_info_with_session(mobileactivation_client_t client, plist_t handshake_response, plist_t *info)
{
	if (!client || !info)
		return MOBILEACTIVATION_E_INVALID_ARG;

	plist_t result = NULL;
	plist_t data = plist_data_from_plist(handshake_response);
	mobileactivation_error_t ret = mobileactivation_send_command(client, "CreateTunnel1ActivationInfoRequest", data, &result);
	plist_free(data);
	if (ret == MOBILEACTIVATION_E_SUCCESS) {
		plist_t node = plist_dict_get_item(result, "Value");
		if (!node) {
			debug_info("ERROR: CreateTunnel1ActivationInfoRequest command returned success but has no value in reply");
			ret = MOBILEACTIVATION_E_UNKNOWN_ERROR;
		} else {
			*info = plist_copy(node);
		}
	}
	plist_free(result);
	result = NULL;

	return ret;	
}

LIBIMOBILEDEVICE_API mobileactivation_error_t mobileactivation_activate(mobileactivation_client_t client, plist_t activation_record)
{
	if (!client || !activation_record)
		return MOBILEACTIVATION_E_INVALID_ARG;

	plist_t result = NULL;
	mobileactivation_error_t ret = mobileactivation_send_command(client, "HandleActivationInfoRequest", activation_record, &result);
	plist_free(result);
	result = NULL;

	return ret;
}

LIBIMOBILEDEVICE_API mobileactivation_error_t mobileactivation_activate_with_session(mobileactivation_client_t client, plist_t activation_record)
{
	if (!client || !activation_record)
		return MOBILEACTIVATION_E_INVALID_ARG;

	plist_t result = NULL;
	plist_t data = plist_data_from_plist(activation_record);
	mobileactivation_error_t ret = mobileactivation_send_command(client, "HandleActivationInfoWithSessionRequest", data, &result);
	plist_free(data);
	plist_free(result);
	result = NULL;

	return ret;
}


LIBIMOBILEDEVICE_API mobileactivation_error_t mobileactivation_deactivate(mobileactivation_client_t client)
{
	if (!client)
		return MOBILEACTIVATION_E_INVALID_ARG;

	plist_t result = NULL;
	mobileactivation_error_t ret = mobileactivation_send_command(client, "DeactivateRequest", NULL, &result);
	plist_free(result);
	result = NULL;

	return ret;
}
