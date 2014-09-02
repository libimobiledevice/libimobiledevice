/*
 * mobilebackup2.c 
 * Contains functions for the built-in MobileBackup2 client (iOS4+ only)
 * 
 * Copyright (c) 2010 Nikias Bassen All Rights Reserved.
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

#include <plist/plist.h>
#include <string.h>
#include <stdlib.h>

#include "mobilebackup2.h"
#include "device_link_service.h"
#include "common/debug.h"

#define MBACKUP2_VERSION_INT1 300
#define MBACKUP2_VERSION_INT2 0

#define IS_FLAG_SET(x, y) ((x & y) == y)

/**
 * Convert an device_link_service_error_t value to an mobilebackup2_error_t value.
 * Used internally to get correct error codes from the underlying
 * device_link_service.
 *
 * @param err An device_link_service_error_t error code
 *
 * @return A matching mobilebackup2_error_t error code,
 *     MOBILEBACKUP2_E_UNKNOWN_ERROR otherwise.
 */
static mobilebackup2_error_t mobilebackup2_error(device_link_service_error_t err)
{
	switch (err) {
		case DEVICE_LINK_SERVICE_E_SUCCESS:
			return MOBILEBACKUP2_E_SUCCESS;
		case DEVICE_LINK_SERVICE_E_INVALID_ARG:
			return MOBILEBACKUP2_E_INVALID_ARG;
		case DEVICE_LINK_SERVICE_E_PLIST_ERROR:
			return MOBILEBACKUP2_E_PLIST_ERROR;
		case DEVICE_LINK_SERVICE_E_MUX_ERROR:
			return MOBILEBACKUP2_E_MUX_ERROR;
		case DEVICE_LINK_SERVICE_E_BAD_VERSION:
			return MOBILEBACKUP2_E_BAD_VERSION;
		default:
			break;
	}
	return MOBILEBACKUP2_E_UNKNOWN_ERROR;
}

mobilebackup2_error_t mobilebackup2_client_new(idevice_t device, lockdownd_service_descriptor_t service,
						mobilebackup2_client_t * client)
{
	if (!device || !service || service->port == 0 || !client || *client)
		return MOBILEBACKUP2_E_INVALID_ARG;

	device_link_service_client_t dlclient = NULL;
	mobilebackup2_error_t ret = mobilebackup2_error(device_link_service_client_new(device, service, &dlclient));
	if (ret != MOBILEBACKUP2_E_SUCCESS) {
		return ret;
	}

	mobilebackup2_client_t client_loc = (mobilebackup2_client_t) malloc(sizeof(struct mobilebackup2_client_private));
	client_loc->parent = dlclient;

	/* perform handshake */
	ret = mobilebackup2_error(device_link_service_version_exchange(dlclient, MBACKUP2_VERSION_INT1, MBACKUP2_VERSION_INT2));
	if (ret != MOBILEBACKUP2_E_SUCCESS) {
		debug_info("version exchange failed, error %d", ret);
		mobilebackup2_client_free(client_loc);
		return ret;
	}

	*client = client_loc;

	return ret;
}

mobilebackup2_error_t mobilebackup2_client_start_service(idevice_t device, mobilebackup2_client_t * client, const char* label)
{
	mobilebackup2_error_t err = MOBILEBACKUP2_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, MOBILEBACKUP2_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(mobilebackup2_client_new), &err);
	return err;
}

mobilebackup2_error_t mobilebackup2_client_free(mobilebackup2_client_t client)
{
	if (!client)
		return MOBILEBACKUP2_E_INVALID_ARG;
	mobilebackup2_error_t err = MOBILEBACKUP2_E_SUCCESS;
	if (client->parent) {
		device_link_service_disconnect(client->parent, NULL);
		err = mobilebackup2_error(device_link_service_client_free(client->parent));
	}
	free(client);
	return err;
}

mobilebackup2_error_t mobilebackup2_send_message(mobilebackup2_client_t client, const char *message, plist_t options)
{
	if (!client || !client->parent || (!message && !options))
		return MOBILEBACKUP2_E_INVALID_ARG;

	if (options && (plist_get_node_type(options) != PLIST_DICT)) {
		return MOBILEBACKUP2_E_INVALID_ARG;
	}

	mobilebackup2_error_t err;

	if (message) {
		plist_t dict = NULL;
		if (options) {
			dict = plist_copy(options);
		} else {
			dict = plist_new_dict();
		}
		plist_dict_set_item(dict, "MessageName", plist_new_string(message));

		/* send it as DLMessageProcessMessage */
		err = mobilebackup2_error(device_link_service_send_process_message(client->parent, dict));
		plist_free(dict);
	} else {
		err = mobilebackup2_error(device_link_service_send_process_message(client->parent, options));
	}
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		debug_info("ERROR: Could not send message '%s' (%d)!", message, err);
	}
	return err;
}

/**
 * Receives a plist from the device and checks if the value for the
 * MessageName key matches the value passed in the message parameter.
 *
 * @param client The connected MobileBackup client to use.
 * @param message The expected message to check.
 * @param result Pointer to a plist_t that will be set to the received plist
 *    for further processing. The caller has to free it using plist_free().
 *    Note that it will be set to NULL if the operation itself fails due to
 *    a communication or plist error.
 *    If this parameter is NULL, it will be ignored.
 *
 * @return MOBILEBACKUP2_E_SUCCESS on success, MOBILEBACKUP2_E_INVALID_ARG if
 *    client or message is invalid, MOBILEBACKUP2_E_REPLY_NOT_OK if the
 *    expected message could not be received, MOBILEBACKUP2_E_PLIST_ERROR if
 *    the received message is not a valid backup message plist (i.e. the
 *    MessageName key is not present), or MOBILEBACKUP2_E_MUX_ERROR
 *    if a communication error occurs.
 */
static mobilebackup2_error_t internal_mobilebackup2_receive_message(mobilebackup2_client_t client, const char *message, plist_t *result)
{
	if (!client || !client->parent || !message)
		return MOBILEBACKUP2_E_INVALID_ARG;

	if (result)
		*result = NULL;
	mobilebackup2_error_t err;

	plist_t dict = NULL;

	/* receive DLMessageProcessMessage */
	err = mobilebackup2_error(device_link_service_receive_process_message(client->parent, &dict));
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		goto leave;
	}

	plist_t node = plist_dict_get_item(dict, "MessageName");
	if (!node) {
		debug_info("ERROR: MessageName key not found in plist!");
		err = MOBILEBACKUP2_E_PLIST_ERROR;
		goto leave;
	}

	char *str = NULL;
	plist_get_string_val(node, &str);
	if (str && (strcmp(str, message) == 0)) {
		err = MOBILEBACKUP2_E_SUCCESS;
	} else {
		debug_info("ERROR: MessageName value does not match '%s'!", message);
		err = MOBILEBACKUP2_E_REPLY_NOT_OK;
	}
	if (str)
		free(str);

	if (result) {
		*result = dict;
		dict = NULL;
	}
leave:
	if (dict) {
		plist_free(dict);
	}

	return err;
}

mobilebackup2_error_t mobilebackup2_receive_message(mobilebackup2_client_t client, plist_t *msg_plist, char **dlmessage)
{
	return mobilebackup2_error(device_link_service_receive_message(client->parent, msg_plist, dlmessage));
}

mobilebackup2_error_t mobilebackup2_send_raw(mobilebackup2_client_t client, const char *data, uint32_t length, uint32_t *bytes)
{
	if (!client || !client->parent || !data || (length == 0) || !bytes)
		return MOBILEBACKUP2_E_INVALID_ARG;

	*bytes = 0;

	service_client_t raw = client->parent->parent->parent;

	int bytes_loc = 0;
	uint32_t sent = 0;
	do {
		bytes_loc = 0;
		service_send(raw, data+sent, length-sent, (uint32_t*)&bytes_loc);
		if (bytes_loc <= 0)
			break;
		sent += bytes_loc;
	} while (sent < length);
	if (sent > 0) {
		*bytes = sent;
		return MOBILEBACKUP2_E_SUCCESS;
	} else {
		return MOBILEBACKUP2_E_MUX_ERROR;
	}
}

mobilebackup2_error_t mobilebackup2_receive_raw(mobilebackup2_client_t client, char *data, uint32_t length, uint32_t *bytes)
{
	if (!client || !client->parent || !data || (length == 0) || !bytes)
		return MOBILEBACKUP2_E_INVALID_ARG;

	service_client_t raw = client->parent->parent->parent;

	*bytes = 0;

	int bytes_loc = 0;
	uint32_t received = 0;
	do {
		bytes_loc = 0;
		service_receive(raw, data+received, length-received, (uint32_t*)&bytes_loc);
		if (bytes_loc <= 0) break;
		received += bytes_loc;
	} while (received < length);
	if (received > 0) {
		*bytes = received;
		return MOBILEBACKUP2_E_SUCCESS;
	} else if (received == 0) {
		return MOBILEBACKUP2_E_SUCCESS;
	} else {
		return MOBILEBACKUP2_E_MUX_ERROR;
	}
}

mobilebackup2_error_t mobilebackup2_version_exchange(mobilebackup2_client_t client, double local_versions[], char count, double *remote_version)
{
	int i;

	if (!client || !client->parent)
		return MOBILEBACKUP2_E_INVALID_ARG;

	plist_t dict = plist_new_dict();
	plist_t array = plist_new_array();
	for (i = 0; i < count; i++) {
		plist_array_append_item(array, plist_new_real(local_versions[i]));
	}
	plist_dict_set_item(dict, "SupportedProtocolVersions", array);

	mobilebackup2_error_t err = mobilebackup2_send_message(client, "Hello", dict);
	plist_free(dict);

	if (err != MOBILEBACKUP2_E_SUCCESS)
		goto leave;

	dict = NULL;
	err = internal_mobilebackup2_receive_message(client, "Response", &dict);
	if (err != MOBILEBACKUP2_E_SUCCESS)
		goto leave;

	/* check if we received an error */
	plist_t node = plist_dict_get_item(dict, "ErrorCode");
	if (!node || (plist_get_node_type(node) != PLIST_UINT)) {
		err = MOBILEBACKUP2_E_PLIST_ERROR;
		goto leave;
	}

	uint64_t val = 0;
	plist_get_uint_val(node, &val);
	if (val != 0) {
		if (val == 1) {
			err = MOBILEBACKUP2_E_NO_COMMON_VERSION;
		} else {
			err = MOBILEBACKUP2_E_REPLY_NOT_OK;
		}
		goto leave;
	}

	/* retrieve the protocol version of the device */
	node = plist_dict_get_item(dict, "ProtocolVersion");
	if (!node || (plist_get_node_type(node) != PLIST_REAL)) {
		err = MOBILEBACKUP2_E_PLIST_ERROR;
		goto leave;
	}

	*remote_version = 0.0;
	plist_get_real_val(node, remote_version);
leave:
	if (dict)
		plist_free(dict);
	return err;
}

mobilebackup2_error_t mobilebackup2_send_request(mobilebackup2_client_t client, const char *request, const char *target_identifier, const char *source_identifier, plist_t options)
{
	if (!client || !client->parent || !request || !target_identifier)
		return MOBILEBACKUP2_E_INVALID_ARG;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "TargetIdentifier", plist_new_string(target_identifier));
	if (source_identifier) {
		plist_dict_set_item(dict, "SourceIdentifier", plist_new_string(source_identifier));
	}
	if (options) {
		plist_dict_set_item(dict, "Options", plist_copy(options));
	}
	if (!strcmp(request, "Unback") && options) {
		plist_t node = plist_dict_get_item(options, "Password");
		if (node) {
			plist_dict_set_item(dict, "Password", plist_copy(node));
		}
	}
	if (!strcmp(request, "EnableCloudBackup") && options) {
		plist_t node = plist_dict_get_item(options, "CloudBackupState");
		if (node) {
			plist_dict_set_item(dict, "CloudBackupState", plist_copy(node));
		}
	}
	mobilebackup2_error_t err = mobilebackup2_send_message(client, request, dict);
	plist_free(dict);

	return err;
}

mobilebackup2_error_t mobilebackup2_send_status_response(mobilebackup2_client_t client, int status_code, const char *status1, plist_t status2)
{
	if (!client || !client->parent)
		return MOBILEBACKUP2_E_INVALID_ARG;

	plist_t array = plist_new_array();
	plist_array_append_item(array, plist_new_string("DLMessageStatusResponse"));
	plist_array_append_item(array, plist_new_uint(status_code));
	if (status1) {
		plist_array_append_item(array, plist_new_string(status1));
	} else {
		plist_array_append_item(array, plist_new_string("___EmptyParameterString___"));
	}
	if (status2) {
		plist_array_append_item(array, plist_copy(status2));
	} else {
		plist_array_append_item(array, plist_new_string("___EmptyParameterString___"));
	}

	mobilebackup2_error_t err = mobilebackup2_error(device_link_service_send(client->parent, array));
	plist_free(array);

	return err;
}
