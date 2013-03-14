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
#include "debug.h"

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

/**
 * Connects to the mobilebackup2 service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated
 *     mobilebackup2_client_t upon successful return.
 *
 * @return MOBILEBACKUP2_E_SUCCESS on success, MOBILEBACKUP2_E_INVALID ARG
 *     if one or more parameter is invalid, or MOBILEBACKUP2_E_BAD_VERSION
 *     if the mobilebackup2 version on the device is newer.
 */
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

/**
 * Disconnects a mobilebackup2 client from the device and frees up the
 * mobilebackup2 client data.
 *
 * @param client The mobilebackup2 client to disconnect and free.
 *
 * @return MOBILEBACKUP2_E_SUCCESS on success, or MOBILEBACKUP2_E_INVALID_ARG
 *     if client is NULL.
 */
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

/**
 * Sends a backup message plist.
 *
 * @param client The connected MobileBackup client to use.
 * @param message The message to send. This will be inserted into the request
 *     plist as value for MessageName. If this parameter is NULL,
 *     the plist passed in the options parameter will be sent directly.
 * @param options Additional options as PLIST_DICT to add to the request.
 *     The MessageName key with the value passed in the message parameter
 *     will be inserted into this plist before sending it. This parameter
 *     can be NULL if message is not NULL.
 */
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
		plist_dict_insert_item(dict, "MessageName", plist_new_string(message));

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

/**
 * Receives a DL* message plist from the device.
 * This function is a wrapper around device_link_service_receive_message.
 *
 * @param client The connected MobileBackup client to use.
 * @param msg_plist Pointer to a plist that will be set to the contents of the
 *    message plist upon successful return.
 * @param dlmessage A pointer that will be set to a newly allocated char*
 *     containing the DL* string from the given plist. It is up to the caller
 *     to free the allocated memory. If this parameter is NULL
 *     it will be ignored.
 *
 * @return MOBILEBACKUP2_E_SUCCESS if a DL* message was received,
 *    MOBILEBACKUP2_E_INVALID_ARG if client or message is invalid,
 *    MOBILEBACKUP2_E_PLIST_ERROR if the received plist is invalid
 *    or is not a DL* message plist, or MOBILEBACKUP2_E_MUX_ERROR if
 *    receiving from the device failed.
 */
mobilebackup2_error_t mobilebackup2_receive_message(mobilebackup2_client_t client, plist_t *msg_plist, char **dlmessage)
{
	return mobilebackup2_error(device_link_service_receive_message(client->parent, msg_plist, dlmessage));
}

/**
 * Send binary data to the device.
 *
 * @note This function returns MOBILEBACKUP2_E_SUCCESS even if less than the
 *     requested length has been sent. The fourth parameter is required and
 *     must be checked to ensure if the whole data has been sent.
 *
 * @param client The MobileBackup client to send to.
 * @param data Pointer to the data to send
 * @param length Number of bytes to send
 * @param bytes Number of bytes actually sent
 *
 * @return MOBILEBACKUP2_E_SUCCESS if any data was successfully sent,
 *     MOBILEBACKUP2_E_INVALID_ARG if one of the parameters is invalid,
 *     or MOBILEBACKUP2_E_MUX_ERROR if sending of the data failed.
 */
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

/**
 * Receive binary from the device.
 *
 * @note This function returns MOBILEBACKUP2_E_SUCCESS even if no data
 *     has been received (unless a communication error occured).
 *     The fourth parameter is required and must be checked to know how
 *     many bytes were actually received.
 *
 * @param client The MobileBackup client to receive from.
 * @param data Pointer to a buffer that will be filled with the received data.
 * @param length Number of bytes to receive. The data buffer needs to be large
 *     enough to store this amount of data.
 * @paran bytes Number of bytes actually received.
 *
 * @return MOBILEBACKUP2_E_SUCCESS if any or no data was received,
 *     MOBILEBACKUP2_E_INVALID_ARG if one of the parameters is invalid,
 *     or MOBILEBACKUP2_E_MUX_ERROR if receiving the data failed.
 */
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

/**
 * Performs the mobilebackup2 protocol version exchange.
 * 
 * @param client The MobileBackup client to use.
 * @param local_versions An array of supported versions to send to the remote.
 * @param count The number of items in local_versions.
 * @param remote_version Holds the protocol version of the remote on success.
 * 
 * @return MOBILEBACKUP2_E_SUCCESS on success, or a MOBILEBACKUP2_E_* error
 *     code otherwise.
 */
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
	plist_dict_insert_item(dict, "SupportedProtocolVersions", array);

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

/**
 * Send a request to the connected mobilebackup2 service.
 *
 * @param client
 * @param request The request to send to the backup service.
 *     Currently, this is one of "Backup", "Restore", "Info", or "List".
 * @param target_identifier UDID of the target device.
 * @param source_identifier UDID of backup data?
 * @param options Additional options in a plist of type PLIST_DICT.
 *
 * @return MOBILEBACKUP2_E_SUCCESS if the request was successfully sent,
 *     or a MOBILEBACKUP2_E_* error value otherwise.
 */
mobilebackup2_error_t mobilebackup2_send_request(mobilebackup2_client_t client, const char *request, const char *target_identifier, const char *source_identifier, plist_t options)
{
	if (!client || !client->parent || !request || !target_identifier)
		return MOBILEBACKUP2_E_INVALID_ARG;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "TargetIdentifier", plist_new_string(target_identifier));
	if (source_identifier) {
		plist_dict_insert_item(dict, "SourceIdentifier", plist_new_string(source_identifier));
	}
	if (options) {
		plist_dict_insert_item(dict, "Options", plist_copy(options));
	}
	mobilebackup2_error_t err = mobilebackup2_send_message(client, request, dict);
	plist_free(dict);

	return err;
}

/**
 * Sends a DLMessageStatusResponse to the device.
 * 
 * @param client The MobileBackup client to use.
 * @param status_code The status code to send.
 * @param status1 A status message to send. Can be NULL if not required.
 * @param status2 An additional status plist to attach to the response.
 *     Can be NULL if not required.
 *
 * @return MOBILEBACKUP2_E_SUCCESS on success, MOBILEBACKUP2_E_INVALID_ARG
 *     if client is invalid, or another MOBILEBACKUP2_E_* otherwise.
 */
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
