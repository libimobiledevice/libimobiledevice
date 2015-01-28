/*
 * device_link_service.c
 * DeviceLink service implementation.
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
#include "device_link_service.h"
#include "property_list_service.h"
#include "common/debug.h"

/**
 * Internally used function to extract the message string from a DL* message
 * plist.
 *
 * @param dl_msg The DeviceLink property list to parse.
 * @param message A pointer that will be set to a newly allocated char*
 *     containing the DLMessage* string from the given plist. It is up to
 *     the caller to free the allocated memory. If this parameter is NULL
 *     it will be ignored.
 *
 * @return 1 if the given plist is a DL* message, or 0 if the plist does not
 *     contain any DL* message.
 */
static int device_link_service_get_message(plist_t dl_msg, char **message)
{
	plist_t cmd = NULL;
	char *cmd_str = NULL;

	/* sanity check */
	if ((plist_get_node_type(dl_msg) != PLIST_ARRAY) || (plist_array_get_size(dl_msg) < 1)) {
		return 0;
	}

	/* get dl command */
	cmd = plist_array_get_item(dl_msg, 0);
	if (!cmd || (plist_get_node_type(cmd) != PLIST_STRING)) {
		return 0;
	}

	plist_get_string_val(cmd, &cmd_str);
	if (!cmd_str) {
		return 0;
	}

	if ((strlen(cmd_str) < 9) || (strncmp(cmd_str, "DL", 2))) {
		free(cmd_str);
		return 0;
	}

	if (message)
		*message = cmd_str;

	/* we got a DL* message */
	return 1;
}

/**
 * Creates a new device link service client.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Reference that will point to a newly allocated
 *     device_link_service_client_t upon successful return.
 *
 * @return DEVICE_LINK_SERVICE_E_SUCCESS on success,
 *     DEVICE_LINK_SERVICE_E_INVALID_ARG when one of the parameters is invalid,
 *     or DEVICE_LINK_SERVICE_E_MUX_ERROR when the connection failed.
 */
device_link_service_error_t device_link_service_client_new(idevice_t device, lockdownd_service_descriptor_t service, device_link_service_client_t *client)
{
	if (!device || !service || service->port == 0 || !client || *client) {
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;
	}

	property_list_service_client_t plistclient = NULL;
	if (property_list_service_client_new(device, service, &plistclient) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return DEVICE_LINK_SERVICE_E_MUX_ERROR;
	}

	/* create client object */
	device_link_service_client_t client_loc = (device_link_service_client_t) malloc(sizeof(struct device_link_service_client_private));
	client_loc->parent = plistclient;

	/* enable SSL if requested */
	if (service->ssl_enabled)
		property_list_service_enable_ssl(client_loc->parent);

	/* all done, return success */
	*client = client_loc;
	return DEVICE_LINK_SERVICE_E_SUCCESS;
}

/**
 * Frees a device link service client.
 *
 * @param client The device_link_service_client_t to free.
 *
 * @return DEVICE_LINK_SERVICE_E_SUCCESS on success,
 *     DEVICE_LINK_SERVICE_E_INVALID_ARG when one of client or client->parent
 *     is invalid, or DEVICE_LINK_SERVICE_E_UNKNOWN_ERROR when the was an error
 *     freeing the parent property_list_service client.
 */
device_link_service_error_t device_link_service_client_free(device_link_service_client_t client)
{
	if (!client)
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;

	if (property_list_service_client_free(client->parent) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return DEVICE_LINK_SERVICE_E_UNKNOWN_ERROR;
	}
	free(client);
	return DEVICE_LINK_SERVICE_E_SUCCESS;
}

/**
 * Performs the DLMessageVersionExchange with the connected device.
 * This should be the first operation to be executed by an implemented
 * device link service client.
 *
 * @param client The device_link_service client to use.
 * @param version_major The major version number to check.
 * @param version_minor The minor version number to check.
 *
 * @return DEVICE_LINK_SERVICE_E_SUCCESS on success,
 *     DEVICE_LINK_SERVICE_E_INVALID_ARG when client is NULL,
 *     DEVICE_LINK_SERVICE_E_MUX_ERROR when a communication error occurs,
 *     DEVICE_LINK_SERVICE_E_PLIST_ERROR when the received plist has not the
 *     expected contents, DEVICE_LINK_SERVICE_E_BAD_VERSION when the version
 *     given by the device is larger than the given version,
 *     or DEVICE_LINK_SERVICE_E_UNKNOWN_ERROR otherwise.
 */
device_link_service_error_t device_link_service_version_exchange(device_link_service_client_t client, uint64_t version_major, uint64_t version_minor)
{
	if (!client)
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;

	device_link_service_error_t err = DEVICE_LINK_SERVICE_E_UNKNOWN_ERROR;

	/* perform version exchange */
	plist_t array = NULL;
	char *msg = NULL;

	/* receive DLMessageVersionExchange from device */
	if (property_list_service_receive_plist(client->parent, &array) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		debug_info("Did not receive initial message from device!");
		err = DEVICE_LINK_SERVICE_E_MUX_ERROR;
		goto leave;
	}
	device_link_service_get_message(array, &msg);
	if (!msg || strcmp(msg, "DLMessageVersionExchange")) {
		debug_info("Did not receive DLMessageVersionExchange from device!");
		err = DEVICE_LINK_SERVICE_E_PLIST_ERROR;
		goto leave;
	}
	free(msg);
	msg = NULL;

	/* get major and minor version number */
	if (plist_array_get_size(array) < 3) {
		debug_info("DLMessageVersionExchange has unexpected format!");
		err = DEVICE_LINK_SERVICE_E_PLIST_ERROR;
		goto leave;
	}
	plist_t maj = plist_array_get_item(array, 1);
	plist_t min = plist_array_get_item(array, 2);
	uint64_t vmajor = 0;
	uint64_t vminor = 0;
	if (maj) {
		plist_get_uint_val(maj, &vmajor);
	}
	if (min) {
		plist_get_uint_val(min, &vminor);
	}
	if (vmajor > version_major) {
		debug_info("Version mismatch: device=(%lld,%lld) > expected=(%lld,%lld)", vmajor, vminor, version_major, version_minor);
		err = DEVICE_LINK_SERVICE_E_BAD_VERSION;
		goto leave;
	} else if ((vmajor == version_major) && (vminor > version_minor)) {
		debug_info("WARNING: Version mismatch: device=(%lld,%lld) > expected=(%lld,%lld)", vmajor, vminor, version_major, version_minor);
		err = DEVICE_LINK_SERVICE_E_BAD_VERSION;
		goto leave;
	}
	plist_free(array);

	/* version is ok, send reply */
	array = plist_new_array();
	plist_array_append_item(array, plist_new_string("DLMessageVersionExchange"));
	plist_array_append_item(array, plist_new_string("DLVersionsOk"));
	plist_array_append_item(array, plist_new_uint(version_major));
	if (property_list_service_send_binary_plist(client->parent, array) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		debug_info("Error when sending DLVersionsOk");
		err = DEVICE_LINK_SERVICE_E_MUX_ERROR;
		goto leave;
	}
	plist_free(array);

	/* receive DeviceReady message */
	array = NULL;
	if (property_list_service_receive_plist(client->parent, &array) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		debug_info("Error when receiving DLMessageDeviceReady!");
		err = DEVICE_LINK_SERVICE_E_MUX_ERROR;
		goto leave;
	}
	device_link_service_get_message(array, &msg);
	if (!msg || strcmp(msg, "DLMessageDeviceReady")) {
		debug_info("Did not get DLMessageDeviceReady!");
		err = DEVICE_LINK_SERVICE_E_PLIST_ERROR;
		goto leave;
	}
	err = DEVICE_LINK_SERVICE_E_SUCCESS;

leave:
	if (msg) {
		free(msg);
	}
	if (array) {
		plist_free(array);
	}
	return err;
}

/**
 * Performs a disconnect with the connected device link service client.
 *
 * @param client The device link service client to disconnect.
 * @param message Optional message to send send to the device or NULL.
 *
 * @return DEVICE_LINK_SERVICE_E_SUCCESS on success,
 *     DEVICE_LINK_SERVICE_E_INVALID_ARG if client is NULL,
 *     or DEVICE_LINK_SERVICE_E_MUX_ERROR when there's an error when sending
 *     the the disconnect message.
 */
device_link_service_error_t device_link_service_disconnect(device_link_service_client_t client, const char *message)
{
	if (!client)
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;

	plist_t array = plist_new_array();
	plist_array_append_item(array, plist_new_string("DLMessageDisconnect"));
	if (message)
		plist_array_append_item(array, plist_new_string(message));
	else
		plist_array_append_item(array, plist_new_string("___EmptyParameterString___"));

	device_link_service_error_t err = DEVICE_LINK_SERVICE_E_SUCCESS;
	if (property_list_service_send_binary_plist(client->parent, array) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		err = DEVICE_LINK_SERVICE_E_MUX_ERROR;
	}
	plist_free(array);
	return err;
}

/**
 * Sends a DLMessagePing plist.
 *
 * @param client The device link service client to use.
 * @param message String to send as ping message.
 *
 * @return DEVICE_LINK_SERVICE_E_SUCCESS on success,
 *     DEVICE_LINK_SERVICE_E_INVALID_ARG if client or message is invalid,
 *     or DEVICE_LINK_SERVICE_E_MUX_ERROR if the DLMessagePing plist could
 *     not be sent.
 */
device_link_service_error_t device_link_service_send_ping(device_link_service_client_t client, const char *message)
{
	if (!client || !client->parent || !message)
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;

	plist_t array = plist_new_array();
	plist_array_append_item(array, plist_new_string("DLMessagePing"));
	plist_array_append_item(array, plist_new_string(message));

	device_link_service_error_t err = DEVICE_LINK_SERVICE_E_SUCCESS;
	if (property_list_service_send_binary_plist(client->parent, array) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		err = DEVICE_LINK_SERVICE_E_MUX_ERROR;
	}
	plist_free(array);
	return err;
}

/**
 * Sends a DLMessageProcessMessage plist.
 *
 * @param client The device link service client to use.
 * @param message PLIST_DICT to send.
 *
 * @return DEVICE_LINK_SERVICE_E_SUCCESS on success,
 *     DEVICE_LINK_SERVICE_E_INVALID_ARG if client or message is invalid or
 *     message is not a PLIST_DICT, or DEVICE_LINK_SERVICE_E_MUX_ERROR if
 *     the DLMessageProcessMessage plist could not be sent.
 */
device_link_service_error_t device_link_service_send_process_message(device_link_service_client_t client, plist_t message)
{
	if (!client || !client->parent || !message)
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;

	if (plist_get_node_type(message) != PLIST_DICT)
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;

	plist_t array = plist_new_array();
	plist_array_append_item(array, plist_new_string("DLMessageProcessMessage"));
	plist_array_append_item(array, plist_copy(message));

	device_link_service_error_t err = DEVICE_LINK_SERVICE_E_SUCCESS;
	if (property_list_service_send_binary_plist(client->parent, array) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		err = DEVICE_LINK_SERVICE_E_MUX_ERROR;
	}
	plist_free(array);
	return err;
}

/**
 * Receives a DL* message plist
 *
 * @param client The connected device link service client used for receiving.
 * @param msg_plist Pointer to a plist that will be set to the contents of the
 *    message plist upon successful return.
 * @param dlmessage A pointer that will be set to a newly allocated char*
 *     containing the DL* string from the given plist. It is up to the caller
 *     to free the allocated memory. If this parameter is NULL
 *     it will be ignored.
 *
 * @return DEVICE_LINK_SERVICE_E_SUCCESS if a DL* message was received,
 *    DEVICE_LINK_SERVICE_E_INVALID_ARG if client or message is invalid,
 *    DEVICE_LINK_SERVICE_E_PLIST_ERROR if the received plist is invalid
 *    or is not a DL* message plist, or DEVICE_LINK_SERVICE_E_MUX_ERROR if
 *    receiving from the device failed.
 */
device_link_service_error_t device_link_service_receive_message(device_link_service_client_t client, plist_t *msg_plist, char **dlmessage)
{
	if (!client || !client->parent || !msg_plist)
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;

	*msg_plist = NULL;
	if (property_list_service_receive_plist(client->parent, msg_plist) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return DEVICE_LINK_SERVICE_E_MUX_ERROR;
	}

	if (!device_link_service_get_message(*msg_plist, dlmessage)) {
		debug_info("Did not receive a DL* message as expected!");
		return DEVICE_LINK_SERVICE_E_PLIST_ERROR;
	}
	return DEVICE_LINK_SERVICE_E_SUCCESS;
}

/**
 * Receives a DLMessageProcessMessage plist.
 *
 * @param client The connected device link service client used for receiving.
 * @param message Pointer to a plist that will be set to the contents of the
 *    message contents upon successful return.
 *
 * @return DEVICE_LINK_SERVICE_E_SUCCESS when a DLMessageProcessMessage was
 *    received, DEVICE_LINK_SERVICE_E_INVALID_ARG when client or message is
 *    invalid, DEVICE_LINK_SERVICE_E_PLIST_ERROR if the received plist is
 *    invalid or is not a DLMessageProcessMessage,
 *    or DEVICE_LINK_SERVICE_E_MUX_ERROR if receiving from device fails.
 */
device_link_service_error_t device_link_service_receive_process_message(device_link_service_client_t client, plist_t *message)
{
	if (!client || !client->parent || !message)
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;

	plist_t pmsg = NULL;
	if (property_list_service_receive_plist(client->parent, &pmsg) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return DEVICE_LINK_SERVICE_E_MUX_ERROR;
	}

	device_link_service_error_t err = DEVICE_LINK_SERVICE_E_UNKNOWN_ERROR;

	char *msg = NULL;
	device_link_service_get_message(pmsg, &msg);
	if (!msg || strcmp(msg, "DLMessageProcessMessage")) {
		debug_info("Did not receive DLMessageProcessMessage as expected!");
		err = DEVICE_LINK_SERVICE_E_PLIST_ERROR;
		goto leave;
	}

	if (plist_array_get_size(pmsg) != 2) {
		debug_info("Malformed plist received for DLMessageProcessMessage");
		err = DEVICE_LINK_SERVICE_E_PLIST_ERROR;
		goto leave;
	}

	plist_t msg_loc = plist_array_get_item(pmsg, 1);
	if (msg_loc) {
		*message = plist_copy(msg_loc);
		err = DEVICE_LINK_SERVICE_E_SUCCESS;
	} else {
		*message = NULL;
		err = DEVICE_LINK_SERVICE_E_PLIST_ERROR;
	}

leave:
	if (msg)
		free(msg);
	if (pmsg)
		plist_free(pmsg);

	return err;
}

/**
 * Generic device link service send function.
 *
 * @param client The device link service client to use for sending
 * @param plist The property list to send
 *
 * @return DEVICE_LINK_SERVICE_E_SUCCESS on success,
 *     DEVICE_LINK_SERVICE_E_INVALID_ARG when client or plist is NULL,
 *     or DEVICE_LINK_SERVICE_E_MUX_ERROR when the given property list could
 *     not be sent.
 */
device_link_service_error_t device_link_service_send(device_link_service_client_t client, plist_t plist)
{
	if (!client || !plist) {
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;
	}
	if (property_list_service_send_binary_plist(client->parent, plist) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return DEVICE_LINK_SERVICE_E_MUX_ERROR;
	}
	return DEVICE_LINK_SERVICE_E_SUCCESS;
}

/* Generic device link service receive function.
 *
 * @param client The device link service client to use for sending
 * @param plist Pointer that will point to the property list received upon
 *     successful return.
 *
 * @return DEVICE_LINK_SERVICE_E_SUCCESS on success,
 *     DEVICE_LINK_SERVICE_E_INVALID_ARG when client or plist is NULL,
 *     or DEVICE_LINK_SERVICE_E_MUX_ERROR when no property list could be
 *     received.
 */
device_link_service_error_t device_link_service_receive(device_link_service_client_t client, plist_t *plist)
{
	if (!client || !plist || (plist && *plist)) {
		return DEVICE_LINK_SERVICE_E_INVALID_ARG;
	}

	if (property_list_service_receive_plist(client->parent, plist) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return DEVICE_LINK_SERVICE_E_MUX_ERROR;
	}
	return DEVICE_LINK_SERVICE_E_SUCCESS;
}

