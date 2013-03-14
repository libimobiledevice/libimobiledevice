/*
 * mobilesync.c 
 * Contains functions for the built-in MobileSync client.
 * 
 * Copyright (c) 2010 Bryan Forbes All Rights Reserved.
 * Copyright (c) 2009 Jonathan Beck All Rights Reserved.
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

#define _GNU_SOURCE 1
#define __USE_GNU 1

#include <plist/plist.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mobilesync.h"
#include "device_link_service.h"
#include "debug.h"

#define MSYNC_VERSION_INT1 300
#define MSYNC_VERSION_INT2 100

#define EMPTY_PARAMETER_STRING "___EmptyParameterString___"

/**
 * Convert an #device_link_service_error_t value to an #mobilesync_error_t value.
 * Used internally to get correct error codes when using device_link_service stuff.
 *
 * @param err A #device_link_service_error_t error code
 *
 * @return A matching #mobilesync_error_t error code,
 *     MOBILESYNC_E_UNKNOWN_ERROR otherwise.
 */
static mobilesync_error_t mobilesync_error(device_link_service_error_t err)
{
	switch (err) {
		case DEVICE_LINK_SERVICE_E_SUCCESS:
			return MOBILESYNC_E_SUCCESS;
		case DEVICE_LINK_SERVICE_E_INVALID_ARG:
			return MOBILESYNC_E_INVALID_ARG;
		case DEVICE_LINK_SERVICE_E_PLIST_ERROR:
			return MOBILESYNC_E_PLIST_ERROR;
		case DEVICE_LINK_SERVICE_E_MUX_ERROR:
			return MOBILESYNC_E_MUX_ERROR;
		case DEVICE_LINK_SERVICE_E_BAD_VERSION:
			return MOBILESYNC_E_BAD_VERSION;
		default:
			break;
	}
	return MOBILESYNC_E_UNKNOWN_ERROR;
}

/**
 * Connects to the mobilesync service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated
 *     #mobilesync_client_t upon successful return.
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one or more parameters are invalid
 * @retval DEVICE_LINK_SERVICE_E_BAD_VERSION if the mobilesync version on
 * the device is newer.
 */
mobilesync_error_t mobilesync_client_new(idevice_t device, lockdownd_service_descriptor_t service,
						   mobilesync_client_t * client)
{
	if (!device || !service || service->port == 0 || !client || *client)
		return MOBILESYNC_E_INVALID_ARG;

	device_link_service_client_t dlclient = NULL;
	mobilesync_error_t ret = mobilesync_error(device_link_service_client_new(device, service, &dlclient));
	if (ret != MOBILESYNC_E_SUCCESS) {
		return ret;
	}

	mobilesync_client_t client_loc = (mobilesync_client_t) malloc(sizeof(struct mobilesync_client_private));
	client_loc->parent = dlclient;
	client_loc->direction = MOBILESYNC_SYNC_DIR_DEVICE_TO_COMPUTER;
	client_loc->data_class = NULL;

	/* perform handshake */
	ret = mobilesync_error(device_link_service_version_exchange(dlclient, MSYNC_VERSION_INT1, MSYNC_VERSION_INT2));
	if (ret != MOBILESYNC_E_SUCCESS) {
		debug_info("version exchange failed, error %d", ret);
		mobilesync_client_free(client_loc);
		return ret;
	}

	*client = client_loc;

	return ret;
}

/**
 * Disconnects a mobilesync client from the device and frees up the
 * mobilesync client data.
 *
 * @param client The mobilesync client to disconnect and free.
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if \a client is NULL.
 */
mobilesync_error_t mobilesync_client_free(mobilesync_client_t client)
{
	if (!client)
		return MOBILESYNC_E_INVALID_ARG;
	device_link_service_disconnect(client->parent, "All done, thanks for the memories");
	mobilesync_error_t err = mobilesync_error(device_link_service_client_free(client->parent));
	free(client);
	return err;
}

/**
 * Polls the device for mobilesync data.
 *
 * @param client The mobilesync client
 * @param plist A pointer to the location where the plist should be stored
 *
 * @return an error code
 */
mobilesync_error_t mobilesync_receive(mobilesync_client_t client, plist_t * plist)
{
	if (!client)
		return MOBILESYNC_E_INVALID_ARG;
	mobilesync_error_t ret = mobilesync_error(device_link_service_receive(client->parent, plist));
	return ret;
}

/**
 * Sends mobilesync data to the device
 * 
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The mobilesync client
 * @param plist The location of the plist to send
 *
 * @return an error code
 */
mobilesync_error_t mobilesync_send(mobilesync_client_t client, plist_t plist)
{
	if (!client || !plist)
		return MOBILESYNC_E_INVALID_ARG;
	return mobilesync_error(device_link_service_send(client->parent, plist));
}

/**
 * Requests starting synchronization of a data class with the device
 *
 * @param client The mobilesync client
 * @param data_class The data class identifier to sync
 * @param anchors The anchors required to exchange with the device. The anchors
 *   allow the device to tell if the synchronization information on the computer
 *   and device are consistent to determine what sync type is required.
 * @param computer_data_class_version The version of the data class storage on the computer
 * @param sync_type A pointer to store the sync type reported by the device_anchor
 * @param device_data_class_version The version of the data class storage on the device
 * @param error_description A pointer to store an error message if reported by the device
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 * @retval MOBILESYNC_E_PLIST_ERROR if the received plist is not of valid form
 * @retval MOBILESYNC_E_SYNC_REFUSED if the device refused to sync
 * @retval MOBILESYNC_E_CANCELLED if the device explicitly cancelled the
 * sync request
 */
mobilesync_error_t mobilesync_start(mobilesync_client_t client, const char *data_class, mobilesync_anchors_t anchors, uint64_t computer_data_class_version, mobilesync_sync_type_t *sync_type, uint64_t *device_data_class_version, char** error_description)
{
	if (!client || client->data_class || !data_class ||
		!anchors || !anchors->computer_anchor) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	mobilesync_error_t err = MOBILESYNC_E_UNKNOWN_ERROR;
	char *response_type = NULL;
	char *sync_type_str = NULL;
	plist_t msg = NULL;
	plist_t response_type_node = NULL;

	*error_description = NULL;

	msg = plist_new_array();
	plist_array_append_item(msg, plist_new_string("SDMessageSyncDataClassWithDevice"));
	plist_array_append_item(msg, plist_new_string(data_class));
	if (anchors->device_anchor) {
		plist_array_append_item(msg, plist_new_string(anchors->device_anchor));
	} else {
		plist_array_append_item(msg, plist_new_string("---"));
	}
	plist_array_append_item(msg, plist_new_string(anchors->computer_anchor));
	plist_array_append_item(msg, plist_new_uint(computer_data_class_version));
	plist_array_append_item(msg, plist_new_string(EMPTY_PARAMETER_STRING));

	err = mobilesync_send(client, msg);

	if (err != MOBILESYNC_E_SUCCESS) {
		goto out;
	}

	plist_free(msg);
	msg = NULL;

	err = mobilesync_receive(client, &msg);

	if (err != MOBILESYNC_E_SUCCESS) {
		goto out;
	}

	response_type_node = plist_array_get_item(msg, 0);
	if (!response_type_node) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	plist_get_string_val(response_type_node, &response_type);
	if (!response_type) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	// did the device refuse to sync with the computer?
	if (!strcmp(response_type, "SDMessageRefuseToSyncDataClassWithComputer")) {
		err = MOBILESYNC_E_SYNC_REFUSED;
		plist_get_string_val(plist_array_get_item(msg, 2), error_description);
		debug_info("Device refused sync: %s", error_description);
		goto out;
	}

	// did the device cancel the session?
	if (!strcmp(response_type, "SDMessageCancelSession")) {
		err = MOBILESYNC_E_CANCELLED;
		plist_get_string_val(plist_array_get_item(msg, 2), error_description);
		debug_info("Device cancelled: %s", error_description);
		goto out;
	}

	if (sync_type != NULL) {
		plist_t sync_type_node = plist_array_get_item(msg, 4);
		if (!sync_type_node) {
			err = MOBILESYNC_E_PLIST_ERROR;
			goto out;
		}

		plist_get_string_val(sync_type_node, &sync_type_str);
		if (!sync_type_str) {
			err = MOBILESYNC_E_PLIST_ERROR;
			goto out;
		}

		if (!strcmp(sync_type_str, "SDSyncTypeFast")) {
			*sync_type = MOBILESYNC_SYNC_TYPE_FAST;
		} else if (!strcmp(sync_type_str, "SDSyncTypeSlow")) {
			*sync_type = MOBILESYNC_SYNC_TYPE_SLOW;
		} else if (!strcmp(sync_type_str, "SDSyncTypeReset")) {
			*sync_type = MOBILESYNC_SYNC_TYPE_RESET;
		} else {
			err = MOBILESYNC_E_PLIST_ERROR;
			goto out;
		}
	}

	if (device_data_class_version != NULL) {
		plist_t device_data_class_version_node = plist_array_get_item(msg, 5);
		if (!device_data_class_version_node) {
			err = MOBILESYNC_E_PLIST_ERROR;
			goto out;
		}

		plist_get_uint_val(device_data_class_version_node, device_data_class_version);
	}

	err = MOBILESYNC_E_SUCCESS;

	out:
	if (sync_type_str) {
		free(sync_type_str);
		sync_type_str = NULL;
	}
	if (response_type) {
		free(response_type);
		response_type = NULL;
	}
	if (msg) {
		plist_free(msg);
		msg = NULL;
	}

	client->data_class = strdup(data_class);
	client->direction = MOBILESYNC_SYNC_DIR_DEVICE_TO_COMPUTER;
	return err;
}

/**
 * Finish a synchronization session of a data class on the device.
 * A session must have previously been started using mobilesync_start().
 *
 * @param client The mobilesync client
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 * @retval MOBILESYNC_E_PLIST_ERROR if the received plist is not of valid
 * form
 */
mobilesync_error_t mobilesync_finish(mobilesync_client_t client)
{
	if (!client || !client->data_class) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	mobilesync_error_t err = MOBILESYNC_E_UNKNOWN_ERROR;

	plist_t msg = NULL;
	plist_t response_type_node = NULL;
	char *response_type = NULL;

	msg = plist_new_array();
	plist_array_append_item(msg, plist_new_string("SDMessageFinishSessionOnDevice"));
	plist_array_append_item(msg, plist_new_string(client->data_class));

	err = mobilesync_send(client, msg);

	if (err != MOBILESYNC_E_SUCCESS) {
		goto out;
	}

	plist_free(msg);
	msg = NULL;

	err = mobilesync_receive(client, &msg);

	if (err != MOBILESYNC_E_SUCCESS) {
		goto out;
	}

	response_type_node = plist_array_get_item(msg, 0);
	if (!response_type_node) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	plist_get_string_val(response_type_node, &response_type);
	if (!response_type) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	if (!strcmp(response_type, "SDMessageDeviceFinishedSession")) {
		err = MOBILESYNC_E_SUCCESS;
	}

	out:
	if (response_type) {
		free(response_type);
		response_type = NULL;
	}
	if (msg) {
		plist_free(msg);
		msg = NULL;
	}

	free(client->data_class);
	client->data_class = NULL;
	client->direction = MOBILESYNC_SYNC_DIR_DEVICE_TO_COMPUTER;
	return err;
}

static mobilesync_error_t mobilesync_get_records(mobilesync_client_t client, const char *operation)
{
	if (!client || !client->data_class || !operation) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	mobilesync_error_t err = MOBILESYNC_E_UNKNOWN_ERROR;
	plist_t msg = NULL;

	msg = plist_new_array();
	plist_array_append_item(msg, plist_new_string(operation));
	plist_array_append_item(msg, plist_new_string(client->data_class));
	
	err = mobilesync_send(client, msg);

	if (msg) {
		plist_free(msg);
		msg = NULL;
	}
	return err;
}

/**
 * Requests to receive all records of the currently set data class from the device.
 * The actually changes are retrieved using mobilesync_receive_changes() after this
 * request has been successful.
 *
 * @param client The mobilesync client
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 */
mobilesync_error_t mobilesync_get_all_records_from_device(mobilesync_client_t client)
{
	return mobilesync_get_records(client, "SDMessageGetAllRecordsFromDevice");
}

/**
 * Requests to receive only changed records of the currently set data class from the device.
 * The actually changes are retrieved using mobilesync_receive_changes() after this
 * request has been successful.
 *
 * @param client The mobilesync client
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 */
mobilesync_error_t mobilesync_get_changes_from_device(mobilesync_client_t client)
{
	return mobilesync_get_records(client, "SDMessageGetChangesFromDevice");
}

/**
 * Receives changed entitites of the currently set data class from the device
 *
 * @param client The mobilesync client
 * @param entities A pointer to store the changed entity records as a PLIST_DICT
 * @param is_last_record A pointer to store a flag indicating if this submission is the last one
 * @param actions A pointer to additional flags the device is sending or NULL to ignore
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 * @retval MOBILESYNC_E_CANCELLED if the device explicitly cancelled the
 * session
 */
mobilesync_error_t mobilesync_receive_changes(mobilesync_client_t client, plist_t *entities, uint8_t *is_last_record, plist_t *actions)
{
	if (!client || !client->data_class) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	plist_t msg = NULL;
	plist_t response_type_node = NULL;
	plist_t actions_node = NULL;
	char *response_type = NULL;
	uint8_t has_more_changes = 0;

	mobilesync_error_t err = mobilesync_receive(client, &msg);
	if (err != MOBILESYNC_E_SUCCESS) {
		goto out;
	}

	response_type_node = plist_array_get_item(msg, 0);
	if (!response_type_node) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	plist_get_string_val(response_type_node, &response_type);
	if (!response_type) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	if (!strcmp(response_type, "SDMessageCancelSession")) {
		char *reason = NULL;
		err = MOBILESYNC_E_CANCELLED;
		plist_get_string_val(plist_array_get_item(msg, 2), &reason);
		debug_info("Device cancelled: %s", reason);
		free(reason);
		goto out;
	}

	if (entities != NULL) {
		*entities = plist_copy(plist_array_get_item(msg, 2));
	}

	if (is_last_record != NULL) {
		plist_get_bool_val(plist_array_get_item(msg, 3), &has_more_changes);
		*is_last_record = (has_more_changes > 0 ? 0 : 1);
	}

	if (actions != NULL) {
		actions_node = plist_array_get_item(msg, 4);
		if (plist_get_node_type(actions) == PLIST_DICT)
			*actions = plist_copy(actions_node);
		else
			*actions = NULL;
	}

	out:
	if (response_type) {
		free(response_type);
		response_type = NULL;
	}
	if (msg) {
		plist_free(msg);
		msg = NULL;
	}
	return err;
}

/**
 * Requests the device to delete all records of the current data class
 *
 * @note The operation must be called after starting synchronization.
 *
 * @param client The mobilesync client
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 * @retval MOBILESYNC_E_PLIST_ERROR if the received plist is not of valid form
 */
mobilesync_error_t mobilesync_clear_all_records_on_device(mobilesync_client_t client)
{
	if (!client || !client->data_class) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	mobilesync_error_t err = MOBILESYNC_E_UNKNOWN_ERROR;
	plist_t msg = NULL;
	plist_t response_type_node = NULL;
	char *response_type = NULL;

	msg = plist_new_array();
	plist_array_append_item(msg, plist_new_string("SDMessageClearAllRecordsOnDevice"));
	plist_array_append_item(msg, plist_new_string(client->data_class));
	plist_array_append_item(msg, plist_new_string(EMPTY_PARAMETER_STRING));

	err = mobilesync_send(client, msg);

	if (err != MOBILESYNC_E_SUCCESS) {
		goto out;
	}

	plist_free(msg);
	msg = NULL;

	err = mobilesync_receive(client, &msg);

	if (err != MOBILESYNC_E_SUCCESS) {
		goto out;
	}

	response_type_node = plist_array_get_item(msg, 0);
	if (!response_type_node) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	plist_get_string_val(response_type_node, &response_type);
	if (!response_type) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	if (!strcmp(response_type, "SDMessageCancelSession")) {
		char *reason = NULL;
		err = MOBILESYNC_E_CANCELLED;
		plist_get_string_val(plist_array_get_item(msg, 2), &reason);
		debug_info("Device cancelled: %s", reason);
		free(reason);
		goto out;
	}

	if (strcmp(response_type, "SDMessageDeviceWillClearAllRecords")) {
		err = MOBILESYNC_E_PLIST_ERROR;
	}

	out:
	if (response_type) {
		free(response_type);
		response_type = NULL;
	}
	if (msg) {
		plist_free(msg);
		msg = NULL;
	}

	return err;
}

/**
 * Acknowledges to the device that the changes have been merged on the computer
 *
 * @param client The mobilesync client
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 */
mobilesync_error_t mobilesync_acknowledge_changes_from_device(mobilesync_client_t client)
{
	if (!client || !client->data_class) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	plist_t msg = NULL;
	mobilesync_error_t err = MOBILESYNC_E_UNKNOWN_ERROR;

	msg = plist_new_array();
	plist_array_append_item(msg, plist_new_string("SDMessageAcknowledgeChangesFromDevice"));
	plist_array_append_item(msg, plist_new_string(client->data_class));

	err = mobilesync_send(client, msg);
	plist_free(msg);
	return err;
}

static plist_t create_process_changes_message(const char *data_class, plist_t entities, uint8_t more_changes, plist_t actions)
{
	plist_t msg = plist_new_array();
	plist_array_append_item(msg, plist_new_string("SDMessageProcessChanges"));
	plist_array_append_item(msg, plist_new_string(data_class));
	plist_array_append_item(msg, plist_copy(entities));
	plist_array_append_item(msg, plist_new_bool(more_changes));

	if (actions)
		plist_array_append_item(msg, plist_copy(actions));
	else
		plist_array_append_item(msg, plist_new_string(EMPTY_PARAMETER_STRING));

	return msg;
}

/**
 * Verifies if the device is ready to receive changes from the computer.
 * This call changes the synchronization direction so that mobilesync_send_changes()
 * can be used to send changes to the device.
 *
 * @param client The mobilesync client
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 * @retval MOBILESYNC_E_PLIST_ERROR if the received plist is not of valid form
 * @retval MOBILESYNC_E_WRONG_DIRECTION if the current sync direction does
 * not permit this call
 * @retval MOBILESYNC_E_CANCELLED if the device explicitly cancelled the
 * session
 * @retval MOBILESYNC_E_NOT_READY if the device is not ready to start
 * receiving any changes
 */
mobilesync_error_t mobilesync_ready_to_send_changes_from_computer(mobilesync_client_t client)
{
	if (!client || !client->data_class) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	if (client->direction != MOBILESYNC_SYNC_DIR_DEVICE_TO_COMPUTER) {
		return MOBILESYNC_E_WRONG_DIRECTION;
	}

	plist_t msg = NULL;
	plist_t response_type_node = NULL;
	char *response_type = NULL;
	mobilesync_error_t err = MOBILESYNC_E_UNKNOWN_ERROR;

	err = mobilesync_receive(client, &msg);
	if (err != MOBILESYNC_E_SUCCESS) {
		goto out;
	}

	response_type_node = plist_array_get_item(msg, 0);
	if (!response_type_node) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	plist_get_string_val(response_type_node, &response_type);
	if (!response_type) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	if (!strcmp(response_type, "SDMessageCancelSession")) {
		char *reason = NULL;
		err = MOBILESYNC_E_CANCELLED;
		plist_get_string_val(plist_array_get_item(msg, 2), &reason);
		debug_info("Device cancelled: %s", reason);
		free(reason);
		goto out;
	}

	if (strcmp(response_type, "SDMessageDeviceReadyToReceiveChanges") != 0) {
		err = MOBILESYNC_E_NOT_READY;
		goto out;
	}

	err = mobilesync_error(device_link_service_send_ping(client->parent, "Preparing to get changes for device"));
	if (err != MOBILESYNC_E_SUCCESS) {
		goto out;
	}

	client->direction = MOBILESYNC_SYNC_DIR_COMPUTER_TO_DEVICE;
	err = MOBILESYNC_E_SUCCESS;

	out:
	if (response_type) {
		free(response_type);
		response_type = NULL;
	}
	if (msg) {
		plist_free(msg);
		msg = NULL;
	}

	return err;
}

/**
 * Sends changed entities of the currently set data class to the device
 *
 * @param client The mobilesync client
 * @param entities The changed entity records as a PLIST_DICT
 * @param is_last_record A flag indicating if this submission is the last one
 * @param actions Additional actions for the device created with mobilesync_actions_new()
 *    or NULL if no actions should be passed
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid,
 * @retval MOBILESYNC_E_WRONG_DIRECTION if the current sync direction does
 * not permit this call
 */
mobilesync_error_t mobilesync_send_changes(mobilesync_client_t client, plist_t entities, uint8_t is_last_record, plist_t actions)
{
	if (!client || !client->data_class || !entities) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	if (plist_get_node_type(entities) != PLIST_DICT) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	if (client->direction != MOBILESYNC_SYNC_DIR_COMPUTER_TO_DEVICE) {
		return MOBILESYNC_E_WRONG_DIRECTION;
	}

	mobilesync_error_t err = MOBILESYNC_E_UNKNOWN_ERROR;
	plist_t msg = NULL;

	msg = create_process_changes_message(client->data_class, entities, (is_last_record > 0 ? 0 : 1), actions);
	err = mobilesync_send(client, msg);

	if (msg) {
		plist_free(msg);
		msg = NULL;
	}

	return err;
}

/**
 * Receives any remapped identifiers reported after the device merged submitted changes.
 *
 * @param client The mobilesync client
 * @param mapping A pointer to an array plist containing a dict of identifier remappings
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 * @retval MOBILESYNC_E_PLIST_ERROR if the received plist is not of valid
 * form
 * @retval MOBILESYNC_E_WRONG_DIRECTION if the current sync direction does
 * not permit this call
 * @retval MOBILESYNC_E_CANCELLED if the device explicitly cancelled the
 * session
 */
mobilesync_error_t mobilesync_remap_identifiers(mobilesync_client_t client, plist_t *mapping)
{
	if (!client || !client->data_class) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	if (client->direction == MOBILESYNC_SYNC_DIR_DEVICE_TO_COMPUTER) {
		return MOBILESYNC_E_WRONG_DIRECTION;
	}

	plist_t msg = NULL;
	plist_t response_type_node = NULL;
	char *response_type = NULL;

	mobilesync_error_t err = mobilesync_receive(client, &msg);
	if (err != MOBILESYNC_E_SUCCESS) {
		goto out;
	}

	response_type_node = plist_array_get_item(msg, 0);
	if (!response_type_node) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	plist_get_string_val(response_type_node, &response_type);
	if (!response_type) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	if (!strcmp(response_type, "SDMessageCancelSession")) {
		char *reason = NULL;
		err = MOBILESYNC_E_CANCELLED;
		plist_get_string_val(plist_array_get_item(msg, 2), &reason);
		debug_info("Device cancelled: %s", reason);
		free(reason);
		goto out;
	}

	if (strcmp(response_type, "SDMessageRemapRecordIdentifiers") != 0) {
		err = MOBILESYNC_E_PLIST_ERROR;
		goto out;
	}

	if (mapping != NULL) {
		plist_t map = plist_array_get_item(msg, 2);
		if (plist_get_node_type(map) == PLIST_DICT) {
			*mapping = plist_copy(map);
		} else {
			*mapping = NULL;
		}
	}

	err = MOBILESYNC_E_SUCCESS;

	out:
	if (response_type) {
		free(response_type);
		response_type = NULL;
	}
	if (msg) {
		plist_free(msg);
		msg = NULL;
	}

	return err;
}

/**
 * Cancels a running synchronization session with a device at any time.
 *
 * @param client The mobilesync client
 * @param reason The reason to supply to the device for cancelling
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 */
mobilesync_error_t mobilesync_cancel(mobilesync_client_t client, const char* reason)
{
	if (!client || !client->data_class || !reason) {
		return MOBILESYNC_E_INVALID_ARG;
	}

	mobilesync_error_t err = MOBILESYNC_E_UNKNOWN_ERROR;
	plist_t msg = NULL;

	msg = plist_new_array();
	plist_array_append_item(msg, plist_new_string("SDMessageCancelSession"));
	plist_array_append_item(msg, plist_new_string(client->data_class));
	plist_array_append_item(msg, plist_new_string(reason));

	err = mobilesync_send(client, msg);

	plist_free(msg);
	msg = NULL;

	free(client->data_class);
	client->data_class = NULL;
	client->direction = MOBILESYNC_SYNC_DIR_DEVICE_TO_COMPUTER;

	return err;
}

/**
 * Allocates memory for a new anchors struct initialized with the passed anchors.
 *
 * @param device_anchor An anchor the device reported the last time or NULL
 *   if none is known yet which for instance is true on first synchronization.
 * @param computer_anchor An arbitrary string to use as anchor for the computer.
 * 
 * @return A new #mobilesync_anchors_t struct. Must be freed using mobilesync_anchors_free().
 */
mobilesync_anchors_t mobilesync_anchors_new(const char *device_anchor, const char *computer_anchor)
{
	mobilesync_anchors_t anchors = (mobilesync_anchors_t) malloc(sizeof(mobilesync_anchors)); 
	if (device_anchor != NULL) {
		anchors->device_anchor = strdup(device_anchor);
	} else {
		anchors->device_anchor = NULL;
	}
	if (computer_anchor != NULL) {
		anchors->computer_anchor = strdup(computer_anchor);
	} else {
		anchors->computer_anchor = NULL;
	}

	return anchors;
}

/**
 * Free memory used by anchors.
 *
 * @param anchors The anchors to free.
 */
void mobilesync_anchors_free(mobilesync_anchors_t anchors)
{
	if (anchors->device_anchor != NULL) {
		free(anchors->device_anchor);
		anchors->device_anchor = NULL;
	}
	if (anchors->computer_anchor != NULL) {
		free(anchors->computer_anchor);
		anchors->computer_anchor = NULL;
	}
	free(anchors);
	anchors = NULL;
}

/**
 * Create a new actions plist to use in mobilesync_send_changes().
 *
 * @return A new plist_t of type PLIST_DICT.
 */
plist_t mobilesync_actions_new()
{
	return plist_new_dict();
}

/**
 * Add one or more new key:value pairs to the given actions plist.
 *
 * @param actions The actions to modify.
 * @param ... KEY, VALUE, [KEY, VALUE], NULL
 *
 * @note The known keys so far are "SyncDeviceLinkEntityNamesKey" which expects
 *       an array of entity names, followed by a count paramter as well as
 *       "SyncDeviceLinkAllRecordsOfPulledEntityTypeSentKey" which expects an
 *       integer to use as a boolean value indicating that the device should
 *       link submitted changes and report remapped identifiers.
 */
void mobilesync_actions_add(plist_t actions, ...)
{
	if (!actions)
		return;
	va_list args;
	va_start(args, actions);
	char *arg = va_arg(args, char*);
	while (arg) {
		char *key = strdup(arg);
		if (!strcmp(key, "SyncDeviceLinkEntityNamesKey")) {
			char **entity_names = va_arg(args, char**);
			int entity_names_length = va_arg(args, int);
			int i = 0;

			plist_t array = plist_new_array();

			for (i = 0; i < entity_names_length; i++) {
				plist_array_append_item(array, plist_new_string(entity_names[i]));
			}

			plist_dict_insert_item(actions, key, array);
		} else if (!strcmp(key, "SyncDeviceLinkAllRecordsOfPulledEntityTypeSentKey")) {
			int link_records = va_arg(args, int);
			plist_dict_insert_item(actions, key, plist_new_bool(link_records));
		}
		free(key);
		key = NULL;
		arg = va_arg(args, char*);
	}
	va_end(args);
}

/**
 * Free actions plist.
 *
 * @param actions The actions plist to free. Does nothing if NULL is passed.
 */
void mobilesync_actions_free(plist_t actions)
{
	if (actions) {
		plist_free(actions);
		actions = NULL;
	}
}
