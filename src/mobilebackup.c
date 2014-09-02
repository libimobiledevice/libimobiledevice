/*
 * mobilebackup.c 
 * Contains functions for the built-in MobileBackup client.
 * 
 * Copyright (c) 2009 Martin Szulecki All Rights Reserved.
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

#include "mobilebackup.h"
#include "device_link_service.h"
#include "common/debug.h"

#define MBACKUP_VERSION_INT1 100
#define MBACKUP_VERSION_INT2 0

#define IS_FLAG_SET(x, y) ((x & y) == y)

/**
 * Convert an device_link_service_error_t value to an mobilebackup_error_t value.
 * Used internally to get correct error codes when using device_link_service stuff.
 *
 * @param err An device_link_service_error_t error code
 *
 * @return A matching mobilebackup_error_t error code,
 *     MOBILEBACKUP_E_UNKNOWN_ERROR otherwise.
 */
static mobilebackup_error_t mobilebackup_error(device_link_service_error_t err)
{
	switch (err) {
		case DEVICE_LINK_SERVICE_E_SUCCESS:
			return MOBILEBACKUP_E_SUCCESS;
		case DEVICE_LINK_SERVICE_E_INVALID_ARG:
			return MOBILEBACKUP_E_INVALID_ARG;
		case DEVICE_LINK_SERVICE_E_PLIST_ERROR:
			return MOBILEBACKUP_E_PLIST_ERROR;
		case DEVICE_LINK_SERVICE_E_MUX_ERROR:
			return MOBILEBACKUP_E_MUX_ERROR;
		case DEVICE_LINK_SERVICE_E_BAD_VERSION:
			return MOBILEBACKUP_E_BAD_VERSION;
		default:
			break;
	}
	return MOBILEBACKUP_E_UNKNOWN_ERROR;
}

mobilebackup_error_t mobilebackup_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobilebackup_client_t * client)
{
	if (!device || !service || service->port == 0 || !client || *client)
		return MOBILEBACKUP_E_INVALID_ARG;

	device_link_service_client_t dlclient = NULL;
	mobilebackup_error_t ret = mobilebackup_error(device_link_service_client_new(device, service, &dlclient));
	if (ret != MOBILEBACKUP_E_SUCCESS) {
		return ret;
	}

	mobilebackup_client_t client_loc = (mobilebackup_client_t) malloc(sizeof(struct mobilebackup_client_private));
	client_loc->parent = dlclient;

	/* perform handshake */
	ret = mobilebackup_error(device_link_service_version_exchange(dlclient, MBACKUP_VERSION_INT1, MBACKUP_VERSION_INT2));
	if (ret != MOBILEBACKUP_E_SUCCESS) {
		debug_info("version exchange failed, error %d", ret);
		mobilebackup_client_free(client_loc);
		return ret;
	}

	*client = client_loc;

	return ret;
}

mobilebackup_error_t mobilebackup_client_start_service(idevice_t device, mobilebackup_client_t * client, const char* label)
{
	mobilebackup_error_t err = MOBILEBACKUP_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, MOBILEBACKUP_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(mobilebackup_client_new), &err);
	return err;
}

mobilebackup_error_t mobilebackup_client_free(mobilebackup_client_t client)
{
	if (!client)
		return MOBILEBACKUP_E_INVALID_ARG;
	mobilebackup_error_t err = MOBILEBACKUP_E_SUCCESS;
	if (client->parent) {
		device_link_service_disconnect(client->parent, NULL);
		err = mobilebackup_error(device_link_service_client_free(client->parent));
	}
	free(client);
	return err;
}

mobilebackup_error_t mobilebackup_receive(mobilebackup_client_t client, plist_t * plist)
{
	if (!client)
		return MOBILEBACKUP_E_INVALID_ARG;
	mobilebackup_error_t ret = mobilebackup_error(device_link_service_receive(client->parent, plist));
	return ret;
}

mobilebackup_error_t mobilebackup_send(mobilebackup_client_t client, plist_t plist)
{
	if (!client || !plist)
		return MOBILEBACKUP_E_INVALID_ARG;
	return mobilebackup_error(device_link_service_send(client->parent, plist));
}

/**
 * Sends a backup message plist.
 *
 * @param client The connected MobileBackup client to use.
 * @param message The message to send. This will be inserted into the request
 *     plist as value for BackupMessageTypeKey. If this parameter is NULL,
 *     the plist passed in the options parameter will be sent directly.
 * @param options Additional options as PLIST_DICT to add to the request.
 *     The BackupMessageTypeKey with the value passed in the message parameter
 *     will be inserted into this plist before sending it. This parameter
 *     can be NULL if message is not NULL.
 */
static mobilebackup_error_t mobilebackup_send_message(mobilebackup_client_t client, const char *message, plist_t options)
{
	if (!client || !client->parent || (!message && !options))
		return MOBILEBACKUP_E_INVALID_ARG;

	if (options && (plist_get_node_type(options) != PLIST_DICT)) {
		return MOBILEBACKUP_E_INVALID_ARG;
	}

	mobilebackup_error_t err;

	if (message) {
		plist_t dict = NULL;
		if (options) {
			dict = plist_copy(options);
		} else {
			dict = plist_new_dict();
		}
		plist_dict_set_item(dict, "BackupMessageTypeKey", plist_new_string(message));

		/* send it as DLMessageProcessMessage */
		err = mobilebackup_error(device_link_service_send_process_message(client->parent, dict));
		plist_free(dict);
	} else {
		err = mobilebackup_error(device_link_service_send_process_message(client->parent, options));
	}
	if (err != MOBILEBACKUP_E_SUCCESS) {
		debug_info("ERROR: Could not send message '%s' (%d)!", message, err);
	}
	return err;
}

/**
 * Receives a plist from the device and checks if the value for the
 * BackupMessageTypeKey matches the value passed in the message parameter.
 *
 * @param client The connected MobileBackup client to use.
 * @param message The expected message to check.
 * @param result Pointer to a plist_t that will be set to the received plist
 *    for further processing. The caller has to free it using plist_free().
 *    Note that it will be set to NULL if the operation itself fails due to
 *    a communication or plist error.
 *    If this parameter is NULL, it will be ignored.
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, MOBILEBACKUP_E_INVALID_ARG if
 *    client or message is invalid, MOBILEBACKUP_E_REPLY_NOT_OK if the
 *    expected message could not be received, MOBILEBACKUP_E_PLIST_ERROR if
 *    the received message is not a valid backup message plist (i.e. the
 *    BackupMessageTypeKey is not present), or MOBILEBACKUP_E_MUX_ERROR
 *    if a communication error occurs.
 */
static mobilebackup_error_t mobilebackup_receive_message(mobilebackup_client_t client, const char *message, plist_t *result)
{
	if (!client || !client->parent || !message)
		return MOBILEBACKUP_E_INVALID_ARG;

	if (result)
		*result = NULL;
	mobilebackup_error_t err;

	plist_t dict = NULL;

	/* receive DLMessageProcessMessage */
	err = mobilebackup_error(device_link_service_receive_process_message(client->parent, &dict));
	if (err != MOBILEBACKUP_E_SUCCESS) {
		goto leave;
	}

	plist_t node = plist_dict_get_item(dict, "BackupMessageTypeKey");
	if (!node) {
		debug_info("ERROR: BackupMessageTypeKey not found in plist!");
		err = MOBILEBACKUP_E_PLIST_ERROR;
		goto leave;
	}

	char *str = NULL;
	plist_get_string_val(node, &str);
	if (str && (strcmp(str, message) == 0)) {
		err = MOBILEBACKUP_E_SUCCESS;
	} else {
		debug_info("ERROR: BackupMessageTypeKey value does not match '%s'!", message);
		err = MOBILEBACKUP_E_REPLY_NOT_OK;
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

mobilebackup_error_t mobilebackup_request_backup(mobilebackup_client_t client, plist_t backup_manifest, const char *base_path, const char *proto_version)
{
	if (!client || !client->parent || !base_path || !proto_version)
		return MOBILEBACKUP_E_INVALID_ARG;

	if (backup_manifest && (plist_get_node_type(backup_manifest) != PLIST_DICT))
		return MOBILEBACKUP_E_PLIST_ERROR;

	mobilebackup_error_t err;

	/* construct request plist */
	plist_t dict = plist_new_dict();
	if (backup_manifest)
		plist_dict_set_item(dict, "BackupManifestKey", plist_copy(backup_manifest));
	plist_dict_set_item(dict, "BackupComputerBasePathKey", plist_new_string(base_path));
	plist_dict_set_item(dict, "BackupMessageTypeKey", plist_new_string("BackupMessageBackupRequest"));
	plist_dict_set_item(dict, "BackupProtocolVersion", plist_new_string(proto_version));

	/* send request */
	err = mobilebackup_send_message(client, NULL, dict);
	plist_free(dict);
	dict = NULL;
	if (err != MOBILEBACKUP_E_SUCCESS) {
		debug_info("ERROR: Could not send backup request message (%d)!", err);
		goto leave;
	}

	/* now receive and hopefully get a BackupMessageBackupReplyOK */
	err = mobilebackup_receive_message(client, "BackupMessageBackupReplyOK", &dict);
	if (err != MOBILEBACKUP_E_SUCCESS) {
		debug_info("ERROR: Could not receive BackupReplyOK message (%d)!", err);
		goto leave;
	}

	plist_t node = plist_dict_get_item(dict, "BackupProtocolVersion");
	if (node) {
		char *str = NULL;
		plist_get_string_val(node, &str);
		if (str) {
			if (strcmp(str, proto_version) != 0) {
				err = MOBILEBACKUP_E_BAD_VERSION;
			}
			free(str);
		}
	}
	if (err != MOBILEBACKUP_E_SUCCESS)
		goto leave;

	/* BackupMessageBackupReplyOK received, send it back */
	err = mobilebackup_send_message(client, NULL, dict);
	if (err != MOBILEBACKUP_E_SUCCESS) {
		debug_info("ERROR: Could not send BackupReplyOK ACK (%d)", err);
	}

leave:
	if (dict)
		plist_free(dict);
	return err;
}

mobilebackup_error_t mobilebackup_send_backup_file_received(mobilebackup_client_t client)
{
	return mobilebackup_send_message(client, "kBackupMessageBackupFileReceived", NULL);
}

mobilebackup_error_t mobilebackup_request_restore(mobilebackup_client_t client, plist_t backup_manifest, mobilebackup_flags_t flags, const char *proto_version)
{
	if (!client || !client->parent || !backup_manifest || !proto_version)
		return MOBILEBACKUP_E_INVALID_ARG;

	if (backup_manifest && (plist_get_node_type(backup_manifest) != PLIST_DICT))
		return MOBILEBACKUP_E_PLIST_ERROR;

	mobilebackup_error_t err;

	/* construct request plist */
	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "BackupManifestKey", plist_copy(backup_manifest));
	plist_dict_set_item(dict, "BackupMessageTypeKey", plist_new_string("kBackupMessageRestoreRequest"));
	plist_dict_set_item(dict, "BackupProtocolVersion", plist_new_string(proto_version));
	/* add flags */
	plist_dict_set_item(dict, "BackupNotifySpringBoard", plist_new_bool(IS_FLAG_SET(flags, MB_RESTORE_NOTIFY_SPRINGBOARD)));
	plist_dict_set_item(dict, "BackupPreserveSettings", plist_new_bool(IS_FLAG_SET(flags, MB_RESTORE_PRESERVE_SETTINGS)));
	plist_dict_set_item(dict, "BackupPreserveCameraRoll", plist_new_bool(IS_FLAG_SET(flags, MB_RESTORE_PRESERVE_CAMERA_ROLL)));

	/* send request */
	err = mobilebackup_send_message(client, NULL, dict);
	plist_free(dict);
	dict = NULL;
	if (err != MOBILEBACKUP_E_SUCCESS) {
		debug_info("ERROR: Could not send restore request message (%d)!", err);
		goto leave;
	}

	/* now receive and hopefully get a BackupMessageRestoreReplyOK */
	err = mobilebackup_receive_message(client, "BackupMessageRestoreReplyOK", &dict);
	if (err != MOBILEBACKUP_E_SUCCESS) {
		debug_info("ERROR: Could not receive RestoreReplyOK message (%d)!", err);
		goto leave;
	}

	plist_t node = plist_dict_get_item(dict, "BackupProtocolVersion");
	if (node) {
		char *str = NULL;
		plist_get_string_val(node, &str);
		if (str) {
			if (strcmp(str, proto_version) != 0) {
				err = MOBILEBACKUP_E_BAD_VERSION;
			}
			free(str);
		}
	}

leave:
	if (dict)
		plist_free(dict);
	return err;
}

mobilebackup_error_t mobilebackup_receive_restore_file_received(mobilebackup_client_t client, plist_t *result)
{
	return mobilebackup_receive_message(client, "BackupMessageRestoreFileReceived", result);
}

mobilebackup_error_t mobilebackup_receive_restore_application_received(mobilebackup_client_t client, plist_t *result)
{
	return mobilebackup_receive_message(client, "BackupMessageRestoreApplicationReceived", result);
}

mobilebackup_error_t mobilebackup_send_restore_complete(mobilebackup_client_t client)
{
	mobilebackup_error_t err = mobilebackup_send_message(client, "BackupMessageRestoreComplete", NULL);
	if (err != MOBILEBACKUP_E_SUCCESS) {
		return err;
	}
	plist_t dlmsg = NULL;
	err = mobilebackup_receive(client, &dlmsg);
	if ((err != MOBILEBACKUP_E_SUCCESS) || !dlmsg || (plist_get_node_type(dlmsg) != PLIST_ARRAY) || (plist_array_get_size(dlmsg) != 2)) {
		if (dlmsg) {
			debug_info("ERROR: Did not receive DLMessageDisconnect:");
			debug_plist(dlmsg);
			plist_free(dlmsg);
		}
		if (err == MOBILEBACKUP_E_SUCCESS) {
			err = MOBILEBACKUP_E_PLIST_ERROR;
		}
		return err;
	}
	plist_t node = plist_array_get_item (dlmsg, 0);
	char *msg = NULL;
	if (node && (plist_get_node_type(node) == PLIST_STRING)) {
		plist_get_string_val(node, &msg);
	}

	if (msg && !strcmp(msg, "DLMessageDisconnect")) {
		err = MOBILEBACKUP_E_SUCCESS;
		/* we need to do this here, otherwise mobilebackup_client_free
		   will fail */
		device_link_service_client_free(client->parent);
		client->parent = NULL;
	} else {
		debug_info("ERROR: Malformed plist received:");
		debug_plist(dlmsg);
		err = MOBILEBACKUP_E_PLIST_ERROR;
	}

	plist_free(dlmsg);

	if (msg)
		free(msg);

	return err;
}

mobilebackup_error_t mobilebackup_send_error(mobilebackup_client_t client, const char *reason)
{
	if (!client || !client->parent || !reason)
		return MOBILEBACKUP_E_INVALID_ARG;

	mobilebackup_error_t err;

	/* construct error plist */
	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "BackupErrorReasonKey", plist_new_string(reason));

	err = mobilebackup_send_message(client, "BackupMessageError", dict);
	plist_free(dict);

	return err;
}
