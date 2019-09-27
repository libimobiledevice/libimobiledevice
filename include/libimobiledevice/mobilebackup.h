/**
 * @file libimobiledevice/mobilebackup.h
 * @brief Backup and restore of all device data.
 * \internal
 *
 * Copyright (c) 2010-2019 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2009-2014 Martin Szulecki, All Rights Reserved.
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

#ifndef IMOBILEBACKUP_H
#define IMOBILEBACKUP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define MOBILEBACKUP_SERVICE_NAME "com.apple.mobilebackup"

/** Error Codes */
typedef enum {
	MOBILEBACKUP_E_SUCCESS         =  0,
	MOBILEBACKUP_E_INVALID_ARG     = -1,
	MOBILEBACKUP_E_PLIST_ERROR     = -2,
	MOBILEBACKUP_E_MUX_ERROR       = -3,
	MOBILEBACKUP_E_SSL_ERROR       = -4,
	MOBILEBACKUP_E_RECEIVE_TIMEOUT = -5,
	MOBILEBACKUP_E_BAD_VERSION     = -6,
	MOBILEBACKUP_E_REPLY_NOT_OK    = -7,
	MOBILEBACKUP_E_UNKNOWN_ERROR   = -256
} mobilebackup_error_t;

typedef struct mobilebackup_client_private mobilebackup_client_private;
typedef mobilebackup_client_private *mobilebackup_client_t; /**< The client handle. */

typedef enum {
	MB_RESTORE_NOTIFY_SPRINGBOARD = 1 << 0,
	MB_RESTORE_PRESERVE_SETTINGS = 1 << 1,
	MB_RESTORE_PRESERVE_CAMERA_ROLL = 1 << 2
} mobilebackup_flags_t;

/**
 * Connects to the mobilebackup service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated
 *     mobilebackup_client_t upon successful return.
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, MOBILEBACKUP_E_INVALID ARG if one
 *     or more parameters are invalid, or DEVICE_LINK_SERVICE_E_BAD_VERSION if
 *     the mobilebackup version on the device is newer.
 */
mobilebackup_error_t mobilebackup_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobilebackup_client_t * client);

/**
 * Starts a new mobilebackup service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     mobilebackup_client_t upon successful return. Must be freed using
 *     mobilebackup_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, or an MOBILEBACKUP_E_* error
 *     code otherwise.
 */
mobilebackup_error_t mobilebackup_client_start_service(idevice_t device, mobilebackup_client_t* client, const char* label);

/**
 * Disconnects a mobilebackup client from the device and frees up the
 * mobilebackup client data.
 *
 * @param client The mobilebackup client to disconnect and free.
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, or MOBILEBACKUP_E_INVALID_ARG
 *     if client is NULL.
 */
mobilebackup_error_t mobilebackup_client_free(mobilebackup_client_t client);


/**
 * Polls the device for mobilebackup data.
 *
 * @param client The mobilebackup client
 * @param plist A pointer to the location where the plist should be stored
 *
 * @return an error code
 */
mobilebackup_error_t mobilebackup_receive(mobilebackup_client_t client, plist_t *plist);

/**
 * Sends mobilebackup data to the device
 *
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The mobilebackup client
 * @param plist The location of the plist to send
 *
 * @return an error code
 */
mobilebackup_error_t mobilebackup_send(mobilebackup_client_t client, plist_t plist);

/**
 * Request a backup from the connected device.
 *
 * @param client The connected MobileBackup client to use.
 * @param backup_manifest The backup manifest, a plist_t of type PLIST_DICT
 *    containing the backup state of the last backup. For a first-time backup
 *    set this parameter to NULL.
 * @param base_path The base path on the device to use for the backup
 *    operation, usually "/".
 * @param proto_version A string denoting the version of the backup protocol
 *    to use. Latest known version is "1.6"
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, MOBILEBACKUP_E_INVALID_ARG if
 *    one of the parameters is invalid, MOBILEBACKUP_E_PLIST_ERROR if
 *    backup_manifest is not of type PLIST_DICT, MOBILEBACKUP_E_MUX_ERROR
 *    if a communication error occurs, MOBILEBACKUP_E_REPLY_NOT_OK
 */
mobilebackup_error_t mobilebackup_request_backup(mobilebackup_client_t client, plist_t backup_manifest, const char *base_path, const char *proto_version);

/**
 * Sends a confirmation to the device that a backup file has been received.
 *
 * @param client The connected MobileBackup client to use.
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, MOBILEBACKUP_E_INVALID_ARG if
 *    client is invalid, or MOBILEBACKUP_E_MUX_ERROR if a communication error
 *    occurs.
 */
mobilebackup_error_t mobilebackup_send_backup_file_received(mobilebackup_client_t client);

/**
 * Request that a backup should be restored to the connected device.
 *
 * @param client The connected MobileBackup client to use.
 * @param backup_manifest The backup manifest, a plist_t of type PLIST_DICT
 *    containing the backup state to be restored.
 * @param flags Flags to send with the request. Currently this is a combination
 *    of the following mobilebackup_flags_t:
 *    MB_RESTORE_NOTIFY_SPRINGBOARD - let SpringBoard show a 'Restore' screen
 *    MB_RESTORE_PRESERVE_SETTINGS - do not overwrite any settings
 *    MB_RESTORE_PRESERVE_CAMERA_ROLL - preserve the photos of the camera roll
 * @param proto_version A string denoting the version of the backup protocol
 *    to use. Latest known version is "1.6". Ideally this value should be
 *    extracted from the given manifest plist.
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, MOBILEBACKUP_E_INVALID_ARG if
 *    one of the parameters is invalid, MOBILEBACKUP_E_PLIST_ERROR if
 *    backup_manifest is not of type PLIST_DICT, MOBILEBACKUP_E_MUX_ERROR
 *    if a communication error occurs, or MOBILEBACKUP_E_REPLY_NOT_OK
 *    if the device did not accept the request.
 */
mobilebackup_error_t mobilebackup_request_restore(mobilebackup_client_t client, plist_t backup_manifest, mobilebackup_flags_t flags, const char *proto_version);

/**
 * Receive a confirmation from the device that it successfully received
 * a restore file.
 *
 * @param client The connected MobileBackup client to use.
 * @param result Pointer to a plist_t that will be set to the received plist
 *    for further processing. The caller has to free it using plist_free().
 *    Note that it will be set to NULL if the operation itself fails due to
 *    a communication or plist error.
 *    If this parameter is NULL, it will be ignored.
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, MOBILEBACKUP_E_INVALID_ARG if
 *    client is invalid, MOBILEBACKUP_E_REPLY_NOT_OK if the expected
 *    'BackupMessageRestoreFileReceived' message could not be received,
 *    MOBILEBACKUP_E_PLIST_ERROR if the received message is not a valid backup
 *    message plist, or MOBILEBACKUP_E_MUX_ERROR if a communication error
 *    occurs.
 */
mobilebackup_error_t mobilebackup_receive_restore_file_received(mobilebackup_client_t client, plist_t *result);

/**
 * Receive a confirmation from the device that it successfully received
 * application data file.
 *
 * @param client The connected MobileBackup client to use.
 * @param result Pointer to a plist_t that will be set to the received plist
 *    for further processing. The caller has to free it using plist_free().
 *    Note that it will be set to NULL if the operation itself fails due to
 *    a communication or plist error.
 *    If this parameter is NULL, it will be ignored.
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, MOBILEBACKUP_E_INVALID_ARG if
 *    client is invalid, MOBILEBACKUP_E_REPLY_NOT_OK if the expected
 *    'BackupMessageRestoreApplicationReceived' message could not be received,
 *    MOBILEBACKUP_E_PLIST_ERROR if the received message is not a valid backup
 *    message plist, or MOBILEBACKUP_E_MUX_ERROR if a communication error
 *    occurs.
 */
mobilebackup_error_t mobilebackup_receive_restore_application_received(mobilebackup_client_t client, plist_t *result);

/**
 * Tells the device that the restore process is complete and waits for the
 * device to close the connection. After that, the device should reboot.
 *
 * @param client The connected MobileBackup client to use.
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, MOBILEBACKUP_E_INVALID_ARG if
 *    client is invalid, MOBILEBACKUP_E_PLIST_ERROR if the received disconnect
 *    message plist is invalid, or MOBILEBACKUP_E_MUX_ERROR if a communication
 *    error occurs.
 */
mobilebackup_error_t mobilebackup_send_restore_complete(mobilebackup_client_t client);

/**
 * Sends a backup error message to the device.
 *
 * @param client The connected MobileBackup client to use.
 * @param reason A string describing the reason for the error message.
 *
 * @return MOBILEBACKUP_E_SUCCESS on success, MOBILEBACKUP_E_INVALID_ARG if
 *    one of the parameters is invalid, or MOBILEBACKUP_E_MUX_ERROR if a
 *    communication error occurs.
 */
mobilebackup_error_t mobilebackup_send_error(mobilebackup_client_t client, const char *reason);

#ifdef __cplusplus
}
#endif

#endif
