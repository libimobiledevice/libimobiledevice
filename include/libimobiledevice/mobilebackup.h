/**
 * @file libimobiledevice/mobilebackup.h
 * @brief Backup and restore of all device data.
 * \internal
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

#ifndef IMOBILEBACKUP_H
#define IMOBILEBACKUP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** @name Error Codes */
/*@{*/
#define MOBILEBACKUP_E_SUCCESS                0
#define MOBILEBACKUP_E_INVALID_ARG           -1
#define MOBILEBACKUP_E_PLIST_ERROR           -2
#define MOBILEBACKUP_E_MUX_ERROR             -3
#define MOBILEBACKUP_E_BAD_VERSION           -4
#define MOBILEBACKUP_E_REPLY_NOT_OK          -5

#define MOBILEBACKUP_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t mobilebackup_error_t;

typedef struct mobilebackup_client_private mobilebackup_client_private;
typedef mobilebackup_client_private *mobilebackup_client_t; /**< The client handle. */

typedef enum {
	MB_RESTORE_NOTIFY_SPRINGBOARD = 1 << 0,
	MB_RESTORE_PRESERVE_SETTINGS = 1 << 1,
	MB_RESTORE_PRESERVE_CAMERA_ROLL = 1 << 2
} mobilebackup_flags_t;

mobilebackup_error_t mobilebackup_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobilebackup_client_t * client);
mobilebackup_error_t mobilebackup_client_free(mobilebackup_client_t client);
mobilebackup_error_t mobilebackup_receive(mobilebackup_client_t client, plist_t *plist);
mobilebackup_error_t mobilebackup_send(mobilebackup_client_t client, plist_t plist);
mobilebackup_error_t mobilebackup_request_backup(mobilebackup_client_t client, plist_t backup_manifest, const char *base_path, const char *proto_version);
mobilebackup_error_t mobilebackup_send_backup_file_received(mobilebackup_client_t client);
mobilebackup_error_t mobilebackup_request_restore(mobilebackup_client_t client, plist_t backup_manifest, mobilebackup_flags_t flags, const char *proto_version);
mobilebackup_error_t mobilebackup_receive_restore_file_received(mobilebackup_client_t client, plist_t *result);
mobilebackup_error_t mobilebackup_receive_restore_application_received(mobilebackup_client_t client, plist_t *result);
mobilebackup_error_t mobilebackup_send_restore_complete(mobilebackup_client_t client);
mobilebackup_error_t mobilebackup_send_error(mobilebackup_client_t client, const char *reason);

#ifdef __cplusplus
}
#endif

#endif
