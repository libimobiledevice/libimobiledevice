/**
 * @file libimobiledevice/mobilesync.h
 * @brief Synchronize data classes with a device and computer.
 * \internal
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

#ifndef IMOBILESYNC_H
#define IMOBILESYNC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** @name Error Codes */
/*@{*/
#define MOBILESYNC_E_SUCCESS                0
#define MOBILESYNC_E_INVALID_ARG           -1
#define MOBILESYNC_E_PLIST_ERROR           -2
#define MOBILESYNC_E_MUX_ERROR             -3
#define MOBILESYNC_E_BAD_VERSION           -4
#define MOBILESYNC_E_SYNC_REFUSED          -5
#define MOBILESYNC_E_CANCELLED             -6
#define MOBILESYNC_E_WRONG_DIRECTION       -7
#define MOBILESYNC_E_NOT_READY             -8

#define MOBILESYNC_E_UNKNOWN_ERROR       -256
/*@}*/

/** The sync type of the current sync session. */
typedef enum {
	MOBILESYNC_SYNC_TYPE_FAST, /**< Fast-sync requires that only the changes made since the last synchronization should be reported by the computer. */
	MOBILESYNC_SYNC_TYPE_SLOW, /**< Slow-sync requires that all data from the computer needs to be synchronized/sent. */
	MOBILESYNC_SYNC_TYPE_RESET /**< Reset-sync signals that the computer should send all data again. */
} mobilesync_sync_type_t;

/** Represents an error code. */
typedef int16_t mobilesync_error_t;

typedef struct mobilesync_client_private mobilesync_client_private;
typedef mobilesync_client_private *mobilesync_client_t; /**< The client handle */

typedef struct {
	char *device_anchor;
	char *computer_anchor;
} mobilesync_anchors;
typedef mobilesync_anchors *mobilesync_anchors_t; /**< Anchors used by the device and computer. */

/* Interface */
mobilesync_error_t mobilesync_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobilesync_client_t * client);
mobilesync_error_t mobilesync_client_free(mobilesync_client_t client);

mobilesync_error_t mobilesync_receive(mobilesync_client_t client, plist_t *plist);
mobilesync_error_t mobilesync_send(mobilesync_client_t client, plist_t plist);

mobilesync_error_t mobilesync_start(mobilesync_client_t client, const char *data_class, mobilesync_anchors_t anchors, uint64_t computer_data_class_version, mobilesync_sync_type_t *sync_type, uint64_t *device_data_class_version, char** error_description);
mobilesync_error_t mobilesync_cancel(mobilesync_client_t client, const char* reason);
mobilesync_error_t mobilesync_finish(mobilesync_client_t client);

mobilesync_error_t mobilesync_get_all_records_from_device(mobilesync_client_t client);
mobilesync_error_t mobilesync_get_changes_from_device(mobilesync_client_t client);
mobilesync_error_t mobilesync_clear_all_records_on_device(mobilesync_client_t client);

mobilesync_error_t mobilesync_receive_changes(mobilesync_client_t client, plist_t *entities, uint8_t *is_last_record, plist_t *actions);
mobilesync_error_t mobilesync_acknowledge_changes_from_device(mobilesync_client_t client);

mobilesync_error_t mobilesync_ready_to_send_changes_from_computer(mobilesync_client_t client);

mobilesync_error_t mobilesync_send_changes(mobilesync_client_t client, plist_t entities, uint8_t is_last_record, plist_t actions);
mobilesync_error_t mobilesync_remap_identifiers(mobilesync_client_t client, plist_t *mapping);

/* Helper */
mobilesync_anchors_t mobilesync_anchors_new(const char *device_anchor, const char *computer_anchor);
void mobilesync_anchors_free(mobilesync_anchors_t anchors);

plist_t mobilesync_actions_new();
void mobilesync_actions_add(plist_t actions, ...);
void mobilesync_actions_free(plist_t actions);

#ifdef __cplusplus
}
#endif

#endif
