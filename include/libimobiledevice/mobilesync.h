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

#define MOBILESYNC_SERVICE_NAME "com.apple.mobilesync"

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
mobilesync_error_t mobilesync_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobilesync_client_t * client);

/**
 * Starts a new mobilesync service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     mobilesync_client_t upon successful return. Must be freed using
 *     mobilesync_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return MOBILESYNC_E_SUCCESS on success, or an MOBILESYNC_E_* error
 *     code otherwise.
 */
mobilesync_error_t mobilesync_client_start_service(idevice_t device, mobilesync_client_t* client, const char* label);

/**
 * Disconnects a mobilesync client from the device and frees up the
 * mobilesync client data.
 *
 * @param client The mobilesync client to disconnect and free.
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if \a client is NULL.
 */
mobilesync_error_t mobilesync_client_free(mobilesync_client_t client);


/**
 * Polls the device for mobilesync data.
 *
 * @param client The mobilesync client
 * @param plist A pointer to the location where the plist should be stored
 *
 * @return an error code
 */
mobilesync_error_t mobilesync_receive(mobilesync_client_t client, plist_t *plist);

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
mobilesync_error_t mobilesync_send(mobilesync_client_t client, plist_t plist);


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
mobilesync_error_t mobilesync_start(mobilesync_client_t client, const char *data_class, mobilesync_anchors_t anchors, uint64_t computer_data_class_version, mobilesync_sync_type_t *sync_type, uint64_t *device_data_class_version, char** error_description);

/**
 * Cancels a running synchronization session with a device at any time.
 *
 * @param client The mobilesync client
 * @param reason The reason to supply to the device for cancelling
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 */
mobilesync_error_t mobilesync_cancel(mobilesync_client_t client, const char* reason);

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
mobilesync_error_t mobilesync_finish(mobilesync_client_t client);


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
mobilesync_error_t mobilesync_get_all_records_from_device(mobilesync_client_t client);

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
mobilesync_error_t mobilesync_get_changes_from_device(mobilesync_client_t client);

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
mobilesync_error_t mobilesync_clear_all_records_on_device(mobilesync_client_t client);


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
mobilesync_error_t mobilesync_receive_changes(mobilesync_client_t client, plist_t *entities, uint8_t *is_last_record, plist_t *actions);

/**
 * Acknowledges to the device that the changes have been merged on the computer
 *
 * @param client The mobilesync client
 *
 * @retval MOBILESYNC_E_SUCCESS on success
 * @retval MOBILESYNC_E_INVALID_ARG if one of the parameters is invalid
 */
mobilesync_error_t mobilesync_acknowledge_changes_from_device(mobilesync_client_t client);


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
mobilesync_error_t mobilesync_ready_to_send_changes_from_computer(mobilesync_client_t client);


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
mobilesync_error_t mobilesync_send_changes(mobilesync_client_t client, plist_t entities, uint8_t is_last_record, plist_t actions);

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
mobilesync_error_t mobilesync_remap_identifiers(mobilesync_client_t client, plist_t *mapping);

/* Helper */

/**
 * Allocates memory for a new anchors struct initialized with the passed anchors.
 *
 * @param device_anchor An anchor the device reported the last time or NULL
 *   if none is known yet which for instance is true on first synchronization.
 * @param computer_anchor An arbitrary string to use as anchor for the computer.
 *
 * @return A new #mobilesync_anchors_t struct. Must be freed using mobilesync_anchors_free().
 */
mobilesync_anchors_t mobilesync_anchors_new(const char *device_anchor, const char *computer_anchor);

/**
 * Free memory used by anchors.
 *
 * @param anchors The anchors to free.
 */
void mobilesync_anchors_free(mobilesync_anchors_t anchors);


/**
 * Create a new actions plist to use in mobilesync_send_changes().
 *
 * @return A new plist_t of type PLIST_DICT.
 */
plist_t mobilesync_actions_new();

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
void mobilesync_actions_add(plist_t actions, ...);

/**
 * Free actions plist.
 *
 * @param actions The actions plist to free. Does nothing if NULL is passed.
 */
void mobilesync_actions_free(plist_t actions);

#ifdef __cplusplus
}
#endif

#endif
