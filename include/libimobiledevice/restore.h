/**
 * @file libimobiledevice/restore.h
 * @brief Initiate restore process or reboot device.
 * @note This service is only available if the device is in restore mode.
 * \internal
 *
 * Copyright (c) 2010-2014 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2010 Joshua Hill. All Rights Reserved.
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

#ifndef IRESTORE_H
#define IRESTORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>

/** Error Codes */
typedef enum {
	RESTORE_E_SUCCESS              =  0,
	RESTORE_E_INVALID_ARG          = -1,
	RESTORE_E_INVALID_CONF         = -2,
	RESTORE_E_PLIST_ERROR          = -3,
	RESTORE_E_DICT_ERROR           = -4,
	RESTORE_E_NOT_ENOUGH_DATA      = -5,
	RESTORE_E_MUX_ERROR            = -6,
	RESTORE_E_START_RESTORE_FAILED = -7,
	RESTORE_E_DEVICE_ERROR         = -8,
	RESTORE_E_UNKNOWN_ERROR        = -256
} restored_error_t;

typedef struct restored_client_private restored_client_private;
typedef restored_client_private *restored_client_t; /**< The client handle. */

/* Interface */

/**
 * Creates a new restored client for the device.
 *
 * @param device The device to create a restored client for
 * @param client The pointer to the location of the new restored_client
 * @param label The label to use for communication. Usually the program name.
 *
 * @return RESTORE_E_SUCCESS on success, RESTORE_E_INVALID_ARG when client is NULL
 */
restored_error_t restored_client_new(idevice_t device, restored_client_t *client, const char *label);

/**
 * Closes the restored client session if one is running and frees up the
 * restored_client struct.
 *
 * @param client The restore client
 *
 * @return RESTORE_E_SUCCESS on success, RESTORE_E_INVALID_ARG when client is NULL
 */
restored_error_t restored_client_free(restored_client_t client);


/**
 * Query the type of the service daemon. Depending on whether the device is
 * queried in normal mode or restore mode, different types will be returned.
 *
 * @param client The restored client
 * @param type The type returned by the service daemon. Pass NULL to ignore.
 * @param version The restore protocol version. Pass NULL to ignore.
 *
 * @return RESTORE_E_SUCCESS on success, RESTORE_E_INVALID_ARG when client is NULL
 */
restored_error_t restored_query_type(restored_client_t client, char **type, uint64_t *version);

/**
 * Queries a value from the device specified by a key.
 *
 * @param client An initialized restored client.
 * @param key The key name to request
 * @param value A plist node representing the result value node
 *
 * @return RESTORE_E_SUCCESS on success, RESTORE_E_INVALID_ARG when client is NULL, RESTORE_E_PLIST_ERROR if value for key can't be found
 */
restored_error_t restored_query_value(restored_client_t client, const char *key, plist_t *value);

/**
 * Retrieves a value from information plist specified by a key.
 *
 * @param client An initialized restored client.
 * @param key The key name to request or NULL to query for all keys
 * @param value A plist node representing the result value node
 *
 * @return RESTORE_E_SUCCESS on success, RESTORE_E_INVALID_ARG when client is NULL, RESTORE_E_PLIST_ERROR if value for key can't be found
 */
restored_error_t restored_get_value(restored_client_t client, const char *key, plist_t *value) ;

/**
 * Sends a plist to restored.
 *
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The restored client
 * @param plist The plist to send
 *
 * @return RESTORE_E_SUCCESS on success, RESTORE_E_INVALID_ARG when client or
 *  plist is NULL
 */
restored_error_t restored_send(restored_client_t client, plist_t plist);

/**
 * Receives a plist from restored.
 *
 * @param client The restored client
 * @param plist The plist to store the received data
 *
 * @return RESTORE_E_SUCCESS on success, RESTORE_E_INVALID_ARG when client or
 *  plist is NULL
 */
restored_error_t restored_receive(restored_client_t client, plist_t *plist);

/**
 * Sends the Goodbye request to restored signaling the end of communication.
 *
 * @param client The restore client
 *
 * @return RESTORE_E_SUCCESS on success, RESTORE_E_INVALID_ARG when client is NULL,
 *  RESTORE_E_PLIST_ERROR if the device did not acknowledge the request
 */
restored_error_t restored_goodbye(restored_client_t client);


/**
 * Requests to start a restore and retrieve it's port on success.
 *
 * @param client The restored client
 * @param options PLIST_DICT with options for the restore process or NULL
 * @param version the restore protocol version, see restored_query_type()
 *
 * @return RESTORE_E_SUCCESS on success, RESTORE_E_INVALID_ARG if a parameter
 *  is NULL, RESTORE_E_START_RESTORE_FAILED if the request fails
 */
restored_error_t restored_start_restore(restored_client_t client, plist_t options, uint64_t version);

/**
 * Requests device to reboot.
 *
 * @param client The restored client
 *
 * @return RESTORE_E_SUCCESS on success, RESTORE_E_INVALID_ARG if a parameter
 *  is NULL
 */
restored_error_t restored_reboot(restored_client_t client);

/* Helper */

/**
 * Sets the label to send for requests to restored.
 *
 * @param client The restore client
 * @param label The label to set or NULL to disable sending a label
 *
 */
void restored_client_set_label(restored_client_t client, const char *label);

#ifdef __cplusplus
}
#endif

#endif
