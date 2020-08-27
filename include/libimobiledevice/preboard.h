/**
 * @file libimobiledevice/preboard.h
 * @brief Service to 'preboard' a device, which allows to ask for passcode during firmware updates.
 * \internal
 *
 * Copyright (c) 2019 Nikias Bassen, All Rights Reserved.
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

#ifndef IPREBOARD_H
#define IPREBOARD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define PREBOARD_SERVICE_NAME "com.apple.preboardservice_v2"

/** Error Codes */
typedef enum {
	PREBOARD_E_SUCCESS         =  0,
	PREBOARD_E_INVALID_ARG     = -1,
	PREBOARD_E_PLIST_ERROR     = -2,
	PREBOARD_E_MUX_ERROR       = -3,
	PREBOARD_E_SSL_ERROR       = -4,
	PREBOARD_E_NOT_ENOUGH_DATA = -5,
	PREBOARD_E_TIMEOUT         = -6,
	PREBOARD_E_OP_IN_PROGRESS  = -10,
	PREBOARD_E_UNKNOWN_ERROR   = -256
} preboard_error_t;

typedef struct preboard_client_private preboard_client_private;
typedef preboard_client_private *preboard_client_t; /**< The client handle. */

/** Reports the status response of the given command */
typedef void (*preboard_status_cb_t) (plist_t message, void *user_data);

/**
 * Connects to the preboard service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     preboard_client_t upon successful return. Must be freed using
 *     preboard_client_free() after use.
 *
 * @return PREBOARD_E_SUCCESS on success, PREBOARD_E_INVALID_ARG when
 *     client is NULL, or an PREBOARD_E_* error code otherwise.
 */
preboard_error_t preboard_client_new(idevice_t device, lockdownd_service_descriptor_t service, preboard_client_t * client);

/**
 * Starts a new preboard service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     preboard_client_t upon successful return. Must be freed using
 *     preboard_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return PREBOARD_E_SUCCESS on success, or a PREBOARD_E_* error
 *     code otherwise.
 */
preboard_error_t preboard_client_start_service(idevice_t device, preboard_client_t * client, const char* label);

/**
 * Disconnects a preboard client from the device and frees up the
 * preboard client data.
 *
 * @param client The preboard client to disconnect and free.
 *
 * @return PREBOARD_E_SUCCESS on success, PREBOARD_E_INVALID_ARG when
 *     client is NULL, or a PREBOARD_E_* error code otherwise.
 */
preboard_error_t preboard_client_free(preboard_client_t client);

/**
 * Sends a plist to the service.
 *
 * @param client The preboard client
 * @param plist The plist to send
 *
 * @return PREBOARD_E_SUCCESS on success,
 *  PREBOARD_E_INVALID_ARG when client or plist is NULL,
 *  or a PREBOARD_E_* error code on error
 */
preboard_error_t preboard_send(preboard_client_t client, plist_t plist);

/**
 * Receives a plist from the service.
 *
 * @param client The preboard client
 * @param plist Pointer to a plist_t what will be set to the received plist
 *
 * @return PREBOARD_E_SUCCESS on success,
 *  PREBOARD_E_INVALID_ARG when client or plist is NULL,
 *  PREBOARD_E_TIMEOUT when no data was received after 5 seconds,
 *  or a PREBOARD_E_* error code on error
 */
preboard_error_t preboard_receive(preboard_client_t client, plist_t * plist);

/**
 * Receives a plist from the service with the specified timeout.
 *
 * @param client The preboard client
 * @param plist Pointer to a plist_t what will be set to the received plist
 *
 * @return PREBOARD_E_SUCCESS on success,
 *  PREBOARD_E_INVALID_ARG when client or plist is NULL,
 *  PREBOARD_E_TIMEOUT when no data was received after the given timeout,
 *  or a PREBOARD_E_* error code on error.
 */
preboard_error_t preboard_receive_with_timeout(preboard_client_t client, plist_t * plist, uint32_t timeout_ms);

/**
 * Tells the preboard service to create a stashbag. This will make the device
 * show a passcode entry so it can generate and store a token that is later
 * used during restore.
 *
 * @param client The preboard client
 * @param manifest An optional manifest
 * @param status_cb Callback function that will receive status and error messages.
 *   Can be NULL if you want to handle receiving messages in your own code.
 * @param user_data User data for callback function or NULL.
 *
 * The callback or following preboard_receive* invocations will usually
 * receive a dictionary with:
 *     { ShowDialog: true }
 * If the user does not enter a passcode, after 2 minutes a timeout is reached
 * and the device sends a dictionary with:
 *     { Timeout: true }
 *     followed by { HideDialog: true }
 * If the user aborts the passcode entry, the device sends a dictionary:
 *     { Error: 1, ErrorString: <error string> }
 *     followed by { HideDialog: true }
 *
 * @return PREBOARD_E_SUCCESS if the command was successfully submitted,
 *  PREBOARD_E_INVALID_ARG when client is invalid,
 *  or a PREBOARD_E_* error code on error.
 */
preboard_error_t preboard_create_stashbag(preboard_client_t client, plist_t manifest, preboard_status_cb_t status_cb, void *user_data);

/**
 * Instructs the preboard service to commit a previously created stashbag.
 *
 * @param client The preboard client to use for receiving
 * @param manifest An optional manifest
 * @param status_cb Callback function that will receive status and error messages
 *   Can be NULL if you want to handle receiving messages in your own code.
 * @param user_data User data for callback function or NULL.
 *
 * The callback or following preboard_receive* invocations will usually
 * receive a dictionary with:
 *     { StashbagCommitComplete: true }
 * or in case of an error:
 *     { StashbagCommitComplete: 0, Error: 1, <optional> ErrorString: <error string> }
 *
 * @return PREBOARD_E_SUCCESS if the command was successfully submitted,
 *  PREBOARD_E_INVALID_ARG when client is invalid,
 *  or a PREBOARD_E_* error code on error.
 */
preboard_error_t preboard_commit_stashbag(preboard_client_t client, plist_t manifest, preboard_status_cb_t status_cb, void *user_data);

#ifdef __cplusplus
}
#endif

#endif
