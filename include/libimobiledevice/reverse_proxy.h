/**
 * @file libimobiledevice/reverse_proxy.h
 * @brief Provide a reverse proxy to allow the device to communicate through,
 *     which is used during firmware restore.
 * \internal
 *
 * Copyright (c) 2021 Nikias Bassen, All Rights Reserved.
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

#ifndef IREVERSE_PROXY_H
#define IREVERSE_PROXY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>

#define REVERSE_PROXY_DEFAULT_PORT 1082 /**< default port the reverse proxy is listening on */

/** Error Codes */
typedef enum {
	REVERSE_PROXY_E_SUCCESS         =  0,
	REVERSE_PROXY_E_INVALID_ARG     = -1,
	REVERSE_PROXY_E_PLIST_ERROR     = -2,
	REVERSE_PROXY_E_MUX_ERROR       = -3,
	REVERSE_PROXY_E_SSL_ERROR       = -4,
	REVERSE_PROXY_E_NOT_ENOUGH_DATA = -5,
	REVERSE_PROXY_E_TIMEOUT         = -6,
	REVERSE_PROXY_E_UNKNOWN_ERROR   = -256
} reverse_proxy_error_t;

typedef struct reverse_proxy_client_private reverse_proxy_client_private; /**< \private */
typedef reverse_proxy_client_private *reverse_proxy_client_t; /**< The client handle. */

/** reverse proxy client type */
typedef enum {
	RP_TYPE_CTRL = 1, /**< control connection */
	RP_TYPE_CONN      /**< proxy connection */
} reverse_proxy_client_type_t;

/** reverse proxy status for reverse_proxy_status_cb_t callback */
typedef enum {
	RP_STATUS_READY = 1,    /**< proxy is ready */
	RP_STATUS_TERMINATE,    /**< proxy terminated */
	RP_STATUS_CONNECT_REQ,  /**< connection request received (only RP_TYPE_CTRL) */
	RP_STATUS_SHUTDOWN_REQ, /**< shutdown request received (only RP_TYPE_CTRL) */
	RP_STATUS_CONNECTED,    /**< connection established (only RP_TYPE_CONN) */
	RP_STATUS_DISCONNECTED, /**< connection closed (only RP_TYPE_CONN) */
} reverse_proxy_status_t;

/** reverse proxy data direction passed to reverse_proxy_data_cb_t callback */
typedef enum {
	RP_DATA_DIRECTION_OUT = 1, /**< data going out to remote host */
	RP_DATA_DIRECTION_IN       /**< data coming in from remote host */
} reverse_proxy_data_direction_t;

/**
 * Log callback function prototype.
 *
 * @param client The client that called the callback function
 * @param log_msg The log message
 * @param user_data The user_data pointer that was set when registering the callback
 */
typedef void (*reverse_proxy_log_cb_t) (reverse_proxy_client_t client, const char* log_msg, void* user_data);

/**
 * Data callback function prototype.
 *
 * @param client The client that called the callback function
 * @param direction The direction of the data, either RP_DATA_DIRECTION_OUT or RP_DATA_DIRECTION_IN
 * @param buffer The data buffer
 * @param length The length of the data buffer
 * @param user_data The user_data pointer that was set when registering the callback
 */
typedef void (*reverse_proxy_data_cb_t) (reverse_proxy_client_t client, reverse_proxy_data_direction_t direction, const char* buffer, uint32_t length, void* user_data);

/**
 * Status callback function prototype.
 *
 * @param client The client that called the callback function
 * @param status The status the client is reporting
 * @param status_msg A status message the client reports along with the status
 * @param user_data The user_data pointer that was set when registering the callback
 */
typedef void (*reverse_proxy_status_cb_t) (reverse_proxy_client_t client, reverse_proxy_status_t status, const char* status_msg, void* user_data);

/**
 * Create a reverse proxy client using com.apple.PurpleReverseProxy.Ctrl and
 * com.apple.PurpleReverseProxy.Conn lockdown services. This will open a port
 * 1083 on the device that iOS apps could connect to; \b however that is
 * only allowed if an app has the com.apple.private.PurpleReverseProxy.allowed
 * entitlement, which currently only \c /usr/libexec/fdrhelper holds.
 *
 * @note This function only creates and initializes the reverse proxy;
 *    to make it operational, call reverse_proxy_client_start_proxy().
 *
 * @param device The device to connect to.
 * @param client Pointer that will be set to a newly allocated #reverse_proxy_client_t
 *    upon successful return.
 * @param label A label to pass to lockdownd when creating the service
 *    connections, usually the program name.
 *
 * @return REVERSE_PROXY_E_SUCCESS on success,
 *    or a REVERSE_PROXY_E_* error code otherwise.
 */
reverse_proxy_error_t reverse_proxy_client_create_with_service(idevice_t device, reverse_proxy_client_t* client, const char* label);

/**
 * Create a reverse proxy client using an open port on the device. This is
 * used during firmware restores with the default port REVERSE_PROXY_DEFAULT_PORT (1082).
 *
 * @note This function only creates and initializes the reverse proxy;
 *    to make it operational, call reverse_proxy_client_start_proxy().
 *
 * @param device The device to connect to.
 * @param client Pointer that will be set to a newly allocated reverse_proxy_client_t
 *    upon successful return.
 * @param device_port An open port on the device. Unless it's being used for
 *    a custom implementation, pass REVERSE_PROXY_DEFAULT_PORT here.
 *
 * @return REVERSE_PROXY_E_SUCCESS on success,
 *    or a REVERSE_PROXY_E_* error code otherwise.
 */
reverse_proxy_error_t reverse_proxy_client_create_with_port(idevice_t device, reverse_proxy_client_t* client, uint16_t device_port);

/**
 * Disconnects a reverse proxy client and frees up the client data.
 *
 * @param client The reverse proxy client to disconnect and free.
 */
reverse_proxy_error_t reverse_proxy_client_free(reverse_proxy_client_t client);

/**
 * Make an initialized reverse proxy client operational, i.e. start the actual proxy.
 *
 * @param client The reverse proxy client to start.
 * @param control_protocol_version The control protocol version to use.
 *    This is either 1 or 2. Recent devices use 2.
 *
 * @return REVERSE_PROXY_E_SUCCESS on success,
 *    or a REVERSE_PROXY_E_* error code otherwise.
 */
reverse_proxy_error_t reverse_proxy_client_start_proxy(reverse_proxy_client_t client, int control_protocol_version);

/**
 * Set a status callback function. This allows to report the status of the
 * reverse proxy, like Ready, Connect Request, Connected, etc.
 *
 * @note Set the callback before calling reverse_proxy_client_start_proxy().
 *
 * @param client The reverse proxy client
 * @param callback The status callback function that will be called
 *    when the status of the reverse proxy changes.
 * @param user_data A pointer that will be passed to the callback function.
 */
void reverse_proxy_client_set_status_callback(reverse_proxy_client_t client, reverse_proxy_status_cb_t callback, void* user_data);

/**
 * Set a log callback function. Useful for debugging or verbosity.
 *
 * @note Set the callback before calling reverse_proxy_client_start_proxy().
 *
 * @param client The reverse proxy client
 * @param callback The log callback function that will be called
 *    when the reverse proxy logs something.
 * @param user_data A pointer that will be passed to the callback function.
 */
void reverse_proxy_client_set_log_callback(reverse_proxy_client_t client, reverse_proxy_log_cb_t callback, void* user_data);

/**
 * Set a data callback function. Useful for debugging or extra verbosity.
 *
 * @note Set the callback before calling reverse_proxy_client_start_proxy().
 *
 * @param client The reverse proxy client
 * @param callback The status callback function that will be called
 *    when the status of the reverse proxy changes.
 * @param user_data A pointer that will be passed to the callback function.
 */

void reverse_proxy_client_set_data_callback(reverse_proxy_client_t client, reverse_proxy_data_cb_t callback, void* user_data);

/**
 * Helper function to return the type of a given reverse proxy client, which
 * is either RP_TYPE_CTRL or RP_TYPE_CONN. Useful for callback functions.
 * @see reverse_proxy_client_type_t
 *
 * @param client The reverse proxy client
 *
 * @return The type of the rerverse proxy client
 */
reverse_proxy_client_type_t reverse_proxy_get_type(reverse_proxy_client_t client);

#ifdef __cplusplus
}
#endif

#endif
