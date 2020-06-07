/**
 * @file libimobiledevice/companion_proxy.h
 * @brief Companion proxy support.
 * \internal
 *
 * Copyright (c) 2019-2020 Nikias Bassen, All Rights Reserved.
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

#ifndef ICOMPANION_PROXY_H
#define ICOMPANION_PROXY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define COMPANION_PROXY_SERVICE_NAME "com.apple.companion_proxy"

/** Error Codes */
typedef enum {
	COMPANION_PROXY_E_SUCCESS         =  0,
	COMPANION_PROXY_E_INVALID_ARG     = -1,
	COMPANION_PROXY_E_PLIST_ERROR     = -2,
	COMPANION_PROXY_E_MUX_ERROR       = -3,
	COMPANION_PROXY_E_SSL_ERROR       = -4,
	COMPANION_PROXY_E_NOT_ENOUGH_DATA = -5,
	COMPANION_PROXY_E_TIMEOUT         = -6,
	COMPANION_PROXY_E_OP_IN_PROGRESS  = -7,
	COMPANION_PROXY_E_NO_DEVICES      = -100,
	COMPANION_PROXY_E_UNSUPPORTED_KEY = -101,
	COMPANION_PROXY_E_TIMEOUT_REPLY   = -102,
	COMPANION_PROXY_E_UNKNOWN_ERROR   = -256
} companion_proxy_error_t;

typedef struct companion_proxy_client_private companion_proxy_client_private;
typedef companion_proxy_client_private *companion_proxy_client_t; /**< The client handle. */

typedef void (*companion_proxy_device_event_cb_t) (plist_t event, void* userdata);

/**
 * Connects to the companion_proxy service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     companion_proxy_client_t upon successful return. Must be freed using
 *     companion_proxy_client_free() after use.
 *
 * @return COMPANION_PROXY_E_SUCCESS on success, COMPANION_PROXY_E_INVALID_ARG when
 *     the arguments are invalid, or an COMPANION_PROXY_E_* error code otherwise.
 */
companion_proxy_error_t companion_proxy_client_new(idevice_t device, lockdownd_service_descriptor_t service, companion_proxy_client_t* client);

/**
 * Starts a new companion_proxy service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     companion_proxy_client_t upon successful return. Must be freed using
 *     companion_proxy_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return COMPANION_PROXY_E_SUCCESS on success, or an COMPANION_PROXY_E_* error
 *     code otherwise.
 */
companion_proxy_error_t companion_proxy_client_start_service(idevice_t device, companion_proxy_client_t* client, const char* label);

/**
 * Disconnects a companion_proxy client from the device and frees up the
 * companion_proxy client data.
 *
 * @param client The companion_proxy client to disconnect and free.
 *
 * @return COMPANION_PROXY_E_SUCCESS on success, COMPANION_PROXY_E_INVALID_ARG when
 *     client is NULL, or an COMPANION_PROXY_E_* error code otherwise.
 */
companion_proxy_error_t companion_proxy_client_free(companion_proxy_client_t client);

/**
 * Sends a plist to the service.
 *
 * @param client The companion_proxy client
 * @param plist The plist to send
 *
 * @return COMPANION_PROXY_E_SUCCESS on success,
 *  COMPANION_PROXY_E_INVALID_ARG when client or plist is NULL
 */
companion_proxy_error_t companion_proxy_send(companion_proxy_client_t client, plist_t plist);

/**
 * Receives a plist from the service.
 *
 * @param client The companion_proxy client
 * @param plist The plist to store the received data
 *
 * @return COMPANION_PROXY_E_SUCCESS on success,
 *  COMPANION_PROXY_E_INVALID_ARG when client or plist is NULL
 */
companion_proxy_error_t companion_proxy_receive(companion_proxy_client_t client, plist_t * plist);

/**
 * Retrieves a list of paired devices.
 *
 * @param client The companion_proxy client
 * @param devices Point that will receive a PLIST_ARRAY with paired device UDIDs
 *
 * @note The device closes the connection after sending the reply.
 *
 * @return COMPANION_PROXY_E_SUCCESS on success,
 *  COMPANION_PROXY_E_NO_DEVICES if no devices are paired,
 *  or a COMPANION_PROXY_E_* error code otherwise.
 */
companion_proxy_error_t companion_proxy_get_device_registry(companion_proxy_client_t client, plist_t* paired_devices);

/**
 * Starts listening for paired devices.
 *
 * @param client The companion_proxy client
 * @param callback Callback function that will be called when a new device is detected
 * @param userdata Pointer that that will be passed to the callback function
 *
 * @note The event parameter that gets passed to the callback function is
 *  freed internally after returning from the callback. The consumer needs
 *  to make a copy if required.
 *
 * @return COMPANION_PROXY_E_SUCCESS on success,
 *  or a COMPANION_PROXY_E_* error code otherwise.
 */
companion_proxy_error_t companion_proxy_start_listening_for_devices(companion_proxy_client_t client, companion_proxy_device_event_cb_t callback, void* userdata);

/**
 * Stops listening for paired devices
 *
 * @param client The companion_proxy client
 *
 * @return COMPANION_PROXY_E_SUCCESS on success,
 *  or a COMPANION_PROXY_E_* error code otherwise.
 */
companion_proxy_error_t companion_proxy_stop_listening_for_devices(companion_proxy_client_t client);

/**
 * Returns a value for the given key.
 *
 * @param client The companion_proxy client
 * @param companion_udid UDID of the (paired) companion device
 * @param key The key to retrieve the value for
 *
 * @note The device closes the connection after sending the reply.
 *
 * @return COMPANION_PROXY_E_SUCCESS on success,
 *  COMPANION_PROXY_E_INVALID_ARG when client or paired_devices is invalid,
 *  COMPANION_PROXY_E_UNSUPPORTED_KEY if the companion device doesn't support the given key,
 *  or a COMPANION_PROXY_E_* error code otherwise.
 */
companion_proxy_error_t companion_proxy_get_value_from_registry(companion_proxy_client_t client, const char* companion_udid, const char* key, plist_t* value);

/**
 * Start forwarding a service port on the companion device to a port on the idevice.
 *
 * @see companion_proxy_stop_forwarding_service_port
 *
 * @param client The companion_proxy client
 * @param remote_port remote port
 * @param service_name The name of the service that shall be forwarded
 * @param forward_port Pointer that will receive the newly-assigned port accessible via USB/Network on the idevice
 * @param options PLIST_DICT with additional options. Currently known are
 *    IsServiceLowPriority (boolean) and PreferWifi (boolean).
 *
 * @return COMPANION_PROXY_E_SUCCESS on success,
 *  or a COMPANION_PROXY_E_* error code otherwise.
 */
companion_proxy_error_t companion_proxy_start_forwarding_service_port(companion_proxy_client_t client, uint16_t remote_port, const char* service_name, uint16_t* forward_port, plist_t options);

/**
 * Stop forwarding a service port between companion device and idevice.
 *
 * @see companion_proxy_start_forwarding_service_port
 *
 * @param client The companion_proxy client
 * @param remote_port remote port
 *
 * @return COMPANION_PROXY_E_SUCCESS on success,
 *  or a COMPANION_PROXY_E_* error code otherwise.
 */
companion_proxy_error_t companion_proxy_stop_forwarding_service_port(companion_proxy_client_t client, uint16_t remote_port);

#ifdef __cplusplus
}
#endif

#endif
