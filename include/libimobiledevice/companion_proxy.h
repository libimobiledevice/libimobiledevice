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

#define COMPPROXY_SERVICE_NAME "com.apple.companion_proxy"

/** Error Codes */
typedef enum {
	COMPPROXY_E_SUCCESS         =  0,
	COMPPROXY_E_INVALID_ARG     = -1,
	COMPPROXY_E_PLIST_ERROR     = -2,
	COMPPROXY_E_MUX_ERROR       = -3,
	COMPPROXY_E_SSL_ERROR       = -4,
	COMPPROXY_E_NOT_ENOUGH_DATA = -5,
	COMPPROXY_E_TIMEOUT         = -6,
	COMPPROXY_E_OP_IN_PROGRESS  = -7,
	COMPPROXY_E_NO_DEVICES      = -100,
	COMPPROXY_E_UNSUPPORTED_KEY = -101,
	COMPPROXY_E_TIMEOUT_REPLY   = -102,
	COMPPROXY_E_UNKNOWN_ERROR   = -256
} compproxy_error_t;

typedef struct compproxy_client_private compproxy_client_private;
typedef compproxy_client_private *compproxy_client_t; /**< The client handle. */

typedef void (*compproxy_device_event_cb_t) (plist_t event, void* userdata);

/**
 * Connects to the compproxy service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     compproxy_client_t upon successful return. Must be freed using
 *     compproxy_client_free() after use.
 *
 * @return COMPPROXY_E_SUCCESS on success, COMPPROXY_E_INVALID_ARG when
 *     the arguments are invalid, or an COMPPROXY_E_* error code otherwise.
 */
compproxy_error_t compproxy_client_new(idevice_t device, lockdownd_service_descriptor_t service, compproxy_client_t* client);

/**
 * Starts a new compproxy service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     compproxy_client_t upon successful return. Must be freed using
 *     compproxy_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return COMPPROXY_E_SUCCESS on success, or an COMPPROXY_E_* error
 *     code otherwise.
 */
compproxy_error_t compproxy_client_start_service(idevice_t device, compproxy_client_t* client, const char* label);

/**
 * Disconnects a compproxy client from the device and frees up the
 * compproxy client data.
 *
 * @param client The compproxy client to disconnect and free.
 *
 * @return COMPPROXY_E_SUCCESS on success, COMPPROXY_E_INVALID_ARG when
 *     client is NULL, or an COMPPROXY_E_* error code otherwise.
 */
compproxy_error_t compproxy_client_free(compproxy_client_t client);

/**
 * Sends a plist to the service.
 *
 * @param client The compproxy client
 * @param plist The plist to send
 *
 * @return COMPPROXY_E_SUCCESS on success,
 *  COMPPROXY_E_INVALID_ARG when client or plist is NULL
 */
compproxy_error_t compproxy_send(compproxy_client_t client, plist_t plist);

/**
 * Receives a plist from the service.
 *
 * @param client The compproxy client
 * @param plist The plist to store the received data
 *
 * @return COMPPROXY_E_SUCCESS on success,
 *  COMPPROXY_E_INVALID_ARG when client or plist is NULL
 */
compproxy_error_t compproxy_receive(compproxy_client_t client, plist_t * plist);

/**
 * Retrieves a list of paired devices.
 *
 * @param client The compproxy client
 * @param devices Point that will receive a PLIST_ARRAY with paired device UDIDs
 *
 * @note The device closes the connection after sending the reply.
 *
 * @return COMPPROXY_E_SUCCESS on success,
 *  COMPPROXY_E_NO_DEVICES if no devices are paired,
 *  or a COMPPROXY_E_* error code otherwise.
 */
compproxy_error_t compproxy_get_device_registry(compproxy_client_t client, plist_t* paired_devices);

/**
 * Starts listening for paired devices.
 *
 * @param client The compproxy client
 * @param callback Callback function that will be called when a new device is detected
 * @param userdata Pointer that that will be passed to the callback function
 *
 * @note The event parameter that gets passed to the callback function is
 *  freed internally after returning from the callback. The consumer needs
 *  to make a copy if required.
 *
 * @return COMPPROXY_E_SUCCESS on success,
 *  or a COMPPROXY_E_* error code otherwise.
 */
compproxy_error_t compproxy_start_listening_for_devices(compproxy_client_t client, compproxy_device_event_cb_t callback, void* userdata);

/**
 * Stops listening for paired devices
 *
 * @param client The compproxy client
 *
 * @return COMPPROXY_E_SUCCESS on success,
 *  or a COMPPROXY_E_* error code otherwise.
 */
compproxy_error_t compproxy_stop_listening_for_devices(compproxy_client_t client);

/**
 * Returns a value for the given key.
 *
 * @param client The compproxy client
 * @param companion_udid UDID of the (paired) watch
 * @param key The key to retrieve the value for
 *
 * @note The device closes the connection after sending the reply.
 *
 * @return COMPPROXY_E_SUCCESS on success,
 *  COMPPROXY_E_INVALID_ARG when client or paired_devices is invalid,
 *  COMPPROXY_E_UNSUPPORTED_KEY if the watch doesn't support the given key,
 *  or a COMPPROXY_E_* error code otherwise.
 */
compproxy_error_t compproxy_get_value_from_registry(compproxy_client_t client, const char* companion_udid, const char* key, plist_t* value);

/**
 * Start forwarding a service port on the watch to a port on the idevice.
 *
 * @see compproxy_stop_forwarding_service_port
 *
 * @param client The compproxy client
 * @param remote_port remote port
 * @param service_name The name of the service that shall be forwarded
 * @param forward_port Pointer that will receive the newly-assigned port accessible via USB/Network on the idevice
 * @param options PLIST_DICT with additional options. Currently known are
 *    IsServiceLowPriority (boolean) and PreferWifi (boolean).
 *
 * @return COMPPROXY_E_SUCCESS on success,
 *  or a COMPPROXY_E_* error code otherwise.
 */
compproxy_error_t compproxy_start_forwarding_service_port(compproxy_client_t client, uint16_t remote_port, const char* service_name, uint16_t* forward_port, plist_t options);

/**
 * Stop forwarding a service port between watch and idevice.
 *
 * @see compproxy_start_forwarding_service_port
 *
 * @param client The compproxy client
 * @param remote_port remote port
 *
 * @return COMPPROXY_E_SUCCESS on success,
 *  or a COMPPROXY_E_* error code otherwise.
 */
compproxy_error_t compproxy_stop_forwarding_service_port(compproxy_client_t client, uint16_t remote_port);

#ifdef __cplusplus
}
#endif

#endif
