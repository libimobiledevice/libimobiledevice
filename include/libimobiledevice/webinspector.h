/**
 * @file libimobiledevice/webinspector.h
 * @brief WebKit Remote Debugging.
 * \internal
 *
 * Copyright (c) 2013-2014 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2013 Yury Melnichek All Rights Reserved.
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

#ifndef IWEBINSPECTOR_H
#define IWEBINSPECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define WEBINSPECTOR_SERVICE_NAME "com.apple.webinspector"

/** Error Codes */
typedef enum {
	WEBINSPECTOR_E_SUCCESS       =  0,
	WEBINSPECTOR_E_INVALID_ARG   = -1,
	WEBINSPECTOR_E_PLIST_ERROR   = -2,
	WEBINSPECTOR_E_MUX_ERROR     = -3,
	WEBINSPECTOR_E_SSL_ERROR     = -4,
	WEBINSPECTOR_E_UNKNOWN_ERROR = -256
} webinspector_error_t;

typedef struct webinspector_client_private webinspector_client_private;
typedef webinspector_client_private *webinspector_client_t; /**< The client handle. */


/**
 * Connects to the webinspector service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     webinspector_client_t upon successful return. Must be freed using
 *     webinspector_client_free() after use.
 *
 * @return WEBINSPECTOR_E_SUCCESS on success, WEBINSPECTOR_E_INVALID_ARG when
 *     client is NULL, or an WEBINSPECTOR_E_* error code otherwise.
 */
webinspector_error_t webinspector_client_new(idevice_t device, lockdownd_service_descriptor_t service, webinspector_client_t * client);

/**
 * Starts a new webinspector service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     webinspector_client_t upon successful return. Must be freed using
 *     webinspector_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return WEBINSPECTOR_E_SUCCESS on success, or an WEBINSPECTOR_E_* error
 *     code otherwise.
 */
webinspector_error_t webinspector_client_start_service(idevice_t device, webinspector_client_t * client, const char* label);

/**
 * Disconnects a webinspector client from the device and frees up the
 * webinspector client data.
 *
 * @param client The webinspector client to disconnect and free.
 *
 * @return WEBINSPECTOR_E_SUCCESS on success, WEBINSPECTOR_E_INVALID_ARG when
 *     client is NULL, or an WEBINSPECTOR_E_* error code otherwise.
 */
webinspector_error_t webinspector_client_free(webinspector_client_t client);


/**
 * Sends a plist to the service.
 *
 * @param client The webinspector client
 * @param plist The plist to send
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client or plist is NULL
 */
webinspector_error_t webinspector_send(webinspector_client_t client, plist_t plist);

/**
 * Receives a plist from the service.
 *
 * @param client The webinspector client
 * @param plist The plist to store the received data
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client or plist is NULL
 */
webinspector_error_t webinspector_receive(webinspector_client_t client, plist_t * plist);

/**
 * Receives a plist using the given webinspector client.
 *
 * @param client The webinspector client to use for receiving
 * @param plist pointer to a plist_t that will point to the received plist
 *      upon successful return
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return WEBINSPECTOR_E_SUCCESS on success,
 *      WEBINSPECTOR_E_INVALID_ARG when client or *plist is NULL,
 *      WEBINSPECTOR_E_PLIST_ERROR when the received data cannot be
 *      converted to a plist, WEBINSPECTOR_E_MUX_ERROR when a
 *      communication error occurs, or WEBINSPECTOR_E_UNKNOWN_ERROR
 *      when an unspecified error occurs.
 */
webinspector_error_t webinspector_receive_with_timeout(webinspector_client_t client, plist_t * plist, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
