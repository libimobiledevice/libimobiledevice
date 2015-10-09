/**
 * @file libimobiledevice/syslog_relay.h
 * @brief Capture the syslog output from a device.
 * \internal
 *
 * Copyright (c) 2013-2014 Martin Szulecki All Rights Reserved.
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

#ifndef ISYSLOG_RELAY_H
#define ISYSLOG_RELAY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define SYSLOG_RELAY_SERVICE_NAME "com.apple.syslog_relay"

/** Error Codes */
typedef enum {
	SYSLOG_RELAY_E_SUCCESS       =  0,
	SYSLOG_RELAY_E_INVALID_ARG   = -1,
	SYSLOG_RELAY_E_MUX_ERROR     = -2,
	SYSLOG_RELAY_E_SSL_ERROR     = -3,
	SYSLOG_RELAY_E_UNKNOWN_ERROR = -256
} syslog_relay_error_t;

typedef struct syslog_relay_client_private syslog_relay_client_private;
typedef syslog_relay_client_private *syslog_relay_client_t; /**< The client handle. */

/** Receives each character received from the device. */
typedef void (*syslog_relay_receive_cb_t)(char c, void *user_data);

/* Interface */

/**
 * Connects to the syslog_relay service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     syslog_relay_client_t upon successful return. Must be freed using
 *     syslog_relay_client_free() after use.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success, SYSLOG_RELAY_E_INVALID_ARG when
 *     client is NULL, or an SYSLOG_RELAY_E_* error code otherwise.
 */
syslog_relay_error_t syslog_relay_client_new(idevice_t device, lockdownd_service_descriptor_t service, syslog_relay_client_t * client);

/**
 * Starts a new syslog_relay service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     syslog_relay_client_t upon successful return. Must be freed using
 *     syslog_relay_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success, or an SYSLOG_RELAY_E_* error
 *     code otherwise.
 */
syslog_relay_error_t syslog_relay_client_start_service(idevice_t device, syslog_relay_client_t * client, const char* label);

/**
 * Disconnects a syslog_relay client from the device and frees up the
 * syslog_relay client data.
 *
 * @param client The syslog_relay client to disconnect and free.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success, SYSLOG_RELAY_E_INVALID_ARG when
 *     client is NULL, or an SYSLOG_RELAY_E_* error code otherwise.
 */
syslog_relay_error_t syslog_relay_client_free(syslog_relay_client_t client);


/**
 * Starts capturing the syslog of the device using a callback.
 *
 * Use syslog_relay_stop_capture() to stop receiving the syslog.
 *
 * @param client The syslog_relay client to use
 * @param callback Callback to receive each character from the syslog.
 * @param user_data Custom pointer passed to the callback function.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success,
 *      SYSLOG_RELAY_E_INVALID_ARG when one or more parameters are
 *      invalid or SYSLOG_RELAY_E_UNKNOWN_ERROR when an unspecified
 *      error occurs or a syslog capture has already been started.
 */
syslog_relay_error_t syslog_relay_start_capture(syslog_relay_client_t client, syslog_relay_receive_cb_t callback, void* user_data);

/**
 * Stops capturing the syslog of the device.
 *
 * Use syslog_relay_start_capture() to start receiving the syslog.
 *
 * @param client The syslog_relay client to use
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success,
 *      SYSLOG_RELAY_E_INVALID_ARG when one or more parameters are
 *      invalid or SYSLOG_RELAY_E_UNKNOWN_ERROR when an unspecified
 *      error occurs or a syslog capture has already been started.
 */
syslog_relay_error_t syslog_relay_stop_capture(syslog_relay_client_t client);

/* Receiving */

/**
 * Receives data using the given syslog_relay client with specified timeout.
 *
 * @param client The syslog_relay client to use for receiving
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success,
 *      SYSLOG_RELAY_E_INVALID_ARG when one or more parameters are
 *      invalid, SYSLOG_RELAY_E_MUX_ERROR when a communication error
 *      occurs, or SYSLOG_RELAY_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
syslog_relay_error_t syslog_relay_receive_with_timeout(syslog_relay_client_t client, char *data, uint32_t size, uint32_t *received, unsigned int timeout);

/**
 * Receives data from the service.
 *
 * @param client The syslog_relay client
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success,
 *  SYSLOG_RELAY_E_INVALID_ARG when client or plist is NULL
 */
syslog_relay_error_t syslog_relay_receive(syslog_relay_client_t client, char *data, uint32_t size, uint32_t *received);

#ifdef __cplusplus
}
#endif

#endif
