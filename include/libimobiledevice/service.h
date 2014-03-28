/**
 * @file libimobiledevice/service.h
 * @brief Generic basic service implementation to inherit.
 * \internal
 * 
 * Copyright (c) 2013 Martin Szulecki All Rights Reserved.
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

#ifndef ISERVICE_H
#define ISERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** @name Error Codes */
/*@{*/
#define SERVICE_E_SUCCESS                0
#define SERVICE_E_INVALID_ARG           -1
#define SERVICE_E_MUX_ERROR             -3
#define SERVICE_E_SSL_ERROR             -4
#define SERVICE_E_START_SERVICE_ERROR   -5
#define SERVICE_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t service_error_t;

typedef struct service_client_private service_client_private;
typedef service_client_private* service_client_t; /**< The client handle. */

#define SERVICE_CONSTRUCTOR(x) (int16_t (*)(idevice_t, lockdownd_service_descriptor_t, void**))(x)

/* Interface */

/**
 * Creates a new service for the specified service descriptor.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated
 *     service_client_t upon successful return.
 *
 * @return SERVICE_E_SUCCESS on success,
 *     SERVICE_E_INVALID_ARG when one of the arguments is invalid,
 *     or SERVICE_E_MUX_ERROR when connecting to the device failed.
 */
service_error_t service_client_new(idevice_t device, lockdownd_service_descriptor_t service, service_client_t *client);

/**
 * Starts a new service on the specified device with given name and
 * connects to it.
 *
 * @param device The device to connect to.
 * @param service_name The name of the service to start.
 * @param client Pointer that will point to a newly allocated service_client_t
 *     upon successful return. Must be freed using service_client_free() after
 *     use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return SERVICE_E_SUCCESS on success, or a SERVICE_E_* error code
 *     otherwise.
 */
service_error_t service_client_factory_start_service(idevice_t device, const char* service_name, void **client, const char* label, int16_t (*constructor_func)(idevice_t, lockdownd_service_descriptor_t, void**), int16_t *error_code);

/**
 * Frees a service instance.
 *
 * @param client The service instance to free.
 *
 * @return SERVICE_E_SUCCESS on success,
 *     SERVICE_E_INVALID_ARG when client is invalid, or a
 *     SERVICE_E_UNKNOWN_ERROR when another error occured.
 */
service_error_t service_client_free(service_client_t client);


/**
 * Sends data using the given service client.
 *
 * @param client The service client to use for sending.
 * @param data Data to send
 * @param size Size of the data to send
 * @param sent Number of bytes sent (can be NULL to ignore)
 *
 * @return SERVICE_E_SUCCESS on success,
 *      SERVICE_E_INVALID_ARG when one or more parameters are
 *      invalid, or SERVICE_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
service_error_t service_send(service_client_t client, const char *data, uint32_t size, uint32_t *sent);

/**
 * Receives data using the given service client with specified timeout.
 *
 * @param client The service client to use for receiving
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return SERVICE_E_SUCCESS on success,
 *      SERVICE_E_INVALID_ARG when one or more parameters are
 *      invalid, SERVICE_E_MUX_ERROR when a communication error
 *      occurs, or SERVICE_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
service_error_t service_receive_with_timeout(service_client_t client, char *data, uint32_t size, uint32_t *received, unsigned int timeout);

/**
 * Receives data using the given service client.
 *
 * @param client The service client to use for receiving
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 *
 * @return SERVICE_E_SUCCESS on success,
 *      SERVICE_E_INVALID_ARG when one or more parameters are
 *      invalid, SERVICE_E_MUX_ERROR when a communication error
 *      occurs, or SERVICE_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
service_error_t service_receive(service_client_t client, char *data, uint32_t size, uint32_t *received);


/**
 * Enable SSL for the given service client.
 *
 * @param client The connected service client for that SSL should be enabled.
 *
 * @return SERVICE_E_SUCCESS on success,
 *     SERVICE_E_INVALID_ARG if client or client->connection is
 *     NULL, SERVICE_E_SSL_ERROR when SSL could not be enabled,
 *     or SERVICE_E_UNKNOWN_ERROR otherwise.
 */
service_error_t service_enable_ssl(service_client_t client);

/**
 * Disable SSL for the given service client.
 *
 * @param client The connected service client for that SSL should be disabled.
 *
 * @return SERVICE_E_SUCCESS on success,
 *     SERVICE_E_INVALID_ARG if client or client->connection is
 *     NULL, or SERVICE_E_UNKNOWN_ERROR otherwise.
 */
service_error_t service_disable_ssl(service_client_t client);

#ifdef __cplusplus
}
#endif

#endif
