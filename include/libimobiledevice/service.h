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
service_error_t service_client_new(idevice_t device, lockdownd_service_descriptor_t service, service_client_t *client);
service_error_t service_client_factory_start_service(idevice_t device, const char* service_name, void **client, const char* label, int16_t (*constructor_func)(idevice_t, lockdownd_service_descriptor_t, void**), int16_t *error_code);
service_error_t service_client_free(service_client_t client);

service_error_t service_send(service_client_t client, const char *data, uint32_t size, uint32_t *sent);
service_error_t service_receive_with_timeout(service_client_t client, char *data, uint32_t size, uint32_t *received, unsigned int timeout);
service_error_t service_receive(service_client_t client, char *data, uint32_t size, uint32_t *received);

service_error_t service_enable_ssl(service_client_t client);
service_error_t service_disable_ssl(service_client_t client);

#ifdef __cplusplus
}
#endif

#endif
