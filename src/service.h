/* 
 * service.h
 * Definitions for the generic service implementation
 * 
 * Copyright (c) 2013 Nikias Bassen, All Rights Reserved.
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
#ifndef SERVICE_H
#define SERVICE_H

#include "libimobiledevice/lockdown.h"
#include "idevice.h"

/* Error Codes */
#define SERVICE_E_SUCCESS                0
#define SERVICE_E_INVALID_ARG           -1
#define SERVICE_E_MUX_ERROR             -3
#define SERVICE_E_SSL_ERROR             -4
#define SERVICE_E_START_SERVICE_ERROR   -5
#define SERVICE_E_UNKNOWN_ERROR       -256

struct service_client_private {
	idevice_connection_t connection;
};

typedef struct service_client_private *service_client_t;

typedef int16_t service_error_t;

#define SERVICE_CONSTRUCTOR(x) (int16_t (*)(idevice_t, lockdownd_service_descriptor_t, void**))(x)

/* creation and destruction */
service_error_t service_client_new(idevice_t device, lockdownd_service_descriptor_t service, service_client_t *client);
service_error_t service_client_factory_start_service(idevice_t device, const char* service_name, void **client, const char* label, int16_t (*constructor_func)(idevice_t, lockdownd_service_descriptor_t, void**), int16_t *error_code);
service_error_t service_client_free(service_client_t client);

/* sending */
service_error_t service_send(service_client_t client, const char *data, uint32_t size, uint32_t *sent);

/* receiving */
service_error_t service_receive_with_timeout(service_client_t client, char *data, uint32_t size, uint32_t *received, unsigned int timeout);
service_error_t service_receive(service_client_t client, char *data, uint32_t size, uint32_t *received);

/* misc */
service_error_t service_enable_ssl(service_client_t client);
service_error_t service_disable_ssl(service_client_t client);

#endif
