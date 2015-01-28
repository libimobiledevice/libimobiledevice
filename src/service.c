/*
 * service.c
 * generic service implementation.
 *
 * Copyright (c) 2013 Nikias Bassen. All Rights Reserved.
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "service.h"
#include "idevice.h"
#include "common/debug.h"

/**
 * Convert an idevice_error_t value to an service_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An idevice_error_t error code
 *
 * @return A matching service_error_t error code,
 *     SERVICE_E_UNKNOWN_ERROR otherwise.
 */
static service_error_t idevice_to_service_error(idevice_error_t err)
{
	switch (err) {
		case IDEVICE_E_SUCCESS:
			return SERVICE_E_SUCCESS;
		case IDEVICE_E_INVALID_ARG:
			return SERVICE_E_INVALID_ARG;
		case IDEVICE_E_SSL_ERROR:
			return SERVICE_E_SSL_ERROR;
		default:
			break;
	}
	return SERVICE_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API service_error_t service_client_new(idevice_t device, lockdownd_service_descriptor_t service, service_client_t *client)
{
	if (!device || !service || service->port == 0 || !client || *client)
		return SERVICE_E_INVALID_ARG;

	/* Attempt connection */
	idevice_connection_t connection = NULL;
	if (idevice_connect(device, service->port, &connection) != IDEVICE_E_SUCCESS) {
		return SERVICE_E_MUX_ERROR;
	}

	/* create client object */
	service_client_t client_loc = (service_client_t)malloc(sizeof(struct service_client_private));
	client_loc->connection = connection;

	/* enable SSL if requested */
	if (service->ssl_enabled == 1)
		service_enable_ssl(client_loc);

	/* all done, return success */
	*client = client_loc;
	return SERVICE_E_SUCCESS;
}

LIBIMOBILEDEVICE_API service_error_t service_client_factory_start_service(idevice_t device, const char* service_name, void **client, const char* label, int32_t (*constructor_func)(idevice_t, lockdownd_service_descriptor_t, void**), int32_t *error_code)
{
	*client = NULL;

	lockdownd_client_t lckd = NULL;
	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(device, &lckd, label)) {
		debug_info("Could not create a lockdown client.");
		return SERVICE_E_START_SERVICE_ERROR;
	}

	lockdownd_service_descriptor_t service = NULL;
	lockdownd_start_service(lckd, service_name, &service);
	lockdownd_client_free(lckd);

	if (!service || service->port == 0) {
		debug_info("Could not start service %s!", service_name);
		return SERVICE_E_START_SERVICE_ERROR;
	}

	int32_t ec;
	if (constructor_func) {
		ec = (int32_t)constructor_func(device, service, client);
	} else {
		ec = service_client_new(device, service, (service_client_t*)client);
	}
	if (error_code) {
		*error_code = ec;
	}

	if (ec != SERVICE_E_SUCCESS) {
		debug_info("Could not connect to service %s! Port: %i, error: %i", service_name, service->port, ec);
	}

	lockdownd_service_descriptor_free(service);
	service = NULL;

	return (ec == SERVICE_E_SUCCESS) ? SERVICE_E_SUCCESS : SERVICE_E_START_SERVICE_ERROR;
}

LIBIMOBILEDEVICE_API service_error_t service_client_free(service_client_t client)
{
	if (!client)
		return SERVICE_E_INVALID_ARG;

	service_error_t err = idevice_to_service_error(idevice_disconnect(client->connection));

	free(client);
	client = NULL;

	return err;
}

LIBIMOBILEDEVICE_API service_error_t service_send(service_client_t client, const char* data, uint32_t size, uint32_t *sent)
{
	service_error_t res = SERVICE_E_UNKNOWN_ERROR;
	int bytes = 0;

	if (!client || (client && !client->connection) || !data || (size == 0)) {
		return SERVICE_E_INVALID_ARG;
	}

	debug_info("sending %d bytes", size);
	res = idevice_to_service_error(idevice_connection_send(client->connection, data, size, (uint32_t*)&bytes));
	if (bytes <= 0) {
		debug_info("ERROR: sending to device failed.");
	}
	if (sent) {
		*sent = (uint32_t)bytes;
	}

	return res;
}

LIBIMOBILEDEVICE_API service_error_t service_receive_with_timeout(service_client_t client, char* data, uint32_t size, uint32_t *received, unsigned int timeout)
{
	service_error_t res = SERVICE_E_UNKNOWN_ERROR;
	int bytes = 0;

	if (!client || (client && !client->connection) || !data || (size == 0)) {
		return SERVICE_E_INVALID_ARG;
	}

	res = idevice_to_service_error(idevice_connection_receive_timeout(client->connection, data, size, (uint32_t*)&bytes, timeout));
	if (bytes <= 0) {
		debug_info("could not read data");
	}
	if (received) {
		*received = (uint32_t)bytes;
	}

	return res;
}

LIBIMOBILEDEVICE_API service_error_t service_receive(service_client_t client, char* data, uint32_t size, uint32_t *received)
{
	return service_receive_with_timeout(client, data, size, received, 10000);
}

LIBIMOBILEDEVICE_API service_error_t service_enable_ssl(service_client_t client)
{
	if (!client || !client->connection)
		return SERVICE_E_INVALID_ARG;
	return idevice_to_service_error(idevice_connection_enable_ssl(client->connection));
}

LIBIMOBILEDEVICE_API service_error_t service_disable_ssl(service_client_t client)
{
	if (!client || !client->connection)
		return SERVICE_E_INVALID_ARG;
	return idevice_to_service_error(idevice_connection_disable_ssl(client->connection));
}

