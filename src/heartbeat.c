/*
 * heartbeat.c 
 * com.apple.mobile.heartbeat service implementation.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <plist/plist.h>

#include "heartbeat.h"
#include "lockdown.h"
#include "common/debug.h"

/**
 * Convert a property_list_service_error_t value to a heartbeat_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An property_list_service_error_t error code
 *
 * @return A matching heartbeat_error_t error code,
 *     HEARTBEAT_E_UNKNOWN_ERROR otherwise.
 */
static heartbeat_error_t heartbeat_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return HEARTBEAT_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return HEARTBEAT_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return HEARTBEAT_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return HEARTBEAT_E_MUX_ERROR;
		case PROPERTY_LIST_SERVICE_E_SSL_ERROR:
			return HEARTBEAT_E_SSL_ERROR;
		default:
			break;
	}
	return HEARTBEAT_E_UNKNOWN_ERROR;
}

heartbeat_error_t heartbeat_client_new(idevice_t device, lockdownd_service_descriptor_t service, heartbeat_client_t * client)
{
	*client = NULL;

	if (!device || !service || service->port == 0 || !client || *client) {
		debug_info("Incorrect parameter passed to heartbeat_client_new.");
		return HEARTBEAT_E_INVALID_ARG;
	}

	debug_info("Creating heartbeat_client, port = %d.", service->port);

	property_list_service_client_t plclient = NULL;
	heartbeat_error_t ret = heartbeat_error(property_list_service_client_new(device, service, &plclient));
	if (ret != HEARTBEAT_E_SUCCESS) {
		debug_info("Creating a property list client failed. Error: %i", ret);
		return ret;
	}

	heartbeat_client_t client_loc = (heartbeat_client_t) malloc(sizeof(struct heartbeat_client_private));
	client_loc->parent = plclient;

	*client = client_loc;

	debug_info("heartbeat_client successfully created.");
	return 0;
}

heartbeat_error_t heartbeat_client_start_service(idevice_t device, heartbeat_client_t * client, const char* label)
{
	heartbeat_error_t err = HEARTBEAT_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, HEARTBEAT_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(heartbeat_client_new), &err);
	return err;
}

heartbeat_error_t heartbeat_client_free(heartbeat_client_t client)
{
	if (!client)
		return HEARTBEAT_E_INVALID_ARG;

	heartbeat_error_t err = heartbeat_error(property_list_service_client_free(client->parent));
	free(client);

	return err;
}

heartbeat_error_t heartbeat_send(heartbeat_client_t client, plist_t plist)
{
	heartbeat_error_t res = HEARTBEAT_E_UNKNOWN_ERROR;

	res = heartbeat_error(property_list_service_send_binary_plist(client->parent, plist));
	if (res != HEARTBEAT_E_SUCCESS) {
		debug_info("Sending plist failed with error %d", res);
		return res;
	}

	debug_plist(plist);

	return res;
}

heartbeat_error_t heartbeat_receive(heartbeat_client_t client, plist_t * plist)
{
	return heartbeat_receive_with_timeout(client, plist, 1000);
}

heartbeat_error_t heartbeat_receive_with_timeout(heartbeat_client_t client, plist_t * plist, uint32_t timeout_ms)
{
	heartbeat_error_t res = HEARTBEAT_E_UNKNOWN_ERROR;
	plist_t outplist = NULL;

	res = heartbeat_error(property_list_service_receive_plist_with_timeout(client->parent, &outplist, timeout_ms));
	if (res != HEARTBEAT_E_SUCCESS || !outplist) {
		debug_info("Could not receive plist, error %d", res);
		plist_free(outplist);
		return HEARTBEAT_E_MUX_ERROR;
	}

	*plist = outplist;

	debug_plist(*plist);

	return res;
}
