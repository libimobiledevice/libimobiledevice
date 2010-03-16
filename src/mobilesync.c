/*
 * mobilesync.c 
 * Contains functions for the built-in MobileSync client.
 * 
 * Copyright (c) 2009 Jonathan Beck All Rights Reserved.
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

#include <plist/plist.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "mobilesync.h"
#include "device_link_service.h"
#include "debug.h"

#define MSYNC_VERSION_INT1 100
#define MSYNC_VERSION_INT2 100

/**
 * Convert an device_link_service_error_t value to an mobilesync_error_t value.
 * Used internally to get correct error codes when using device_link_service stuff.
 *
 * @param err An device_link_service_error_t error code
 *
 * @return A matching mobilesync_error_t error code,
 *     MOBILESYNC_E_UNKNOWN_ERROR otherwise.
 */
static mobilesync_error_t mobilesync_error(device_link_service_error_t err)
{
	switch (err) {
		case DEVICE_LINK_SERVICE_E_SUCCESS:
			return MOBILESYNC_E_SUCCESS;
		case DEVICE_LINK_SERVICE_E_INVALID_ARG:
			return MOBILESYNC_E_INVALID_ARG;
		case DEVICE_LINK_SERVICE_E_PLIST_ERROR:
			return MOBILESYNC_E_PLIST_ERROR;
		case DEVICE_LINK_SERVICE_E_MUX_ERROR:
			return MOBILESYNC_E_MUX_ERROR;
		case DEVICE_LINK_SERVICE_E_BAD_VERSION:
			return MOBILESYNC_E_BAD_VERSION;
		default:
			break;
	}
	return MOBILESYNC_E_UNKNOWN_ERROR;
}

/**
 * Connects to the mobilesync service on the specified device.
 *
 * @param device The device to connect to.
 * @param port Destination port (usually given by lockdownd_start_service).
 * @param client Pointer that will be set to a newly allocated
 *     mobilesync_client_t upon successful return.
 *
 * @return MOBILESYNC_E_SUCCESS on success, MOBILESYNC_E_INVALID ARG if one
 *     or more parameters are invalid, or DEVICE_LINK_SERVICE_E_BAD_VERSION if
 *     the mobilesync version on the device is newer.
 */
mobilesync_error_t mobilesync_client_new(idevice_t device, uint16_t port,
						   mobilesync_client_t * client)
{
	if (!device || port == 0 || !client || *client)
		return MOBILESYNC_E_INVALID_ARG;

	device_link_service_client_t dlclient = NULL;
	mobilesync_error_t ret = mobilesync_error(device_link_service_client_new(device, port, &dlclient));
	if (ret != MOBILESYNC_E_SUCCESS) {
		return ret;
	}

	mobilesync_client_t client_loc = (mobilesync_client_t) malloc(sizeof(struct mobilesync_client_private));
	client_loc->parent = dlclient;

	/* perform handshake */
	ret = mobilesync_error(device_link_service_version_exchange(dlclient, MSYNC_VERSION_INT1, MSYNC_VERSION_INT2));
	if (ret != MOBILESYNC_E_SUCCESS) {
		debug_info("version exchange failed, error %d", ret);
		mobilesync_client_free(client_loc);
		return ret;
	}

	*client = client_loc;

	return ret;
}

/**
 * Disconnects a mobilesync client from the device and frees up the
 * mobilesync client data.
 *
 * @param client The mobilesync client to disconnect and free.
 *
 * @return MOBILESYNC_E_SUCCESS on success, or MOBILESYNC_E_INVALID_ARG
 *     if client is NULL.
 */
mobilesync_error_t mobilesync_client_free(mobilesync_client_t client)
{
	if (!client)
		return MOBILESYNC_E_INVALID_ARG;
	device_link_service_disconnect(client->parent);
	mobilesync_error_t err = mobilesync_error(device_link_service_client_free(client->parent));
	free(client);
	return err;
}

/**
 * Polls the device for mobilesync data.
 *
 * @param client The mobilesync client
 * @param plist A pointer to the location where the plist should be stored
 *
 * @return an error code
 */
mobilesync_error_t mobilesync_receive(mobilesync_client_t client, plist_t * plist)
{
	if (!client)
		return MOBILESYNC_E_INVALID_ARG;
	mobilesync_error_t ret = mobilesync_error(device_link_service_receive(client->parent, plist));
	return ret;
}

/**
 * Sends mobilesync data to the device
 * 
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The mobilesync client
 * @param plist The location of the plist to send
 *
 * @return an error code
 */
mobilesync_error_t mobilesync_send(mobilesync_client_t client, plist_t plist)
{
	if (!client || !plist)
		return MOBILESYNC_E_INVALID_ARG;
	return mobilesync_error(device_link_service_send(client->parent, plist));
}
