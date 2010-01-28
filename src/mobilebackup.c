/*
 * mobilebackup.c 
 * Contains functions for the built-in MobileBackup client.
 * 
 * Copyright (c) 2009 Martin Szulecki All Rights Reserved.
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

#include "mobilebackup.h"
#include "device_link_service.h"
#include "debug.h"

#define MBACKUP_VERSION_INT1 100
#define MBACKUP_VERSION_INT2 0

/**
 * Convert an device_link_service_error_t value to an mobilebackup_error_t value.
 * Used internally to get correct error codes when using device_link_service stuff.
 *
 * @param err An device_link_service_error_t error code
 *
 * @return A matching mobilebackup_error_t error code,
 *     MOBILEBACKUP_E_UNKNOWN_ERROR otherwise.
 */
static mobilebackup_error_t mobilebackup_error(device_link_service_error_t err)
{
	switch (err) {
		case DEVICE_LINK_SERVICE_E_SUCCESS:
			return MOBILEBACKUP_E_SUCCESS;
		case DEVICE_LINK_SERVICE_E_INVALID_ARG:
			return MOBILEBACKUP_E_INVALID_ARG;
		case DEVICE_LINK_SERVICE_E_PLIST_ERROR:
			return MOBILEBACKUP_E_PLIST_ERROR;
		case DEVICE_LINK_SERVICE_E_MUX_ERROR:
			return MOBILEBACKUP_E_MUX_ERROR;
		case DEVICE_LINK_SERVICE_E_BAD_VERSION:
			return MOBILEBACKUP_E_BAD_VERSION;
		default:
			break;
	}
	return MOBILEBACKUP_E_UNKNOWN_ERROR;
}

mobilebackup_error_t mobilebackup_client_new(idevice_t device, uint16_t port,
						   mobilebackup_client_t * client)
{
	if (!device || port == 0 || !client || *client)
		return MOBILEBACKUP_E_INVALID_ARG;

	device_link_service_client_t dlclient = NULL;
	mobilebackup_error_t ret = mobilebackup_error(device_link_service_client_new(device, port, &dlclient));
	if (ret != MOBILEBACKUP_E_SUCCESS) {
		return ret;
	}

	mobilebackup_client_t client_loc = (mobilebackup_client_t) malloc(sizeof(struct mobilebackup_client_int));
	client_loc->parent = dlclient;

	/* perform handshake */
	ret = mobilebackup_error(device_link_service_version_exchange(dlclient, MBACKUP_VERSION_INT1, MBACKUP_VERSION_INT2));
	if (ret != MOBILEBACKUP_E_SUCCESS) {
		debug_info("version exchange failed, error %d", ret);
		mobilebackup_client_free(client_loc);
		return ret;
	}

	*client = client_loc;

	return ret;
}

mobilebackup_error_t mobilebackup_client_free(mobilebackup_client_t client)
{
	if (!client)
		return MOBILEBACKUP_E_INVALID_ARG;
	device_link_service_disconnect(client->parent);
	mobilebackup_error_t err = mobilebackup_error(device_link_service_client_free(client->parent));
	free(client);
	return err;
}

/** Polls the device for MobileBackup data.
 *
 * @param client The MobileBackup client
 * @param plist A pointer to the location where the plist should be stored
 *
 * @return an error code
 */
mobilebackup_error_t mobilebackup_receive(mobilebackup_client_t client, plist_t * plist)
{
	if (!client)
		return MOBILEBACKUP_E_INVALID_ARG;
	mobilebackup_error_t ret = mobilebackup_error(device_link_service_receive(client->parent, plist));
	return ret;
}

/** Sends MobileBackup data to the device
 * 
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The MobileBackup client
 * @param plist The location of the plist to send
 *
 * @return an error code
 */
mobilebackup_error_t mobilebackup_send(mobilebackup_client_t client, plist_t plist)
{
	if (!client || !plist)
		return MOBILEBACKUP_E_INVALID_ARG;
	return mobilebackup_error(device_link_service_send(client->parent, plist));
}

