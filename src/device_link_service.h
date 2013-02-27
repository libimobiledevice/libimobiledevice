 /* 
 * device_link_service.h
 * Definitions for the DeviceLink service
 * 
 * Copyright (c) 2010 Nikias Bassen, All Rights Reserved.
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

#ifndef __DEVICE_LINK_SERVICE_H
#define __DEVICE_LINK_SERVICE_H

#include "property_list_service.h"

/* Error Codes */
#define DEVICE_LINK_SERVICE_E_SUCCESS                0
#define DEVICE_LINK_SERVICE_E_INVALID_ARG           -1
#define DEVICE_LINK_SERVICE_E_PLIST_ERROR           -2
#define DEVICE_LINK_SERVICE_E_MUX_ERROR             -3
#define DEVICE_LINK_SERVICE_E_BAD_VERSION           -4

#define DEVICE_LINK_SERVICE_E_UNKNOWN_ERROR       -256

/** Represents an error code. */
typedef int16_t device_link_service_error_t;

struct device_link_service_client_private {
	property_list_service_client_t parent;
};

typedef struct device_link_service_client_private *device_link_service_client_t;

device_link_service_error_t device_link_service_client_new(idevice_t device, lockdownd_service_descriptor_t service, device_link_service_client_t *client);
device_link_service_error_t device_link_service_client_free(device_link_service_client_t client);
device_link_service_error_t device_link_service_version_exchange(device_link_service_client_t client, uint64_t version_major, uint64_t version_minor);
device_link_service_error_t device_link_service_send_ping(device_link_service_client_t client, const char *message);
device_link_service_error_t device_link_service_receive_message(device_link_service_client_t client, plist_t *msg_plist, char **dlmessage);
device_link_service_error_t device_link_service_send_process_message(device_link_service_client_t client, plist_t message);
device_link_service_error_t device_link_service_receive_process_message(device_link_service_client_t client, plist_t *message);
device_link_service_error_t device_link_service_disconnect(device_link_service_client_t client, const char *message);
device_link_service_error_t device_link_service_send(device_link_service_client_t client, plist_t plist);
device_link_service_error_t device_link_service_receive(device_link_service_client_t client, plist_t *plist);

#endif
