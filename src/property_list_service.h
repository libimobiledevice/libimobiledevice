 /* 
 * property_list_service.h
 * Definitions for the PropertyList service
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

#ifndef __PROPERTY_LIST_SERVICE_H
#define __PROPERTY_LIST_SERVICE_H

#include <libimobiledevice/lockdown.h>
#include "service.h"
#include "idevice.h"

/* Error Codes */
#define PROPERTY_LIST_SERVICE_E_SUCCESS                0
#define PROPERTY_LIST_SERVICE_E_INVALID_ARG           -1
#define PROPERTY_LIST_SERVICE_E_PLIST_ERROR           -2
#define PROPERTY_LIST_SERVICE_E_MUX_ERROR             -3
#define PROPERTY_LIST_SERVICE_E_SSL_ERROR             -4

#define PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR       -256

struct property_list_service_client_private {
	service_client_t parent;
};

typedef struct property_list_service_client_private *property_list_service_client_t;

typedef int16_t property_list_service_error_t;

/* creation and destruction */
property_list_service_error_t property_list_service_client_new(idevice_t device, lockdownd_service_descriptor_t service, property_list_service_client_t *client);
property_list_service_error_t property_list_service_client_free(property_list_service_client_t client);

/* sending */
property_list_service_error_t property_list_service_send_xml_plist(property_list_service_client_t client, plist_t plist);
property_list_service_error_t property_list_service_send_binary_plist(property_list_service_client_t client, plist_t plist);

/* receiving */
property_list_service_error_t property_list_service_receive_plist_with_timeout(property_list_service_client_t client, plist_t *plist, unsigned int timeout);
property_list_service_error_t property_list_service_receive_plist(property_list_service_client_t client, plist_t *plist);

/* misc */
property_list_service_error_t property_list_service_enable_ssl(property_list_service_client_t client);
property_list_service_error_t property_list_service_disable_ssl(property_list_service_client_t client);

#endif
