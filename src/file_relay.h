 /* 
 * file_relay.h
 * Definitions for the file_relay service
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
#ifndef FILE_RELAY_H
#define FILE_RELAY_H

#include "libimobiledevice/file_relay.h"
#include "property_list_service.h"

/* Error Codes */
#define FILE_RELAY_E_SUCCESS                0
#define FILE_RELAY_E_INVALID_ARG           -1
#define FILE_RELAY_E_PLIST_ERROR           -2
#define FILE_RELAY_E_MUX_ERROR             -3

#define FILE_RELAY_E_UNKNOWN_ERROR       -256


struct file_relay_client_int {
	property_list_service_client_t parent;
};

#endif
