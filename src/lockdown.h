/*
 * lockdown.h
 * Defines lockdown stuff, like the client struct.
 *
 * Copyright (c) 2008 Zach C. All Rights Reserved.
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

#ifndef __LOCKDOWND_H
#define __LOCKDOWND_H

#include "userpref.h"

#include "libimobiledevice/lockdown.h"
#include "property_list_service.h"

struct lockdownd_client_private {
	property_list_service_client_t parent;
	int ssl_enabled;
	char *session_id;
	char *udid;
	char *label;
};

lockdownd_error_t lockdownd_get_device_public_key(lockdownd_client_t client, key_data_t * public_key);
lockdownd_error_t lockdownd_gen_pair_cert(key_data_t public_key, key_data_t * device_cert, key_data_t * host_cert, key_data_t * root_cert);

#endif
