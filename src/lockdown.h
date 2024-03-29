/*
 * lockdown.h
 * Defines lockdown stuff, like the client struct.
 *
 * Copyright (c) 2014 Martin Szulecki All Rights Reserved.
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

#include "idevice.h"
#include "libimobiledevice/lockdown.h"
#include "property_list_service.h"

#define LOCKDOWN_PROTOCOL_VERSION "2"

struct lockdownd_client_private {
	property_list_service_client_t parent;
	int ssl_enabled;
	char *session_id;
	char *label;
	idevice_t device;
	unsigned char* cu_key;
	unsigned int cu_key_len;
};

lockdownd_error_t lockdown_check_result(plist_t dict, const char *query_match);

#endif
