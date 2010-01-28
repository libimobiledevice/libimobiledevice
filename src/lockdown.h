/*
 * lockdownd.h
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

#ifndef LOCKDOWND_H
#define LOCKDOWND_H

#include <gnutls/gnutls.h>
#include <string.h>

#include "libimobiledevice/lockdown.h"
#include "property_list_service.h"

struct lockdownd_client_int {
	property_list_service_client_t parent;
	int ssl_enabled;
	char *session_id;
	char *uuid;
	char *label;
};

lockdownd_error_t lockdownd_get_device_public_key(lockdownd_client_t client, gnutls_datum_t * public_key);
lockdownd_error_t lockdownd_gen_pair_cert(gnutls_datum_t public_key, gnutls_datum_t * device_cert,
									   gnutls_datum_t * host_cert, gnutls_datum_t * root_cert);

#endif
