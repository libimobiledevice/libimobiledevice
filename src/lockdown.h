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

#ifndef LOCKDOWND_H
#define LOCKDOWND_H

#include "usbmux.h"

#include <gnutls/gnutls.h>
#include <string.h>
#include <libiphone/libiphone.h>




struct iphone_lckd_client_int {
	iphone_umux_client_t connection;
	gnutls_session_t *ssl_session;
	int in_SSL;
	char session_id[40];
};

iphone_lckd_client_t new_lockdownd_client(iphone_device_t phone);
iphone_error_t lockdownd_hello(iphone_lckd_client_t control);

iphone_error_t lockdownd_generic_get_value(iphone_lckd_client_t control, const char *req_key, const char *req_string,
										   gnutls_datum_t * value);

iphone_error_t lockdownd_get_device_public_key(iphone_lckd_client_t control, gnutls_datum_t * public_key);

iphone_error_t lockdownd_gen_pair_cert(gnutls_datum_t public_key, gnutls_datum_t * device_cert,
									   gnutls_datum_t * host_cert, gnutls_datum_t * root_cert);
iphone_error_t lockdownd_pair_device(iphone_lckd_client_t control, char *uid, char *host_id);
void lockdownd_close(iphone_lckd_client_t control);

// SSL functions

iphone_error_t lockdownd_start_SSL_session(iphone_lckd_client_t control, const char *HostID);
ssize_t lockdownd_securead(gnutls_transport_ptr_t transport, char *buffer, size_t length);
ssize_t lockdownd_secuwrite(gnutls_transport_ptr_t transport, char *buffer, size_t length);


#endif
