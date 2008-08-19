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
#include "plist.h"

#include <gnutls/gnutls.h>
#include <string.h>
#include <libiphone/libiphone.h>




struct iphone_lckd_client_int {
	iphone_umux_client_t connection;
	gnutls_session_t *ssl_session;
	int in_SSL;
	char *gtls_buffer_hack;
	int gtls_buffer_hack_len;
};

char *lockdownd_generate_hostid();

iphone_lckd_client_t new_lockdownd_client(iphone_device_t phone);
int lockdownd_hello(iphone_lckd_client_t control);
int lockdownd_get_device_uid(iphone_lckd_client_t control, char **uid);
int lockdownd_get_device_public_key(iphone_lckd_client_t control, char **public_key);

int lockdownd_gen_pair_cert(char *public_key_b64, char **device_cert_b64, char **host_cert_b64, char **root_cert_b64);
int lockdownd_pair_device(iphone_lckd_client_t control, char *public_key, char *host_id);
int lockdownd_recv(iphone_lckd_client_t control, char **dump_data);
int lockdownd_send(iphone_lckd_client_t control, char *raw_data, uint32 length);
void lockdownd_close(iphone_lckd_client_t control);

// SSL functions

int lockdownd_start_SSL_session(iphone_lckd_client_t control, const char *HostID);
ssize_t lockdownd_securead(gnutls_transport_ptr_t transport, char *buffer, size_t length);
ssize_t lockdownd_secuwrite(gnutls_transport_ptr_t transport, char *buffer, size_t length);


#endif
