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

typedef struct {
	usbmux_connection *connection;
	gnutls_session_t *ssl_session;
	int in_SSL;
	char *gtls_buffer_hack;
	int gtls_buffer_hack_len;
} lockdownd_client;

int lockdownd_init(iPhone *phone, lockdownd_client **control);
char *lockdownd_generate_hostid();

lockdownd_client *new_lockdownd_client(iPhone *phone);
int lockdownd_hello(lockdownd_client *control);
int lockdownd_get_device_uid(lockdownd_client *control, char **uid);
int lockdownd_get_device_public_key(lockdownd_client *control, char **public_key);
int lockdownd_gen_pair_cert(char *public_key_b64, char **device_cert_b64, char **host_cert_b64, char **root_cert_b64);
int lockdownd_pair_device(lockdownd_client *control, char *uid, char *host_id);
int lockdownd_recv(lockdownd_client *control, char **dump_data);
int lockdownd_send(lockdownd_client *control, char *raw_data, uint32 length);
void lockdownd_close(lockdownd_client *control);

// SSL functions

int lockdownd_start_SSL_session(lockdownd_client *control, const char *HostID);
ssize_t lockdownd_securead(gnutls_transport_ptr_t transport, char *buffer, size_t length);
ssize_t lockdownd_secuwrite(gnutls_transport_ptr_t transport, char *buffer, size_t length);

// Higher-level lockdownd stuff
int lockdownd_start_service(lockdownd_client *control, const char *service);
#endif
