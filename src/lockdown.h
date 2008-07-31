/*
 * lockdown.h
 * Defines lockdown stuff, like the client struct.
 *
 * Copyright (c) 2008 Zack C. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. 
 */

#ifndef LOCKDOWND_H
#define LOCKDOWND_H

#include "plist.h"

#include <gnutls/gnutls.h>
#include <string.h>

typedef struct {
	usbmux_tcp_header *connection;
	gnutls_session_t *ssl_session;
	iPhone *iphone;
	int in_SSL;
	char *gtls_buffer_hack;
	int gtls_buffer_hack_len;
} lockdownd_client;

lockdownd_client *new_lockdownd_client(iPhone *phone);
int lockdownd_hello(lockdownd_client *control);
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
