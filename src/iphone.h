/*
 * iphone.h
 * Device discovery and communication interface -- header file.
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
#ifndef IPHONE_H
#define IPHONE_H

#include <plist/plist.h>
#include <gnutls/gnutls.h>

#include "libiphone/libiphone.h"

enum connection_type {
	CONNECTION_USBMUXD = 1
};

struct iphone_connection_int {
	enum connection_type type;
	void *data;
};

struct iphone_device_int {
	char *uuid;
	enum connection_type conn_type;
	void *conn_data;
};

iphone_error_t iphone_device_send_xml_plist(iphone_connection_t connection, plist_t plist);
iphone_error_t iphone_device_send_binary_plist(iphone_connection_t connection, plist_t plist);
iphone_error_t iphone_device_send_encrypted_xml_plist(gnutls_session_t ssl_session, plist_t plist);
iphone_error_t iphone_device_send_encrypted_binary_plist(gnutls_session_t ssl_session, plist_t plist);

iphone_error_t iphone_device_receive_plist_with_timeout(iphone_connection_t connection, plist_t *plist, unsigned int timeout);
iphone_error_t iphone_device_receive_plist(iphone_connection_t connection, plist_t *plist);
iphone_error_t iphone_device_receive_encrypted_plist_with_timeout(gnutls_session_t ssl_session, plist_t *plist, unsigned int timeout);
iphone_error_t iphone_device_receive_encrypted_plist(gnutls_session_t ssl_session, plist_t *plist);

#endif
