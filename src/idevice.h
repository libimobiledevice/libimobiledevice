/*
 * idevice.h
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

#ifndef __DEVICE_H
#define __DEVICE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#else
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif

#include "common/userpref.h"

#include "libimobiledevice/libimobiledevice.h"

enum connection_type {
	CONNECTION_USBMUXD = 1
};

struct ssl_data_private {
#ifdef HAVE_OPENSSL
	SSL *session;
	SSL_CTX *ctx;
#else
	gnutls_certificate_credentials_t certificate;
	gnutls_session_t session;
	gnutls_x509_privkey_t root_privkey;
	gnutls_x509_crt_t root_cert;
	gnutls_x509_privkey_t host_privkey;
	gnutls_x509_crt_t host_cert;
#endif
};
typedef struct ssl_data_private *ssl_data_t;

struct idevice_connection_private {
	char *udid;
	enum connection_type type;
	void *data;
	ssl_data_t ssl_data;
};

struct idevice_private {
	char *udid;
	enum connection_type conn_type;
	void *conn_data;
};

#endif
