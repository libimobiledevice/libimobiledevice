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

#if defined(HAVE_OPENSSL)
#include <openssl/ssl.h>
#elif defined(HAVE_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#elif defined(HAVE_MBEDTLS)
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#endif

#ifdef LIBIMOBILEDEVICE_STATIC
  #define LIBIMOBILEDEVICE_API
#elif defined(_WIN32)
  #define LIBIMOBILEDEVICE_API __declspec( dllexport )
#else
  #if __GNUC__ >= 4
    #define LIBIMOBILEDEVICE_API __attribute__((visibility("default")))
  #else
    #define LIBIMOBILEDEVICE_API
  #endif
#endif

#include "common/userpref.h"
#include "libimobiledevice/libimobiledevice.h"

#define DEVICE_VERSION(maj, min, patch) (((maj & 0xFF) << 16) | ((min & 0xFF) << 8) | (patch & 0xFF))

#define DEVICE_CLASS_IPHONE  1
#define DEVICE_CLASS_IPAD    2
#define DEVICE_CLASS_IPOD    3
#define DEVICE_CLASS_APPLETV 4
#define DEVICE_CLASS_WATCH   5
#define DEVICE_CLASS_UNKNOWN 255

struct ssl_data_private {
#if defined(HAVE_OPENSSL)
	SSL *session;
	SSL_CTX *ctx;
#elif defined(HAVE_GNUTLS)
	gnutls_certificate_credentials_t certificate;
	gnutls_session_t session;
	gnutls_x509_privkey_t root_privkey;
	gnutls_x509_crt_t root_cert;
	gnutls_x509_privkey_t host_privkey;
	gnutls_x509_crt_t host_cert;
#elif defined(HAVE_MBEDTLS)
	mbedtls_ssl_context ctx;
	mbedtls_ssl_config config;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_x509_crt certificate;
	mbedtls_pk_context root_privkey;
#endif
};
typedef struct ssl_data_private *ssl_data_t;

struct idevice_connection_private {
	idevice_t device;
	enum idevice_connection_type type;
	void *data;
	ssl_data_t ssl_data;
	unsigned int ssl_recv_timeout;
	idevice_error_t status;
};

struct idevice_private {
	char *udid;
	uint32_t mux_id;
	enum idevice_connection_type conn_type;
	void *conn_data;
	int version;
	int device_class;
};

#endif
