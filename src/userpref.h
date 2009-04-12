/*
 * userpref.h
 * contains methods to access user specific certificates IDs and more.
 *
 * Copyright (c) 2008 Jonathan Beck All Rights Reserved.
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

#ifndef USERPREF_H
#define USERPREF_H

#include <gnutls/gnutls.h>
#include "libiphone/libiphone.h"


iphone_error_t get_keys_and_certs(gnutls_x509_privkey_t root_privkey, gnutls_x509_crt_t root_crt, gnutls_x509_privkey_t host_privkey, gnutls_x509_crt_t host_crt);

iphone_error_t get_certs_as_pem(gnutls_datum_t *pem_root_cert, gnutls_datum_t *pem_host_cert);

char *get_host_id(void);

int is_device_known(char *uid);

int store_device_public_key(char *uid, gnutls_datum_t public_key);

int init_config_file( gnutls_datum_t * root_key, gnutls_datum_t * host_key, gnutls_datum_t * root_cert,
					 gnutls_datum_t * host_cert);
#endif
