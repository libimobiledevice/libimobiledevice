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
#include <glib.h>

#define USERPREF_E_SUCCESS             0
#define USERPREF_E_INVALID_ARG        -1
#define USERPREF_E_INVALID_CONF       -2
#define USERPREF_E_SSL_ERROR          -3

#define USERPREF_E_UNKNOWN_ERROR    -256

typedef int16_t userpref_error_t;

G_GNUC_INTERNAL userpref_error_t userpref_get_keys_and_certs(gnutls_x509_privkey_t root_privkey, gnutls_x509_crt_t root_crt, gnutls_x509_privkey_t host_privkey, gnutls_x509_crt_t host_crt);
G_GNUC_INTERNAL userpref_error_t userpref_set_keys_and_certs(gnutls_datum_t * root_key, gnutls_datum_t * root_cert, gnutls_datum_t * host_key, gnutls_datum_t * host_cert);
G_GNUC_INTERNAL userpref_error_t userpref_get_certs_as_pem(gnutls_datum_t *pem_root_cert, gnutls_datum_t *pem_host_cert);
G_GNUC_INTERNAL userpref_error_t userpref_set_device_public_key(const char *uuid, gnutls_datum_t public_key);
G_GNUC_INTERNAL userpref_error_t userpref_remove_device_public_key(const char *uuid);
G_GNUC_INTERNAL int userpref_has_device_public_key(const char *uuid);
G_GNUC_INTERNAL void userpref_get_host_id(char **host_id);

#endif
