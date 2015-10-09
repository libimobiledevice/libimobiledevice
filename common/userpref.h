/*
 * userpref.h
 * contains methods to access user specific certificates IDs and more.
 *
 * Copyright (c) 2013-2014 Martin Szulecki All Rights Reserved.
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

#ifndef __USERPREF_H
#define __USERPREF_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_OPENSSL
typedef struct {
	unsigned char *data;
	unsigned int size;
} key_data_t;
#else
#include <gnutls/gnutls.h>
typedef gnutls_datum_t key_data_t;
#endif

#include <stdint.h>
#include <plist/plist.h>

#define USERPREF_DEVICE_CERTIFICATE_KEY "DeviceCertificate"
#define USERPREF_ESCROW_BAG_KEY "EscrowBag"
#define USERPREF_HOST_CERTIFICATE_KEY "HostCertificate"
#define USERPREF_ROOT_CERTIFICATE_KEY "RootCertificate"
#define USERPREF_HOST_PRIVATE_KEY_KEY "HostPrivateKey"
#define USERPREF_ROOT_PRIVATE_KEY_KEY "RootPrivateKey"
#define USERPREF_HOST_ID_KEY "HostID"
#define USERPREF_SYSTEM_BUID_KEY "SystemBUID"
#define USERPREF_WIFI_MAC_ADDRESS_KEY "WiFiMACAddress"

/** Error Codes */
typedef enum {
	USERPREF_E_SUCCESS       =  0,
	USERPREF_E_INVALID_ARG   = -1,
	USERPREF_E_INVALID_CONF  = -2,
	USERPREF_E_SSL_ERROR     = -3,
	USERPREF_E_READ_ERROR    = -4,
	USERPREF_E_WRITE_ERROR   = -5,
	USERPREF_E_UNKNOWN_ERROR = -256
} userpref_error_t;

const char *userpref_get_config_dir(void);
int userpref_read_system_buid(char **system_buid);
userpref_error_t userpref_read_pair_record(const char *udid, plist_t *pair_record);
userpref_error_t userpref_save_pair_record(const char *udid, plist_t pair_record);
userpref_error_t userpref_delete_pair_record(const char *udid);

userpref_error_t pair_record_generate_keys_and_certs(plist_t pair_record, key_data_t public_key);
#ifdef HAVE_OPENSSL
userpref_error_t pair_record_import_key_with_name(plist_t pair_record, const char* name, key_data_t* key);
userpref_error_t pair_record_import_crt_with_name(plist_t pair_record, const char* name, key_data_t* cert);
#else
userpref_error_t pair_record_import_key_with_name(plist_t pair_record, const char* name, gnutls_x509_privkey_t key);
userpref_error_t pair_record_import_crt_with_name(plist_t pair_record, const char* name, gnutls_x509_crt_t cert);
#endif

userpref_error_t pair_record_get_host_id(plist_t pair_record, char** host_id);
userpref_error_t pair_record_set_host_id(plist_t pair_record, const char* host_id);
userpref_error_t pair_record_get_item_as_key_data(plist_t pair_record, const char* name, key_data_t *value);
userpref_error_t pair_record_set_item_from_key_data(plist_t pair_record, const char* name, key_data_t *value);

/* deprecated */
userpref_error_t userpref_get_paired_udids(char ***list, unsigned int *count);
int userpref_has_pair_record(const char *udid);

#endif
