/*
 * userpref.c
 * contains methods to access user specific certificates IDs and more.
 *
 * Copyright (c) 2013-2021 Nikias Bassen, All Rights Reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <dirent.h>
#ifndef _WIN32
#include <pwd.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#endif
#include <usbmuxd.h>
#if defined(HAVE_OPENSSL)
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#if OPENSSL_VERSION_NUMBER < 0x1010000fL || \
	(defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x20700000L))
#define X509_set1_notBefore X509_set_notBefore
#define X509_set1_notAfter X509_set_notAfter
#endif
#elif defined(HAVE_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gcrypt.h>
#include <libtasn1.h>
#elif defined(HAVE_MBEDTLS)
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#else
#error No supported TLS/SSL library enabled
#endif

#ifdef _WIN32
#include <shlobj.h>
#endif

#ifndef ETIMEDOUT
#define ETIMEDOUT 138
#endif

#include <libimobiledevice-glue/utils.h>

#include "userpref.h"
#include "debug.h"

#if defined(HAVE_GNUTLS)
const ASN1_ARRAY_TYPE pkcs1_asn1_tab[] = {
	{"PKCS1", 536872976, 0},
	{0, 1073741836, 0},
	{"RSAPublicKey", 536870917, 0},
	{"modulus", 1073741827, 0},
	{"publicExponent", 3, 0},
	{0, 0, 0}
};
#endif

#ifdef _WIN32
#define DIR_SEP '\\'
#define DIR_SEP_S "\\"
#else
#define DIR_SEP '/'
#define DIR_SEP_S "/"
#endif

#define USERPREF_CONFIG_EXTENSION ".plist"

#ifdef _WIN32
#define USERPREF_CONFIG_DIR "Apple"DIR_SEP_S"Lockdown"
#else
#define USERPREF_CONFIG_DIR "lockdown"
#endif

#define USERPREF_CONFIG_FILE "SystemConfiguration"USERPREF_CONFIG_EXTENSION

static char *__config_dir = NULL;

#ifdef _WIN32
static char *userpref_utf16_to_utf8(wchar_t *unistr, long len, long *items_read, long *items_written)
{
	if (!unistr || (len <= 0)) return NULL;
	char *outbuf = (char*)malloc(3*(len+1));
	int p = 0;
	int i = 0;

	wchar_t wc;

	while (i < len) {
		wc = unistr[i++];
		if (wc >= 0x800) {
			outbuf[p++] = (char)(0xE0 + ((wc >> 12) & 0xF));
			outbuf[p++] = (char)(0x80 + ((wc >> 6) & 0x3F));
			outbuf[p++] = (char)(0x80 + (wc & 0x3F));
		} else if (wc >= 0x80) {
			outbuf[p++] = (char)(0xC0 + ((wc >> 6) & 0x1F));
			outbuf[p++] = (char)(0x80 + (wc & 0x3F));
		} else {
			outbuf[p++] = (char)(wc & 0x7F);
		}
	}
	if (items_read) {
		*items_read = i;
	}
	if (items_written) {
		*items_written = p;
	}
	outbuf[p] = 0;

	return outbuf;
}
#endif

const char *userpref_get_config_dir()
{
	char *base_config_dir = NULL;

	if (__config_dir)
		return __config_dir;

#ifdef _WIN32
	wchar_t path[MAX_PATH+1];
	HRESULT hr;
	LPITEMIDLIST pidl = NULL;
	BOOL b = FALSE;

	hr = SHGetSpecialFolderLocation (NULL, CSIDL_COMMON_APPDATA, &pidl);
	if (hr == S_OK) {
		b = SHGetPathFromIDListW (pidl, path);
		if (b) {
			base_config_dir = userpref_utf16_to_utf8 (path, wcslen(path), NULL, NULL);
			CoTaskMemFree (pidl);
		}
	}
#else
#ifdef __APPLE__
	base_config_dir = strdup("/var/db");
#else
	base_config_dir = strdup("/var/lib");
#endif
#endif
	__config_dir = string_concat(base_config_dir, DIR_SEP_S, USERPREF_CONFIG_DIR, NULL);

	if (__config_dir) {
		int i = strlen(__config_dir)-1;
		while ((i > 0) && (__config_dir[i] == DIR_SEP)) {
			__config_dir[i--] = '\0';
		}
	}

	free(base_config_dir);

	debug_info("initialized config_dir to %s", __config_dir);

	return __config_dir;
}

/**
 * Reads the SystemBUID from a previously generated configuration file.
 *
 * @note It is the responsibility of the calling function to free the returned system_buid.
 * @param system_buid A pointer that will be set to a newly allocated string containing the
 *   SystemBUID upon successful return.
 * @return 0 if the SystemBUID has been successfully retrieved or < 0 otherwise.
 */
int userpref_read_system_buid(char **system_buid)
{
	int res = usbmuxd_read_buid(system_buid);
	if (res == 0) {
		debug_info("using %s as %s", *system_buid, USERPREF_SYSTEM_BUID_KEY);
	} else {
		debug_info("could not read system buid, error %d", res);
	}
	return res;
}

/**
 * Fills a list with UDIDs of devices that have been connected to this
 * system before, i.e. for which a public key file exists.
 *
 * @param list A pointer to a char** initially pointing to NULL that will
 *        hold a newly allocated list of UDIDs upon successful return.
 *        The caller is responsible for freeing the memory. Note that if
 *        no public key file was found the list has to be freed too as it
 *        points to a terminating NULL element.
 * @param count The number of UDIDs found. This parameter can be NULL if it
 *        is not required.
 *
 * @return USERPREF_E_SUCCESS on success, or USERPREF_E_INVALID_ARG if the
 *         list parameter is not pointing to NULL.
 */
userpref_error_t userpref_get_paired_udids(char ***list, unsigned int *count)
{
	DIR *config_dir;
	const char *config_path = NULL;
	unsigned int found = 0;

	if (!list || (list && *list)) {
		debug_info("ERROR: The list parameter needs to point to NULL!");
		return USERPREF_E_INVALID_ARG;
	}

	if (count) {
		*count = 0;
	}
	*list = (char**)malloc(sizeof(char*));

	config_path = userpref_get_config_dir();
	config_dir = opendir(config_path);
	if (config_dir) {
		struct dirent *entry;
		while ((entry = readdir(config_dir))) {
			if (strcmp(entry->d_name, USERPREF_CONFIG_FILE) == 0) {
				/* ignore SystemConfiguration.plist */
				continue;
			}
			char *ext = strrchr(entry->d_name, '.');
			if (ext && (strcmp(ext, USERPREF_CONFIG_EXTENSION) == 0)) {
				size_t len = strlen(entry->d_name) - strlen(USERPREF_CONFIG_EXTENSION);
				char **newlist = (char**)realloc(*list, sizeof(char*) * (found+2));
				if (!newlist) {
					fprintf(stderr, "ERROR: Out of memory\n");
					break;
				}
				*list = newlist;
				char *tmp = (char*)malloc(len+1);
				if (tmp) {
					strncpy(tmp, entry->d_name, len);
					tmp[len] = '\0';
				}
				(*list)[found] = tmp;
				if (!tmp) {
					fprintf(stderr, "ERROR: Out of memory\n");
					break;
				}
				found++;
			}
		}
		closedir(config_dir);
	}
	(*list)[found] = NULL;

	if (count) {
		*count = found;
	}

	return USERPREF_E_SUCCESS;
}

/**
 * Save a pair record for a device.
 *
 * @param udid The device UDID as given by the device
 * @param device_id The usbmux device id (handle) of the connected device, or 0
 * @param pair_record The pair record to save
 *
 * @return 1 on success and 0 if no device record is given or if it has already
 *         been saved previously.
 */
userpref_error_t userpref_save_pair_record(const char *udid, uint32_t device_id, plist_t pair_record)
{
	char* record_data = NULL;
	uint32_t record_size = 0;

	plist_to_bin(pair_record, &record_data, &record_size);

	int res = usbmuxd_save_pair_record_with_device_id(udid, device_id, record_data, record_size);

	free(record_data);

	return res == 0 ? USERPREF_E_SUCCESS: USERPREF_E_UNKNOWN_ERROR;
}

/**
 * Read a pair record for a device.
 *
 * @param udid The device UDID as given by the device
 * @param pair_record The pair record to read
 *
 * @return USERPREF_E_SUCCESS on success,
 *     USERPREF_E_NOENT if no pairing record was found,
 *     USERPREF_E_READ_ERROR if retrieving the pairing record from usbmuxd failed,
 *     or USERPREF_E_INVALID_CONF otherwise.
 */
userpref_error_t userpref_read_pair_record(const char *udid, plist_t *pair_record)
{
	char* record_data = NULL;
	uint32_t record_size = 0;

	int res = usbmuxd_read_pair_record(udid, &record_data, &record_size);
	if (res < 0) {
		free(record_data);
		switch (-res) {
		case ENOENT:
			return USERPREF_E_NOENT;
		case ETIMEDOUT:
			return USERPREF_E_READ_ERROR;
		default:
			return USERPREF_E_INVALID_CONF;
		}
	}

	*pair_record = NULL;
	plist_from_memory(record_data, record_size, pair_record, NULL);
	free(record_data);

	if (!*pair_record) {
		debug_info("Failed to parse pairing record");
		return USERPREF_E_INVALID_CONF;
	}
	return USERPREF_E_SUCCESS;
}

/**
 * Remove the pairing record stored for a device from this host.
 *
 * @param udid The udid of the device
 *
 * @return USERPREF_E_SUCCESS on success.
 */
userpref_error_t userpref_delete_pair_record(const char *udid)
{
	int res = usbmuxd_delete_pair_record(udid);

	return res == 0 ? USERPREF_E_SUCCESS: USERPREF_E_UNKNOWN_ERROR;
}

#if defined(HAVE_OPENSSL)
static int X509_add_ext_helper(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;

	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);

	X509V3_set_ctx(&ctx, NULL, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) {
		debug_info("ERROR: X509V3_EXT_conf_nid(%d, %s) failed", nid, value);
		return 0;
	}

	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);

	return 1;
}
#elif defined(HAVE_MBEDTLS)
static int _mbedtls_x509write_crt_set_basic_constraints_critical(mbedtls_x509write_cert *ctx, int is_ca, int max_pathlen)
{
	int ret;
	unsigned char buf[9];
	unsigned char *c = buf + sizeof(buf);
	size_t len = 0;

	memset( buf, 0, sizeof(buf) );

	if (is_ca && max_pathlen > 127)
		return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

	if (is_ca) {
		if (max_pathlen >= 0) {
			MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, buf, max_pathlen ) );
		}
		MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_bool( &c, buf, 1 ) );
	}

	MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
	MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

	return mbedtls_x509write_crt_set_extension( ctx, MBEDTLS_OID_BASIC_CONSTRAINTS, MBEDTLS_OID_SIZE( MBEDTLS_OID_BASIC_CONSTRAINTS ), 1, buf + sizeof(buf) - len, len );
}
#endif

/**
 * Private function to generate required private keys and certificates.
 *
 * @param pair_record a #PLIST_DICT that will be filled with the keys
 *   and certificates
 * @param public_key the public key to use (device public key)
 *
 * @return 1 if keys were successfully generated, 0 otherwise
 */
userpref_error_t pair_record_generate_keys_and_certs(plist_t pair_record, key_data_t public_key)
{
	userpref_error_t ret = USERPREF_E_SSL_ERROR;

	key_data_t dev_cert_pem = { NULL, 0 };
	key_data_t root_key_pem = { NULL, 0 };
	key_data_t root_cert_pem = { NULL, 0 };
	key_data_t host_key_pem = { NULL, 0 };
	key_data_t host_cert_pem = { NULL, 0 };

	if (!pair_record || !public_key.data)
		return USERPREF_E_INVALID_ARG;

	debug_info("Generating keys and certificates...");

#if defined(HAVE_OPENSSL)
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY* root_pkey = EVP_RSA_gen(2048);
	EVP_PKEY* host_pkey = EVP_RSA_gen(2048);
#else
	BIGNUM *e = BN_new();
	RSA* root_keypair = RSA_new();
	RSA* host_keypair = RSA_new();

	BN_set_word(e, 65537);

	RSA_generate_key_ex(root_keypair, 2048, e, NULL);
	RSA_generate_key_ex(host_keypair, 2048, e, NULL);

	BN_free(e);

	EVP_PKEY* root_pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(root_pkey, root_keypair);

	EVP_PKEY* host_pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(host_pkey, host_keypair);
#endif

	/* generate root certificate */
	X509* root_cert = X509_new();
	{
		/* set serial number */
		ASN1_INTEGER* sn = ASN1_INTEGER_new();
		ASN1_INTEGER_set(sn, 0);
		X509_set_serialNumber(root_cert, sn);
		ASN1_INTEGER_free(sn);

		/* set version */
		X509_set_version(root_cert, 2);

		/* set x509v3 basic constraints */
		X509_add_ext_helper(root_cert, NID_basic_constraints, (char*)"critical,CA:TRUE");

		/* set key validity */
		ASN1_TIME* asn1time = ASN1_TIME_new();
		ASN1_TIME_set(asn1time, time(NULL));
		X509_set1_notBefore(root_cert, asn1time);
		ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * 365 * 10));
		X509_set1_notAfter(root_cert, asn1time);
		ASN1_TIME_free(asn1time);

		/* use root public key for root cert */
		X509_set_pubkey(root_cert, root_pkey);

		/* sign root cert with root private key */
		X509_sign(root_cert, root_pkey, EVP_sha1());
	}

	/* create host certificate */
	X509* host_cert = X509_new();
	{
		/* set serial number */
		ASN1_INTEGER* sn = ASN1_INTEGER_new();
		ASN1_INTEGER_set(sn, 0);
		X509_set_serialNumber(host_cert, sn);
		ASN1_INTEGER_free(sn);

		/* set version */
		X509_set_version(host_cert, 2);

		/* set x509v3 basic constraints */
		X509_add_ext_helper(host_cert, NID_basic_constraints, (char*)"critical,CA:FALSE");

		/* set x509v3 key usage */
		X509_add_ext_helper(host_cert, NID_key_usage, (char*)"critical,digitalSignature,keyEncipherment");

		/* set key validity */
		ASN1_TIME* asn1time = ASN1_TIME_new();
		ASN1_TIME_set(asn1time, time(NULL));
		X509_set1_notBefore(host_cert, asn1time);
		ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * 365 * 10));
		X509_set1_notAfter(host_cert, asn1time);
		ASN1_TIME_free(asn1time);

		/* use host public key for host cert */
		X509_set_pubkey(host_cert, host_pkey);

		/* sign host cert with root private key */
		X509_sign(host_cert, root_pkey, EVP_sha1());
	}

	if (root_cert && root_pkey && host_cert && host_pkey) {
		BIO* membp;
		char *bdata;

		membp = BIO_new(BIO_s_mem());
		if (PEM_write_bio_X509(membp, root_cert) > 0) {
			root_cert_pem.size = BIO_get_mem_data(membp, &bdata);
			root_cert_pem.data = (unsigned char*)malloc(root_cert_pem.size);
			if (root_cert_pem.data) {
				memcpy(root_cert_pem.data, bdata, root_cert_pem.size);
			}
			BIO_free(membp);
			membp = NULL;
		}
		membp = BIO_new(BIO_s_mem());
		if (PEM_write_bio_PrivateKey(membp, root_pkey, NULL, NULL, 0, 0, NULL) > 0) {
			root_key_pem.size = BIO_get_mem_data(membp, &bdata);
			root_key_pem.data = (unsigned char*)malloc(root_key_pem.size);
			if (root_key_pem.data) {
				memcpy(root_key_pem.data, bdata, root_key_pem.size);
			}
			BIO_free(membp);
			membp = NULL;
		}
		membp = BIO_new(BIO_s_mem());
		if (PEM_write_bio_X509(membp, host_cert) > 0) {
			host_cert_pem.size = BIO_get_mem_data(membp, &bdata);
			host_cert_pem.data = (unsigned char*)malloc(host_cert_pem.size);
			if (host_cert_pem.data) {
				memcpy(host_cert_pem.data, bdata, host_cert_pem.size);
			}
			BIO_free(membp);
			membp = NULL;
		}
		membp = BIO_new(BIO_s_mem());
		if (PEM_write_bio_PrivateKey(membp, host_pkey, NULL, NULL, 0, 0, NULL) > 0) {
			host_key_pem.size = BIO_get_mem_data(membp, &bdata);
			host_key_pem.data = (unsigned char*)malloc(host_key_pem.size);
			if (host_key_pem.data) {
				memcpy(host_key_pem.data, bdata, host_key_pem.size);
			}
			BIO_free(membp);
			membp = NULL;
		}
	}

	EVP_PKEY *pubkey = NULL;
	{
		BIO *membp = BIO_new_mem_buf(public_key.data, public_key.size);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		if (!PEM_read_bio_PUBKEY(membp, &pubkey, NULL, NULL)) {
			debug_info("WARNING: Could not read public key");
		}
#else
		RSA *rsa_pubkey = NULL;
		if (!PEM_read_bio_RSAPublicKey(membp, &rsa_pubkey, NULL, NULL)) {
			debug_info("WARNING: Could not read public key");
		} else {
			pubkey = EVP_PKEY_new();
			EVP_PKEY_assign_RSA(pubkey, rsa_pubkey);
		}
#endif
		BIO_free(membp);
	}

	X509* dev_cert = X509_new();
	if (pubkey && dev_cert) {
		/* generate device certificate */
		ASN1_INTEGER* sn = ASN1_INTEGER_new();
		ASN1_INTEGER_set(sn, 0);
		X509_set_serialNumber(dev_cert, sn);
		ASN1_INTEGER_free(sn);
		X509_set_version(dev_cert, 2);

		X509_add_ext_helper(dev_cert, NID_basic_constraints, (char*)"critical,CA:FALSE");

		ASN1_TIME* asn1time = ASN1_TIME_new();
		ASN1_TIME_set(asn1time, time(NULL));
		X509_set1_notBefore(dev_cert, asn1time);
		ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * 365 * 10));
		X509_set1_notAfter(dev_cert, asn1time);
		ASN1_TIME_free(asn1time);

		X509_set_pubkey(dev_cert, pubkey);

		X509_add_ext_helper(dev_cert, NID_subject_key_identifier, (char*)"hash");
		X509_add_ext_helper(dev_cert, NID_key_usage, (char*)"critical,digitalSignature,keyEncipherment");

		/* sign device certificate with root private key */
		if (X509_sign(dev_cert, root_pkey, EVP_sha1())) {
			/* if signing succeeded, export in PEM format */
			BIO* membp = BIO_new(BIO_s_mem());
			if (PEM_write_bio_X509(membp, dev_cert) > 0) {
				char *bdata = NULL;
				dev_cert_pem.size = BIO_get_mem_data(membp, &bdata);
				dev_cert_pem.data = (unsigned char*)malloc(dev_cert_pem.size);
				if (dev_cert_pem.data) {
					memcpy(dev_cert_pem.data, bdata, dev_cert_pem.size);
				}
				BIO_free(membp);
				membp = NULL;
			}
		} else {
			debug_info("ERROR: Signing device certificate with root private key failed!");
		}
	}

	X509_free(dev_cert);

	EVP_PKEY_free(pubkey);
	EVP_PKEY_free(root_pkey);
	EVP_PKEY_free(host_pkey);

	X509_free(host_cert);
	X509_free(root_cert);
#elif defined(HAVE_GNUTLS)
	gnutls_x509_privkey_t root_privkey;
	gnutls_x509_crt_t root_cert;
	gnutls_x509_privkey_t host_privkey;
	gnutls_x509_crt_t host_cert;

	/* use less secure random to speed up key generation */
	gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM);

	gnutls_x509_privkey_init(&root_privkey);
	gnutls_x509_privkey_init(&host_privkey);

	gnutls_x509_crt_init(&root_cert);
	gnutls_x509_crt_init(&host_cert);

	/* generate root key */
	gnutls_x509_privkey_generate(root_privkey, GNUTLS_PK_RSA, 2048, 0);
	gnutls_x509_privkey_generate(host_privkey, GNUTLS_PK_RSA, 2048, 0);

	/* generate certificates */
	gnutls_x509_crt_set_key(root_cert, root_privkey);
	gnutls_x509_crt_set_serial(root_cert, "\x01", 1);
	gnutls_x509_crt_set_version(root_cert, 3);
	gnutls_x509_crt_set_ca_status(root_cert, 1);
	gnutls_x509_crt_set_activation_time(root_cert, time(NULL));
	gnutls_x509_crt_set_expiration_time(root_cert, time(NULL) + (60 * 60 * 24 * 365 * 10));
	gnutls_x509_crt_sign2(root_cert, root_cert, root_privkey, GNUTLS_DIG_SHA1, 0);

	gnutls_x509_crt_set_key(host_cert, host_privkey);
	gnutls_x509_crt_set_serial(host_cert, "\x01", 1);
	gnutls_x509_crt_set_version(host_cert, 3);
	gnutls_x509_crt_set_ca_status(host_cert, 0);
	gnutls_x509_crt_set_key_usage(host_cert, GNUTLS_KEY_KEY_ENCIPHERMENT | GNUTLS_KEY_DIGITAL_SIGNATURE);
	gnutls_x509_crt_set_activation_time(host_cert, time(NULL));
	gnutls_x509_crt_set_expiration_time(host_cert, time(NULL) + (60 * 60 * 24 * 365 * 10));
	gnutls_x509_crt_sign2(host_cert, root_cert, root_privkey, GNUTLS_DIG_SHA1, 0);

	/* export to PEM format */
	size_t root_key_export_size = 0;
	size_t host_key_export_size = 0;

	gnutls_x509_privkey_export(root_privkey, GNUTLS_X509_FMT_PEM, NULL, &root_key_export_size);
	gnutls_x509_privkey_export(host_privkey, GNUTLS_X509_FMT_PEM, NULL, &host_key_export_size);

	root_key_pem.data = gnutls_malloc(root_key_export_size);
	host_key_pem.data = gnutls_malloc(host_key_export_size);

	gnutls_x509_privkey_export(root_privkey, GNUTLS_X509_FMT_PEM, root_key_pem.data, &root_key_export_size);
	root_key_pem.size = root_key_export_size;
	gnutls_x509_privkey_export(host_privkey, GNUTLS_X509_FMT_PEM, host_key_pem.data, &host_key_export_size);
	host_key_pem.size = host_key_export_size;

	size_t root_cert_export_size = 0;
	size_t host_cert_export_size = 0;

	gnutls_x509_crt_export(root_cert, GNUTLS_X509_FMT_PEM, NULL, &root_cert_export_size);
	gnutls_x509_crt_export(host_cert, GNUTLS_X509_FMT_PEM, NULL, &host_cert_export_size);

	root_cert_pem.data = gnutls_malloc(root_cert_export_size);
	host_cert_pem.data = gnutls_malloc(host_cert_export_size);

	gnutls_x509_crt_export(root_cert, GNUTLS_X509_FMT_PEM, root_cert_pem.data, &root_cert_export_size);
	root_cert_pem.size = root_cert_export_size;
	gnutls_x509_crt_export(host_cert, GNUTLS_X509_FMT_PEM, host_cert_pem.data, &host_cert_export_size);
	host_cert_pem.size = host_cert_export_size;

	gnutls_datum_t modulus = { NULL, 0 };
	gnutls_datum_t exponent = { NULL, 0 };

	/* now decode the PEM encoded key */
	gnutls_datum_t der_pub_key = { NULL, 0 };
	int gnutls_error = gnutls_pem_base64_decode_alloc("RSA PUBLIC KEY", &public_key, &der_pub_key);
	if (GNUTLS_E_SUCCESS == gnutls_error) {
		/* initalize asn.1 parser */
		ASN1_TYPE pkcs1 = ASN1_TYPE_EMPTY;
		if (ASN1_SUCCESS == asn1_array2tree(pkcs1_asn1_tab, &pkcs1, NULL)) {

			ASN1_TYPE asn1_pub_key = ASN1_TYPE_EMPTY;
			asn1_create_element(pkcs1, "PKCS1.RSAPublicKey", &asn1_pub_key);

			if (ASN1_SUCCESS == asn1_der_decoding(&asn1_pub_key, der_pub_key.data, der_pub_key.size, NULL)) {

				/* get size to read */
				int ret1 = asn1_read_value(asn1_pub_key, "modulus", NULL, (int*)&modulus.size);
				int ret2 = asn1_read_value(asn1_pub_key, "publicExponent", NULL, (int*)&exponent.size);

				modulus.data = gnutls_malloc(modulus.size);
				exponent.data = gnutls_malloc(exponent.size);

				ret1 = asn1_read_value(asn1_pub_key, "modulus", modulus.data, (int*)&modulus.size);
				ret2 = asn1_read_value(asn1_pub_key, "publicExponent", exponent.data, (int*)&exponent.size);
				if (ret1 != ASN1_SUCCESS || ret2 != ASN1_SUCCESS) {
					gnutls_free(modulus.data);
					modulus.data = NULL;
					modulus.size = 0;
					gnutls_free(exponent.data);
					exponent.data = NULL;
					exponent.size = 0;
				}
			}
			if (asn1_pub_key)
				asn1_delete_structure(&asn1_pub_key);
		}
		if (pkcs1)
			asn1_delete_structure(&pkcs1);
	} else {
		debug_info("ERROR: Could not parse public key: %s", gnutls_strerror(gnutls_error));
	}

	/* generate device certificate */
	if (modulus.data && 0 != modulus.size && exponent.data && 0 != exponent.size) {

		gnutls_datum_t prime_p = { (unsigned char*)"\x00\xca\x4a\x03\x13\xdf\x9d\x7a\xfd", 9 };
		gnutls_datum_t prime_q = { (unsigned char*)"\x00\xf2\xff\xe0\x15\xd1\x60\x37\x63", 9 };
		gnutls_datum_t coeff = { (unsigned char*)"\x32\x07\xf1\x68\x57\xdf\x9a\xf4", 8 };

		gnutls_x509_privkey_t fake_privkey;
		gnutls_x509_crt_t dev_cert;

		gnutls_x509_privkey_init(&fake_privkey);
		gnutls_x509_crt_init(&dev_cert);

		gnutls_error = gnutls_x509_privkey_import_rsa_raw(fake_privkey, &modulus, &exponent, &exponent, &prime_p, &prime_q, &coeff);
		if (GNUTLS_E_SUCCESS == gnutls_error) {
			/* now generate device certificate */
			gnutls_x509_crt_set_key(dev_cert, fake_privkey);
			gnutls_x509_crt_set_serial(dev_cert, "\x01", 1);
			gnutls_x509_crt_set_version(dev_cert, 3);
			gnutls_x509_crt_set_ca_status(dev_cert, 0);
			gnutls_x509_crt_set_activation_time(dev_cert, time(NULL));
			gnutls_x509_crt_set_expiration_time(dev_cert, time(NULL) + (60 * 60 * 24 * 365 * 10));

			/* use custom hash generation for compatibility with the "Apple ecosystem" */
			const gnutls_digest_algorithm_t dig_sha1 = GNUTLS_DIG_SHA1;
			size_t hash_size = gnutls_hash_get_len(dig_sha1);
			unsigned char hash[hash_size];
			if (gnutls_hash_fast(dig_sha1, der_pub_key.data, der_pub_key.size, (unsigned char*)&hash) < 0) {
				debug_info("ERROR: Failed to generate SHA1 for public key");
			} else {
				gnutls_x509_crt_set_subject_key_id(dev_cert, hash, hash_size);
			}

			gnutls_x509_crt_set_key_usage(dev_cert, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT);
			gnutls_error = gnutls_x509_crt_sign2(dev_cert, root_cert, root_privkey, GNUTLS_DIG_SHA1, 0);
			if (GNUTLS_E_SUCCESS == gnutls_error) {
				/* if everything went well, export in PEM format */
				size_t export_size = 0;
				gnutls_x509_crt_export(dev_cert, GNUTLS_X509_FMT_PEM, NULL, &export_size);
				dev_cert_pem.data = gnutls_malloc(export_size);
				gnutls_x509_crt_export(dev_cert, GNUTLS_X509_FMT_PEM, dev_cert_pem.data, &export_size);
				dev_cert_pem.size = export_size;
			} else {
				debug_info("ERROR: Signing device certificate with root private key failed: %s", gnutls_strerror(gnutls_error));
			}
		} else {
			debug_info("ERROR: Failed to import RSA key data: %s", gnutls_strerror(gnutls_error));
		}
		gnutls_x509_crt_deinit(dev_cert);
		gnutls_x509_privkey_deinit(fake_privkey);
	}

	gnutls_x509_crt_deinit(root_cert);
	gnutls_x509_crt_deinit(host_cert);
	gnutls_x509_privkey_deinit(root_privkey);
	gnutls_x509_privkey_deinit(host_privkey);

	gnutls_free(modulus.data);
	gnutls_free(exponent.data);

	gnutls_free(der_pub_key.data);
#elif defined(HAVE_MBEDTLS)
	time_t now = time(NULL);
	struct tm* timestamp = gmtime(&now);
	char notbefore[16];
	strftime(notbefore, sizeof(notbefore), "%Y%m%d%H%M%S", timestamp);
	time_t then = now + 60 * 60 * 24 * 365 * 10;
	char notafter[16];
	timestamp = gmtime(&then);
	strftime(notafter, sizeof(notafter), "%Y%m%d%H%M%S", timestamp);

	mbedtls_mpi sn;
	mbedtls_mpi_init(&sn);
	mbedtls_mpi_lset(&sn, 1); /* 0 doesn't work, so we have to use 1 (like GnuTLS) */

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_pk_context root_pkey;
	mbedtls_pk_init(&root_pkey);

	mbedtls_pk_context host_pkey;
	mbedtls_pk_init(&host_pkey);

	mbedtls_pk_context dev_public_key;
	mbedtls_pk_init(&dev_public_key);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"limd", 4);

	/* ----- root key & cert ----- */
	ret = mbedtls_pk_setup(&root_pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	if (ret != 0) {
		debug_info("mbedtls_pk_setup returned -0x%04x", -ret);
		goto cleanup;
	}

	ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(root_pkey), mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
	if (ret != 0) {
		debug_info("mbedtls_rsa_gen_key returned -0x%04x", -ret);
		goto cleanup;
	}

	mbedtls_x509write_cert cert;
	mbedtls_x509write_crt_init(&cert);

	/* set serial number */
	mbedtls_x509write_crt_set_serial(&cert, &sn);

	/* set version */
	mbedtls_x509write_crt_set_version(&cert, 2);

	/* set x509v3 basic constraints */
	_mbedtls_x509write_crt_set_basic_constraints_critical(&cert, 1, -1);

	/* use root public key for root cert */
	mbedtls_x509write_crt_set_subject_key(&cert, &root_pkey);

	/* set x509v3 subject key identifier */
	mbedtls_x509write_crt_set_subject_key_identifier(&cert);

	/* set key validity */
	mbedtls_x509write_crt_set_validity(&cert, notbefore, notafter);

	/* sign root cert with root private key */
	mbedtls_x509write_crt_set_issuer_key(&cert, &root_pkey);
	mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA1);

	unsigned char outbuf[16384];

	/* write root private key */
	mbedtls_pk_write_key_pem(&root_pkey, outbuf, sizeof(outbuf));
	root_key_pem.size = strlen((const char*)outbuf);
	root_key_pem.data = malloc(root_key_pem.size+1);
	memcpy(root_key_pem.data, outbuf, root_key_pem.size);
	root_key_pem.data[root_key_pem.size] = '\0';

	/* write root certificate */
	mbedtls_x509write_crt_pem(&cert, outbuf, sizeof(outbuf), mbedtls_ctr_drbg_random, &ctr_drbg);
	root_cert_pem.size = strlen((const char*)outbuf);
	root_cert_pem.data = malloc(root_cert_pem.size+1);
	memcpy(root_cert_pem.data, outbuf, root_cert_pem.size);
	root_cert_pem.data[root_cert_pem.size] = '\0';

	mbedtls_x509write_crt_free(&cert);


	/* ----- host key & cert ----- */
	ret = mbedtls_pk_setup(&host_pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	if (ret != 0) {
		debug_info("mbedtls_pk_setup returned -0x%04x", -ret);
		goto cleanup;
	}

	ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(host_pkey), mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
	if (ret != 0) {
		debug_info("mbedtls_rsa_gen_key returned -0x%04x", -ret);
		goto cleanup;
	}

	mbedtls_x509write_crt_init(&cert);

	/* set serial number */
	mbedtls_x509write_crt_set_serial(&cert, &sn);

	/* set version */
	mbedtls_x509write_crt_set_version(&cert, 2);

	/* set x509v3 basic constraints */
	_mbedtls_x509write_crt_set_basic_constraints_critical(&cert, 0, -1);

	/* use host public key for host cert */
	mbedtls_x509write_crt_set_subject_key(&cert, &host_pkey);

	/* set x509v3 subject key identifier */
	mbedtls_x509write_crt_set_subject_key_identifier(&cert);

	/* set x509v3 key usage */
	mbedtls_x509write_crt_set_key_usage(&cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);

	/* set key validity */
	mbedtls_x509write_crt_set_validity(&cert, notbefore, notafter);

	/* sign host cert with root private key */
	mbedtls_x509write_crt_set_issuer_key(&cert, &root_pkey);
	mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA1);

	/* write host private key */
	mbedtls_pk_write_key_pem(&host_pkey, outbuf, sizeof(outbuf));
	host_key_pem.size = strlen((const char*)outbuf);
	host_key_pem.data = malloc(host_key_pem.size+1);
	memcpy(host_key_pem.data, outbuf, host_key_pem.size);
	host_key_pem.data[host_key_pem.size] = '\0';

	/* write host certificate */
	mbedtls_x509write_crt_pem(&cert, outbuf, sizeof(outbuf), mbedtls_ctr_drbg_random, &ctr_drbg);
	host_cert_pem.size = strlen((const char*)outbuf);
	host_cert_pem.data = malloc(host_cert_pem.size+1);
	memcpy(host_cert_pem.data, outbuf, host_cert_pem.size);
	host_cert_pem.data[host_cert_pem.size] = '\0';

	mbedtls_x509write_crt_free(&cert);


	/* ----- device certificate ----- */
	unsigned char* pubkey_data = malloc(public_key.size+1);
	if (!pubkey_data) {
		debug_info("malloc() failed\n");
		goto cleanup;
	}
	memcpy(pubkey_data, public_key.data, public_key.size);
	pubkey_data[public_key.size] = '\0';

	int pr = mbedtls_pk_parse_public_key(&dev_public_key, pubkey_data, public_key.size+1);
	free(pubkey_data);
	if (pr != 0) {
		debug_info("Failed to read device public key: -0x%x\n", -pr);
		goto cleanup;
	}

	mbedtls_x509write_crt_init(&cert);

	/* set serial number */
	mbedtls_x509write_crt_set_serial(&cert, &sn);

	/* set version */
	mbedtls_x509write_crt_set_version(&cert, 2);

	/* set x509v3 basic constraints */
	_mbedtls_x509write_crt_set_basic_constraints_critical(&cert, 0, -1);

	/* use root public key for dev cert subject key */
	mbedtls_x509write_crt_set_subject_key(&cert, &dev_public_key);

	/* set x509v3 subject key identifier */
	mbedtls_x509write_crt_set_subject_key_identifier(&cert);

	/* set x509v3 key usage */
	mbedtls_x509write_crt_set_key_usage(&cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);

	/* set key validity */
	mbedtls_x509write_crt_set_validity(&cert, notbefore, notafter);

	/* sign device certificate with root private key */
	mbedtls_x509write_crt_set_issuer_key(&cert, &root_pkey);
	mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA1);

	/* write device certificate */
	mbedtls_x509write_crt_pem(&cert, outbuf, sizeof(outbuf), mbedtls_ctr_drbg_random, &ctr_drbg);
	dev_cert_pem.size = strlen((const char*)outbuf);
	dev_cert_pem.data = malloc(dev_cert_pem.size+1);
	memcpy(dev_cert_pem.data, outbuf, dev_cert_pem.size);
	dev_cert_pem.data[dev_cert_pem.size] = '\0';

	mbedtls_x509write_crt_free(&cert);

	/* cleanup */
cleanup:
	mbedtls_mpi_free(&sn);
	mbedtls_pk_free(&dev_public_key);
	mbedtls_entropy_free(&entropy);
	mbedtls_pk_free(&host_pkey);
	mbedtls_pk_free(&root_pkey);
	mbedtls_ctr_drbg_free(&ctr_drbg);
#endif

	/* make sure that we have all we need */
	if (root_cert_pem.data && 0 != root_cert_pem.size
	    && root_key_pem.data && 0 != root_key_pem.size
	    && host_cert_pem.data && 0 != host_cert_pem.size
	    && host_key_pem.data && 0 != host_key_pem.size
	    && dev_cert_pem.data && 0 != dev_cert_pem.size) {
		/* now set keys and certificates */
		pair_record_set_item_from_key_data(pair_record, USERPREF_DEVICE_CERTIFICATE_KEY, &dev_cert_pem);
		pair_record_set_item_from_key_data(pair_record, USERPREF_HOST_PRIVATE_KEY_KEY, &host_key_pem);
		pair_record_set_item_from_key_data(pair_record, USERPREF_HOST_CERTIFICATE_KEY, &host_cert_pem);
		pair_record_set_item_from_key_data(pair_record, USERPREF_ROOT_PRIVATE_KEY_KEY, &root_key_pem);
		pair_record_set_item_from_key_data(pair_record, USERPREF_ROOT_CERTIFICATE_KEY, &root_cert_pem);
		ret = USERPREF_E_SUCCESS;
	}

	free(dev_cert_pem.data);
	free(root_key_pem.data);
	free(root_cert_pem.data);
	free(host_key_pem.data);
	free(host_cert_pem.data);

	return ret;
}

/**
 * Private function which import the given key into a gnutls structure.
 *
 * @param name The name of the private key to import.
 * @param key the gnutls key structure.
 *
 * @return 1 if the key was successfully imported.
 */
#if defined(HAVE_OPENSSL) || defined(HAVE_MBEDTLS)
userpref_error_t pair_record_import_key_with_name(plist_t pair_record, const char* name, key_data_t* key)
#elif defined(HAVE_GNUTLS)
userpref_error_t pair_record_import_key_with_name(plist_t pair_record, const char* name, gnutls_x509_privkey_t key)
#endif
{
#if defined(HAVE_OPENSSL) || defined(HAVE_MBEDTLS)
	if (!key)
		return USERPREF_E_SUCCESS;
#endif
	userpref_error_t ret = USERPREF_E_INVALID_CONF;

#if defined(HAVE_OPENSSL) || defined(HAVE_MBEDTLS)
	ret = pair_record_get_item_as_key_data(pair_record, name, key);
#elif defined(HAVE_GNUTLS)
	key_data_t pem = { NULL, 0 };
	ret = pair_record_get_item_as_key_data(pair_record, name, &pem);
	if (ret == USERPREF_E_SUCCESS && GNUTLS_E_SUCCESS == gnutls_x509_privkey_import(key, &pem, GNUTLS_X509_FMT_PEM))
		ret = USERPREF_E_SUCCESS;
	else
		ret = USERPREF_E_SSL_ERROR;

	if (pem.data)
		free(pem.data);
#endif
	return ret;
}

/**
 * Private function which import the given certificate into a gnutls structure.
 *
 * @param name The name of the certificate to import.
 * @param cert the gnutls certificate structure.
 *
 * @return IDEVICE_E_SUCCESS if the certificate was successfully imported.
 */
#if defined(HAVE_OPENSSL) || defined(HAVE_MBEDTLS)
userpref_error_t pair_record_import_crt_with_name(plist_t pair_record, const char* name, key_data_t* cert)
#else
userpref_error_t pair_record_import_crt_with_name(plist_t pair_record, const char* name, gnutls_x509_crt_t cert)
#endif
{
#if defined(HAVE_OPENSSL) || defined(HAVE_MBEDTLS)
	if (!cert)
		return USERPREF_E_SUCCESS;
#endif
	userpref_error_t ret = USERPREF_E_INVALID_CONF;

#if defined(HAVE_OPENSSL) || defined(HAVE_MBEDTLS)
	ret = pair_record_get_item_as_key_data(pair_record, name, cert);
#elif defined(HAVE_GNUTLS)
	key_data_t pem = { NULL, 0 };
	ret = pair_record_get_item_as_key_data(pair_record, name, &pem);
	if (ret == USERPREF_E_SUCCESS && GNUTLS_E_SUCCESS == gnutls_x509_crt_import(cert, &pem, GNUTLS_X509_FMT_PEM))
		ret = USERPREF_E_SUCCESS;
	else
		ret = USERPREF_E_SSL_ERROR;

	if (pem.data)
		free(pem.data);
#endif
	return ret;
}

userpref_error_t pair_record_get_host_id(plist_t pair_record, char** host_id)
{
	plist_t node = plist_dict_get_item(pair_record, USERPREF_HOST_ID_KEY);

	if (node && plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, host_id);
	}

	return USERPREF_E_SUCCESS;
}

userpref_error_t pair_record_set_host_id(plist_t pair_record, const char* host_id)
{
	plist_dict_set_item(pair_record, USERPREF_HOST_ID_KEY, plist_new_string(host_id));

	return USERPREF_E_SUCCESS;
}

userpref_error_t pair_record_get_item_as_key_data(plist_t pair_record, const char* name, key_data_t *value)
{
	if (!pair_record || !value)
		return USERPREF_E_INVALID_ARG;

	userpref_error_t ret = USERPREF_E_SUCCESS;
	char* buffer = NULL;
	uint64_t length = 0;

	plist_t node = plist_dict_get_item(pair_record, name);

	if (node && plist_get_node_type(node) == PLIST_DATA) {
		plist_get_data_val(node, &buffer, &length);
		value->data = (unsigned char*)malloc(length+1);
		memcpy(value->data, buffer, length);
		value->data[length] = '\0';
		value->size = length+1;
		free(buffer);
		buffer = NULL;
	} else {
		ret = USERPREF_E_INVALID_CONF;
	}

	if (buffer)
		free(buffer);

	return ret;
}

userpref_error_t pair_record_set_item_from_key_data(plist_t pair_record, const char* name, key_data_t *value)
{
	userpref_error_t ret = USERPREF_E_SUCCESS;

	if (!pair_record || !value) {
		return USERPREF_E_INVALID_ARG;
	}

	/* set new item */
	plist_dict_set_item(pair_record, name, plist_new_data((char*)value->data, value->size));

	return ret;
}

