/*
 * userpref.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifndef WIN32
#include <pwd.h>
#endif
#include <unistd.h>
#include <usbmuxd.h>
#ifdef HAVE_OPENSSL
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#else
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gcrypt.h>
#include <libtasn1.h>
#endif

#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef WIN32
#include <shlobj.h>
#endif

#include "userpref.h"
#include "debug.h"
#include "utils.h"

#ifndef HAVE_OPENSSL
const ASN1_ARRAY_TYPE pkcs1_asn1_tab[] = {
	{"PKCS1", 536872976, 0},
	{0, 1073741836, 0},
	{"RSAPublicKey", 536870917, 0},
	{"modulus", 1073741827, 0},
	{"publicExponent", 3, 0},
	{0, 0, 0}
};
#endif

#ifdef WIN32
#define DIR_SEP '\\'
#define DIR_SEP_S "\\"
#else
#define DIR_SEP '/'
#define DIR_SEP_S "/"
#endif

#define USERPREF_CONFIG_EXTENSION ".plist"

#ifdef WIN32
#define USERPREF_CONFIG_DIR "Apple"DIR_SEP_S"Lockdown"
#else
#define USERPREF_CONFIG_DIR "lockdown"
#endif

#define USERPREF_CONFIG_FILE "SystemConfiguration"USERPREF_CONFIG_EXTENSION

static char *__config_dir = NULL;

#ifdef WIN32
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

#ifdef WIN32
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
 * Reads the BUID from a previously generated configuration file.
 *
 * @note It is the responsibility of the calling function to free the returned system_buid
 * @param system_buid A null terminated string containing a valid SystemBUID.
 * @return 1 if the system buid could be retrieved or 0 otherwise.
 */
int userpref_read_system_buid(char **system_buid)
{
	int res = usbmuxd_read_buid(system_buid);

	debug_info("using %s as %s", *system_buid, USERPREF_SYSTEM_BUID_KEY);

	return res;
}

/**
 * Determines whether this device has been connected to this system before.
 *
 * @param udid The device UDID as given by the device.
 *
 * @return 1 if the device has been connected previously to this configuration
 *         or 0 otherwise.
 */
int userpref_has_pair_record(const char *udid)
{
	int ret = 0;
	const char *config_path = NULL;
	char *config_file = NULL;
	struct stat st;

	if (!udid) return 0;

	/* first get config file */
	config_path = userpref_get_config_dir();
	config_file = string_concat(config_path, DIR_SEP_S, udid, USERPREF_CONFIG_EXTENSION, NULL);

	if ((stat(config_file, &st) == 0) && S_ISREG(st.st_mode))
		ret = 1;

	free(config_file);

	return ret;
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
	struct slist_t {
		char *name;
		void *next;
	};
	DIR *config_dir;
	const char *config_path = NULL;
	struct slist_t *udids = NULL;
	unsigned int i;
	unsigned int found = 0;

	if (!list || (list && *list)) {
		debug_info("ERROR: The list parameter needs to point to NULL!");
		return USERPREF_E_INVALID_ARG;
	}

	if (count) {
		*count = 0;
	}

	config_path = userpref_get_config_dir();
	config_dir = opendir(config_path);
	if (config_dir) {
		struct dirent *entry;
		struct slist_t *listp = udids;
		while ((entry = readdir(config_dir))) {
			char *ext = strstr(entry->d_name, USERPREF_CONFIG_EXTENSION);
			if (ext && ((ext - entry->d_name) == 40) && (strlen(entry->d_name) == (40 + strlen(ext)))) {
				struct slist_t *ne = (struct slist_t*)malloc(sizeof(struct slist_t));
				ne->name = (char*)malloc(41);
				strncpy(ne->name, entry->d_name, 40);
				ne->name[40] = 0;
				ne->next = NULL;
				if (!listp) {
					listp = ne;
					udids = listp;
				} else {
					listp->next = ne;
					listp = listp->next;
				}
				found++;
			}
		}
		closedir(config_dir);
	}
	*list = (char**)malloc(sizeof(char*) * (found+1));
	i = 0;
	while (udids) {
		(*list)[i++] = udids->name;
		struct slist_t *old = udids;
		udids = udids->next;
		free(old);
	}
	(*list)[i] = NULL;

	if (count) {
		*count = found;
	}

	return USERPREF_E_SUCCESS;
}

/**
 * Save a pair record for a device.
 *
 * @param udid The device UDID as given by the device
 * @param pair_record The pair record to save
 *
 * @return 1 on success and 0 if no device record is given or if it has already
 *         been saved previously.
 */
userpref_error_t userpref_save_pair_record(const char *udid, plist_t pair_record)
{
	char* record_data = NULL;
	uint32_t record_size = 0;

	plist_to_bin(pair_record, &record_data, &record_size);

	int res = usbmuxd_save_pair_record(udid, record_data, record_size);

	free(record_data);

	return res == 0 ? USERPREF_E_SUCCESS: USERPREF_E_UNKNOWN_ERROR;
}

/**
 * Read a pair record for a device.
 *
 * @param udid The device UDID as given by the device
 * @param pair_record The pair record to read
 *
 * @return 1 on success and 0 if no device record is given or if it has already
 *         been saved previously.
 */
userpref_error_t userpref_read_pair_record(const char *udid, plist_t *pair_record)
{
	char* record_data = NULL;
	uint32_t record_size = 0;

	int res = usbmuxd_read_pair_record(udid, &record_data, &record_size);

	if (res < 0) {
		if (record_data)
			free(record_data);

		return USERPREF_E_INVALID_CONF;
	}

	*pair_record = NULL;
	if (memcmp(record_data, "bplist00", 8) == 0) {
		plist_from_bin(record_data, record_size, pair_record);
	} else {
		plist_from_xml(record_data, record_size, pair_record);
	}

	free(record_data);

	return res == 0 ? USERPREF_E_SUCCESS: USERPREF_E_UNKNOWN_ERROR;
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

#ifdef HAVE_OPENSSL
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

#ifdef HAVE_OPENSSL
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
		X509_set_notBefore(root_cert, asn1time);
		ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * 365 * 10));
		X509_set_notAfter(root_cert, asn1time);
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
		X509_set_notBefore(host_cert, asn1time);
		ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * 365 * 10));
		X509_set_notAfter(host_cert, asn1time);
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

	RSA *pubkey = NULL;
	{
		BIO *membp = BIO_new_mem_buf(public_key.data, public_key.size);
		if (!PEM_read_bio_RSAPublicKey(membp, &pubkey, NULL, NULL)) {
			debug_info("WARNING: Could not read public key");
		}
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
		X509_set_notBefore(dev_cert, asn1time);
		ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * 365 * 10));
		X509_set_notAfter(dev_cert, asn1time);
		ASN1_TIME_free(asn1time);

		EVP_PKEY* pkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(pkey, pubkey);
		X509_set_pubkey(dev_cert, pkey);
		EVP_PKEY_free(pkey);

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

	X509V3_EXT_cleanup();
	X509_free(dev_cert);

	EVP_PKEY_free(root_pkey);
	EVP_PKEY_free(host_pkey);

	X509_free(host_cert);
	X509_free(root_cert);
#else
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
	gnutls_x509_crt_set_serial(root_cert, "\x00", 1);
	gnutls_x509_crt_set_version(root_cert, 3);
	gnutls_x509_crt_set_ca_status(root_cert, 1);
	gnutls_x509_crt_set_activation_time(root_cert, time(NULL));
	gnutls_x509_crt_set_expiration_time(root_cert, time(NULL) + (60 * 60 * 24 * 365 * 10));
	gnutls_x509_crt_sign(root_cert, root_cert, root_privkey);

	gnutls_x509_crt_set_key(host_cert, host_privkey);
	gnutls_x509_crt_set_serial(host_cert, "\x00", 1);
	gnutls_x509_crt_set_version(host_cert, 3);
	gnutls_x509_crt_set_ca_status(host_cert, 0);
	gnutls_x509_crt_set_key_usage(host_cert, GNUTLS_KEY_KEY_ENCIPHERMENT | GNUTLS_KEY_DIGITAL_SIGNATURE);
	gnutls_x509_crt_set_activation_time(host_cert, time(NULL));
	gnutls_x509_crt_set_expiration_time(host_cert, time(NULL) + (60 * 60 * 24 * 365 * 10));
	gnutls_x509_crt_sign(host_cert, root_cert, root_privkey);

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

	ret = USERPREF_E_UNKNOWN_ERROR;

	gnutls_datum_t modulus = { NULL, 0 };
	gnutls_datum_t exponent = { NULL, 0 };

	/* now decode the PEM encoded key */
	gnutls_datum_t der_pub_key;
	if (GNUTLS_E_SUCCESS == gnutls_pem_base64_decode_alloc("RSA PUBLIC KEY", &public_key, &der_pub_key)) {

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
				if (ASN1_SUCCESS == ret1 && ASN1_SUCCESS == ret2)
					ret = USERPREF_E_SUCCESS;
			}
			if (asn1_pub_key)
				asn1_delete_structure(&asn1_pub_key);
		}
		if (pkcs1)
			asn1_delete_structure(&pkcs1);
	} else {
		debug_info("WARNING: Could not read public key");
	}

	/* now generate certificates */
	if (USERPREF_E_SUCCESS == ret && 0 != modulus.size && 0 != exponent.size) {
		gnutls_datum_t essentially_null = { (unsigned char*)strdup("abababababababab"), strlen("abababababababab") };

		gnutls_x509_privkey_t fake_privkey;
		gnutls_x509_crt_t dev_cert;

		gnutls_x509_privkey_init(&fake_privkey);
		gnutls_x509_crt_init(&dev_cert);

		if (GNUTLS_E_SUCCESS == gnutls_x509_privkey_import_rsa_raw(fake_privkey, &modulus, &exponent, &essentially_null, &essentially_null, &essentially_null, &essentially_null)) {
			/* generate device certificate */
			gnutls_x509_crt_set_key(dev_cert, fake_privkey);
			gnutls_x509_crt_set_serial(dev_cert, "\x00", 1);
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
			gnutls_x509_crt_sign(dev_cert, root_cert, root_privkey);

			if (USERPREF_E_SUCCESS == ret) {
				/* if everything went well, export in PEM format */
				size_t export_size = 0;
				gnutls_x509_crt_export(dev_cert, GNUTLS_X509_FMT_PEM, NULL, &export_size);
				dev_cert_pem.data = gnutls_malloc(export_size);
				gnutls_x509_crt_export(dev_cert, GNUTLS_X509_FMT_PEM, dev_cert_pem.data, &export_size);
				dev_cert_pem.size = export_size;
			} else {
				debug_info("ERROR: Signing device certificate with root private key failed!");
			}
		}

		if (essentially_null.data)
			free(essentially_null.data);

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
#endif
	if (NULL != root_cert_pem.data && 0 != root_cert_pem.size &&
		NULL != host_cert_pem.data && 0 != host_cert_pem.size)
		ret = USERPREF_E_SUCCESS;

	/* now set keys and certificates */
	pair_record_set_item_from_key_data(pair_record, USERPREF_DEVICE_CERTIFICATE_KEY, &dev_cert_pem);
	pair_record_set_item_from_key_data(pair_record, USERPREF_HOST_PRIVATE_KEY_KEY, &host_key_pem);
	pair_record_set_item_from_key_data(pair_record, USERPREF_HOST_CERTIFICATE_KEY, &host_cert_pem);
	pair_record_set_item_from_key_data(pair_record, USERPREF_ROOT_PRIVATE_KEY_KEY, &root_key_pem);
	pair_record_set_item_from_key_data(pair_record, USERPREF_ROOT_CERTIFICATE_KEY, &root_cert_pem);

	if (dev_cert_pem.data)
		free(dev_cert_pem.data);
	if (root_key_pem.data)
		free(root_key_pem.data);
	if (root_cert_pem.data)
		free(root_cert_pem.data);
	if (host_key_pem.data)
		free(host_key_pem.data);
	if (host_cert_pem.data)
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
#ifdef HAVE_OPENSSL
userpref_error_t pair_record_import_key_with_name(plist_t pair_record, const char* name, key_data_t* key)
#else
userpref_error_t pair_record_import_key_with_name(plist_t pair_record, const char* name, gnutls_x509_privkey_t key)
#endif
{
#ifdef HAVE_OPENSSL
	if (!key)
		return USERPREF_E_SUCCESS;
#endif
	userpref_error_t ret = USERPREF_E_INVALID_CONF;

#ifdef HAVE_OPENSSL
		ret = pair_record_get_item_as_key_data(pair_record, name, key);
#else
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
#ifdef HAVE_OPENSSL
userpref_error_t pair_record_import_crt_with_name(plist_t pair_record, const char* name, key_data_t* cert)
#else
userpref_error_t pair_record_import_crt_with_name(plist_t pair_record, const char* name, gnutls_x509_crt_t cert)
#endif
{
#ifdef HAVE_OPENSSL
	if (!cert)
		return USERPREF_E_SUCCESS;
#endif
	userpref_error_t ret = USERPREF_E_INVALID_CONF;

#ifdef HAVE_OPENSSL
		ret = pair_record_get_item_as_key_data(pair_record, name, cert);
#else
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
		value->data = (unsigned char*)malloc(length);
		memcpy(value->data, buffer, length);
		value->size = length;
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

