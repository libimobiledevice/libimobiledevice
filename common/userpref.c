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
#ifdef WIN32
#include <direct.h>
#else
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
#include <gnutls/x509.h>
#include <gcrypt.h>
#endif

#include <dirent.h>
#ifndef WIN32
#include <libgen.h>
#endif
#include <sys/stat.h>
#include <errno.h>

#ifdef WIN32
#include <shlobj.h>
#include <shlwapi.h>
#endif

#include "userpref.h"
#include "debug.h"
#include "utils.h"

#ifdef WIN32
#define DIR_SEP '\\'
#define DIR_SEP_S "\\"
#else
#define DIR_SEP '/'
#define DIR_SEP_S "/"
#endif

#define USERPREF_CONFIG_EXTENSION ".plist"

#ifdef WIN32
	#ifdef USE_APPLE_CONFIG_DIR
		#define USERPREF_CONFIG_DIR "Apple"DIR_SEP_S"Lockdown"
	#else
		#define USERPREF_CONFIG_DIR "Lockdown"
	#endif
#else
	#define USERPREF_CONFIG_DIR "lockdown"
#endif

#define USERPREF_CONFIG_FILE "SystemConfiguration"USERPREF_CONFIG_EXTENSION

/* The path of our local, preconfigured, lockdown config files, which contains 
 * pre-generated keys, certs and ids. */
#define USERPREF_LOCAL_CONFIG_FILE "etc"DIR_SEP_S"LockdownConfiguration"USERPREF_CONFIG_EXTENSION

/* Copy a plist string into a buffer allocated by us (to prevent problems with different heaps) */
#define COPY_PLIST_STRING_VAL(node,val) char * val##_temp = NULL;\
										plist_get_string_val(node, &val##_temp);\
										*val = strdup(val##_temp);\
										plist_free_memory(val##_temp);


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

static int userpref_has_local_config()
{
#ifdef WIN32
	return PathFileExists(USERPREF_LOCAL_CONFIG_FILE);
#endif

	return 0;
}

const char *userpref_get_config_dir()
{
	char *base_config_dir = NULL;

	if (__config_dir)
		return __config_dir;

#ifdef WIN32
	#ifdef USE_APPLE_CONFIG_DIR
		wchar_t path[MAX_PATH+1];
		HRESULT hr;
		LPITEMIDLIST pidl = NULL;
		BOOL b = FALSE;

		hr = SHGetSpecialFolderLocation(NULL, CSIDL_COMMON_APPDATA, &pidl);
		if (hr == S_OK)
		{
			b = SHGetPathFromIDListW(pidl, path);
			if (b)
			{
				base_config_dir = config_utf16_to_utf8(path, wcslen(path), NULL, NULL);
				CoTaskMemFree(pidl);
			}
		}
	#else
		/* Use the currnet user's temp folder as the base dir */
		base_config_dir = (char *)malloc(MAX_PATH + 1);
		GetTempPath(MAX_PATH + 1, base_config_dir);
	#endif
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
		slist_t *next;
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
* Private function which reads a key\cert from a plist
*
* @return 1 if the key\cert was successfully read, 0 otherwise
*/
static int userpref_get_key_from_conf(plist_t conf, const char * name, key_data_t * key)
{
	plist_t value = NULL;
	char * key_data = NULL;
	uint64_t key_size = 0;

	value = plist_dict_get_item(conf, name);
	if (value && (plist_get_node_type(value) == PLIST_DATA)) {
		plist_get_data_val(value, &key_data, &key_size);
		key->data = (unsigned char *)key_data;
		key->size = key_size;

		return 1;
	}

	return 0;
}

/**
* Private function which tries to read the keys and certs from the local config file.
*
* @return 1 if keys\certs were successfully read, 0 otherwise
*/
static int userpref_get_keys_and_cert_from_local_conf(key_data_t * root_key, key_data_t * root_cert, key_data_t * host_key, key_data_t * host_cert)
{
	if (!userpref_has_local_config()) {
		return 0;
	}

	/* Read the local config dir */
	plist_t local_config = NULL;
	if (!plist_read_from_filename(&local_config, USERPREF_LOCAL_CONFIG_FILE)) {
		debug_info("ERROR: Failed to read local config file");
		return USERPREF_E_INVALID_CONF;
	}

	/* Read the keys and certificates from the config file */
	if (userpref_get_key_from_conf(local_config, USERPREF_HOST_PRIVATE_KEY_KEY, host_key) &&
		userpref_get_key_from_conf(local_config, USERPREF_HOST_CERTIFICATE_KEY, host_cert) &&
		userpref_get_key_from_conf(local_config, USERPREF_ROOT_PRIVATE_KEY_KEY, root_key) &&
		userpref_get_key_from_conf(local_config, USERPREF_ROOT_CERTIFICATE_KEY, root_cert))
	{
		plist_free(local_config);
		return 1;
	}

	debug_info("ERROR: Failed to read keys\\cerst from local conf");

	/* We've failed - cleanup */
	plist_free(local_config);
	if (root_key->data) {
		free(root_key->data);
	}
	if (root_cert->data) {
		free(root_cert->data);
	}
	if (host_key->data) {
		free(host_key->data);
	}
	if (host_cert->data) {
		free(host_cert->data);
	}

	return 0;
}

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
	EVP_PKEY* root_pkey = NULL;

	if (!pair_record || !public_key.data)
		return USERPREF_E_INVALID_ARG;

	if (userpref_get_keys_and_cert_from_local_conf(&root_key_pem, &root_cert_pem, &host_key_pem, &host_cert_pem)) {
		debug_info("Using keys and certificates from the local config");

		BIO* membp = BIO_new_mem_buf(root_key_pem.data, root_key_pem.size);
		PEM_read_bio_PrivateKey(membp, &root_pkey, NULL, NULL);
		BIO_free(membp);
	}
	else {
		debug_info("generating keys and certificates");

		BIGNUM *e = BN_new();
		RSA* root_keypair = RSA_new();
		RSA* host_keypair = RSA_new();

		BN_set_word(e, 65537);

		RSA_generate_key_ex(root_keypair, 2048, e, NULL);
		RSA_generate_key_ex(host_keypair, 2048, e, NULL);

		BN_free(e);

		root_pkey = EVP_PKEY_new();
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

		EVP_PKEY_free(host_pkey);

		X509_free(host_cert);
		X509_free(root_cert);
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
	if (pubkey && dev_cert && root_pkey) {
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
	if (root_pkey) {
		EVP_PKEY_free(root_pkey);
	}
	if (dev_cert) {
		X509_free(dev_cert);
	}

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
	if (NULL == pair_record) {
		if (userpref_has_local_config()) {
			/* Read the local config dir */
			plist_t local_config = NULL;
			if (!plist_read_from_filename(&local_config, USERPREF_LOCAL_CONFIG_FILE)) {
				debug_info("ERROR: Failed to read local config file");
				return USERPREF_E_INVALID_CONF;
			}

			/* Read the HostID */
			plist_t host_id_node = plist_dict_get_item(local_config, USERPREF_HOST_ID_KEY);
			if (host_id_node && (plist_get_node_type(host_id_node) == PLIST_STRING)) {
				COPY_PLIST_STRING_VAL(host_id_node, host_id);
			}

			plist_free(local_config);
		} else {
			return USERPREF_E_INVALID_ARG;
		}
	} else {
		plist_t node = plist_dict_get_item(pair_record, USERPREF_HOST_ID_KEY);

		if (node && plist_get_node_type(node) == PLIST_STRING) {
			plist_get_string_val(node, host_id);
		}
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

