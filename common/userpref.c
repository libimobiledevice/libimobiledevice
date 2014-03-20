/*
 * userpref.c
 * contains methods to access user specific certificates IDs and more.
 *
 * Copyright (c) 2013 Martin Szulecki All Rights Reserved.
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
#include <libgen.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef WIN32
#include <shlobj.h>
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

static int __mkdir(const char *dir, int mode)
{
#ifdef WIN32
	return mkdir(dir);
#else
	return mkdir(dir, mode);
#endif
}

static int mkdir_with_parents(const char *dir, int mode)
{
	if (!dir) return -1;
	if (__mkdir(dir, mode) == 0) {
		return 0;
	} else {
		if (errno == EEXIST) return 0;	
	}
	int res;
	char *parent = strdup(dir);
	char* parentdir = dirname(parent);
	if (parentdir) {
		res = mkdir_with_parents(parentdir, mode);
	} else {
		res = -1;
	}
	free(parent);
	return res;
}

/**
 * Creates a freedesktop compatible configuration directory.
 */
static void userpref_create_config_dir(void)
{
	const char *config_path = userpref_get_config_dir();
	struct stat st;
	if (stat(config_path, &st) != 0) {
		mkdir_with_parents(config_path, 0755);
	}
}

static int get_rand(int min, int max)
{
	int retval = (rand() % (max - min)) + min;
	return retval;
}

/**
 * Generates a valid HostID (which is actually a UUID).
 *
 * @return A null terminated string containing a valid HostID.
 */
static char *userpref_generate_host_id(int idx)
{
	/* HostID's are just UUID's, and UUID's are 36 characters long */
	char *hostid = (char *) malloc(sizeof(char) * 37);
	const char *chars = "ABCDEF0123456789";
	srand(time(NULL) - idx);
	int i = 0;

	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			hostid[i] = '-';
			continue;
		} else {
			hostid[i] = chars[get_rand(0, 16)];
		}
	}
	/* make it a real string */
	hostid[36] = '\0';
	return hostid;
}

/**
 * Generates a valid BUID for this system (which is actually a UUID).
 *
 * @return A null terminated string containing a valid BUID.
 */
static char *userpref_generate_system_buid()
{
	return userpref_generate_host_id(1);
}

static int internal_set_value(const char *config_file, const char *key, plist_t value)
{
	if (!config_file)
		return 0;

	/* read file into plist */
	plist_t config = NULL;

	plist_read_from_filename(&config, config_file);
	if (!config) {
		config = plist_new_dict();
		plist_dict_set_item(config, key, value);
	} else {
		plist_t n = plist_dict_get_item(config, key);
		if (n) {
			plist_dict_remove_item(config, key);
		}
		plist_dict_set_item(config, key, value);
		remove(config_file);
	}

	/* store in config file */
	char *value_string = NULL;
	if (plist_get_node_type(value) == PLIST_STRING) {
		plist_get_string_val(value, &value_string);
		debug_info("setting key %s to %s in config_file %s", key, value_string, config_file);
		if (value_string)
			free(value_string);
	} else {
		debug_info("setting key %s in config_file %s", key, config_file);
	}

	plist_write_to_filename(config, config_file, PLIST_FORMAT_XML);

	plist_free(config);

	return 1;
}

int userpref_set_value(const char *key, plist_t value)
{
	const char *config_path = NULL;
	char *config_file = NULL;

	/* Make sure config directory exists */
	userpref_create_config_dir();

	config_path = userpref_get_config_dir();
	config_file = string_concat(config_path, DIR_SEP_S, USERPREF_CONFIG_FILE, NULL);

	int result = internal_set_value(config_file, key, value);

	free(config_file);

	return result;
}

int userpref_device_record_set_value(const char *udid, const char *key, plist_t value)
{
	const char *config_path = NULL;
	char *config_file = NULL;

	/* Make sure config directory exists */
	userpref_create_config_dir();

	config_path = userpref_get_config_dir();
	config_file = string_concat(config_path, DIR_SEP_S, udid, USERPREF_CONFIG_EXTENSION, NULL);

	int result = internal_set_value(config_file, key, value);

	free(config_file);

	return result;
}

static int internal_get_value(const char* config_file, const char *key, plist_t *value)
{
	*value = NULL;

	/* now parse file to get the SystemBUID */
	plist_t config = NULL;
	if (plist_read_from_filename(&config, config_file)) {
		debug_info("reading key %s from config_file %s", key, config_file);
		plist_t n = plist_dict_get_item(config, key);
		if (n) {
			*value = plist_copy(n);
			n = NULL;
		}
	}
	plist_free(config);

	return 1;
}

int userpref_get_value(const char *key, plist_t *value)
{
	const char *config_path = NULL;
	char *config_file = NULL;

	config_path = userpref_get_config_dir();
	config_file = string_concat(config_path, DIR_SEP_S, USERPREF_CONFIG_FILE, NULL);

	int result = internal_get_value(config_file, key, value);

	free(config_file);

	return result;
}

int userpref_device_record_get_value(const char *udid, const char *key, plist_t *value)
{
	const char *config_path = NULL;
	char *config_file = NULL;

	config_path = userpref_get_config_dir();
	config_file = string_concat(config_path, DIR_SEP_S, udid, USERPREF_CONFIG_EXTENSION, NULL);

	int result = internal_get_value(config_file, key, value);

	free(config_file);

	return result;
}

/**
 * Store SystemBUID in config file.
 *
 * @param host_id A null terminated string containing a valid SystemBUID.
 */
static int userpref_set_system_buid(const char *system_buid)
{
	return userpref_set_value(USERPREF_SYSTEM_BUID_KEY, plist_new_string(system_buid));
}

/**
 * Reads the BUID from a previously generated configuration file.
 *
 * @note It is the responsibility of the calling function to free the returned system_buid
 *
 * @return The string containing the BUID or NULL
 */
void userpref_get_system_buid(char **system_buid)
{
	plist_t value = NULL;

	userpref_get_value(USERPREF_SYSTEM_BUID_KEY, &value);

	if (value && (plist_get_node_type(value) == PLIST_STRING)) {
		plist_get_string_val(value, system_buid);
		debug_info("got %s %s", USERPREF_SYSTEM_BUID_KEY, *system_buid);
	}

	if (value)
		plist_free(value);

	if (!*system_buid) {
		/* no config, generate system_buid */
		debug_info("no previous %s found", USERPREF_SYSTEM_BUID_KEY);
		*system_buid = userpref_generate_system_buid();
		userpref_set_system_buid(*system_buid);
	}

	debug_info("using %s as %s", *system_buid, USERPREF_SYSTEM_BUID_KEY);
}

void userpref_device_record_get_host_id(const char *udid, char **host_id)
{
	plist_t value = NULL;

	userpref_device_record_get_value(udid, USERPREF_HOST_ID_KEY, &value);

	if (value && (plist_get_node_type(value) == PLIST_STRING)) {
		plist_get_string_val(value, host_id);
	}

	if (value)
		plist_free(value);

	if (!*host_id) {
		/* no config, generate host_id */
		*host_id = userpref_generate_host_id(0);
		userpref_device_record_set_value(udid, USERPREF_HOST_ID_KEY, plist_new_string(*host_id));
	}

	debug_info("using %s as %s", *host_id, USERPREF_HOST_ID_KEY);
}

/**
 * Determines whether this device has been connected to this system before.
 *
 * @param udid The device UDID as given by the device.
 *
 * @return 1 if the device has been connected previously to this configuration
 *         or 0 otherwise.
 */
int userpref_has_device_record(const char *udid)
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
 * Mark the device as having connected to this configuration.
 *
 * @param udid The device UDID as given by the device
 * @param device_record The device record with full configuration
 *
 * @return 1 on success and 0 if no device record is given or if it has already
 *         been marked as connected previously.
 */
userpref_error_t userpref_set_device_record(const char *udid, plist_t device_record)
{
	/* ensure config directory exists */
	userpref_create_config_dir();

	/* build file path */
	const char *config_path = userpref_get_config_dir();
	char *device_record_file = string_concat(config_path, DIR_SEP_S, udid, USERPREF_CONFIG_EXTENSION, NULL);

	remove(device_record_file);

	/* store file */
	if (!plist_write_to_filename(device_record, device_record_file, PLIST_FORMAT_XML)) {
		debug_info("could not open '%s' for writing: %s", device_record_file, strerror(errno));
	}
	free(device_record_file);

	return USERPREF_E_SUCCESS;
}

userpref_error_t userpref_get_device_record(const char *udid, plist_t *device_record)
{
	/* ensure config directory exists */
	userpref_create_config_dir();

	/* build file path */
	const char *config_path = userpref_get_config_dir();
	char *device_record_file = string_concat(config_path, DIR_SEP_S, udid, USERPREF_CONFIG_EXTENSION, NULL);

	/* read file */
	if (!plist_read_from_filename(device_record, device_record_file)) {
		debug_info("could not open '%s' for reading: %s", device_record_file, strerror(errno));
	}
	free(device_record_file);

	return USERPREF_E_SUCCESS;
}

/**
 * Remove the pairing record stored for a device from this host.
 *
 * @param udid The udid of the device
 *
 * @return USERPREF_E_SUCCESS on success.
 */
userpref_error_t userpref_remove_device_record(const char *udid)
{
	userpref_error_t res = USERPREF_E_SUCCESS;
	if (!userpref_has_device_record(udid))
		return res;

	/* build file path */
	const char *config_path = userpref_get_config_dir();
	char *device_record_file = string_concat(config_path, DIR_SEP_S, udid, USERPREF_CONFIG_EXTENSION, NULL);

	/* remove file */
	if (remove(device_record_file) != 0) {
		debug_info("could not remove %s: %s", device_record_file, strerror(errno));
		res = USERPREF_E_UNKNOWN_ERROR;
	}

	free(device_record_file);

	return res;
}

#if 0
/**
 * Private function which reads the given file into a key_data_t structure.
 *
 * @param file The filename of the file to read
 * @param data The pointer at which to store the data.
 *
 * @return 1 if the file contents where read successfully and 0 otherwise.
 */
static int userpref_get_file_contents(const char *file, key_data_t * data)
{
	int success = 0;
	unsigned long int size = 0;
	unsigned char *content = NULL;
	const char *config_path = NULL;
	char *filepath;
	FILE *fd;

	if (NULL == file || NULL == data)
		return 0;

	/* Read file */
	config_path = userpref_get_config_dir();
	filepath = string_concat(config_path, DIR_SEP_S, file, NULL);

	fd = fopen(filepath, "rb");
	if (fd) {
		fseek(fd, 0, SEEK_END);
		size = ftell(fd);
		fseek(fd, 0, SEEK_SET);

		// prevent huge files
		if (size > 0xFFFFFF) {
			fprintf(stderr, "%s: file is too big (> 16MB). Refusing to read the contents to memory!", __func__);
		} else {
			size_t p = 0;
			content = (unsigned char*)malloc(size);
			while (!feof(fd)) {
				p += fread(content+p, 1, size-p, fd);
				if (ferror(fd) != 0) {
					break;
				}
				if (p >= size) {
					success = 1;
					break;
				}
			}
		}
		fclose(fd);
	}

	free(filepath);

	/* Add it to the key_data_t structure */
	if (success) {
		data->data = (uint8_t*) content;
		data->size = size;
	}

	return success;
}
#endif

/**
 * Private function which generate private keys and certificates.
 *
 * @return 1 if keys were successfully generated, 0 otherwise
 */
static userpref_error_t userpref_device_record_gen_keys_and_cert(const char* udid)
{
	userpref_error_t ret = USERPREF_E_SSL_ERROR;

	key_data_t root_key_pem = { NULL, 0 };
	key_data_t root_cert_pem = { NULL, 0 };
	key_data_t host_key_pem = { NULL, 0 };
	key_data_t host_cert_pem = { NULL, 0 };

	debug_info("generating keys and certificates");
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
		X509_EXTENSION* ext;
		if (!(ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, (char*)"critical,CA:TRUE"))) {
			debug_info("ERROR: X509V3_EXT_conf_nid failed");
		}
		X509_add_ext(root_cert, ext, -1);

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
		X509_EXTENSION* ext;
		if (!(ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, (char*)"critical,CA:FALSE"))) {
			debug_info("ERROR: X509V3_EXT_conf_nid failed");
		}
		X509_add_ext(host_cert, ext, -1);

		/* set x509v3 key usage */
		if (!(ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, (char*)"digitalSignature,keyEncipherment"))) {
			debug_info("ERROR: X509V3_EXT_conf_nid failed");
		}
		X509_add_ext(host_cert, ext, -1);

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

	EVP_PKEY_free(root_pkey);
	EVP_PKEY_free(host_pkey);

	X509_free(host_cert);
	X509_free(root_cert);
#else
	gnutls_x509_privkey_t root_privkey;
	gnutls_x509_crt_t root_cert;
	gnutls_x509_privkey_t host_privkey;
	gnutls_x509_crt_t host_cert;

	gnutls_global_deinit();
	gnutls_global_init();

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

	/* restore gnutls env */
	gnutls_global_deinit();
	gnutls_global_init();
#endif
	if (NULL != root_cert_pem.data && 0 != root_cert_pem.size &&
		NULL != host_cert_pem.data && 0 != host_cert_pem.size)
		ret = USERPREF_E_SUCCESS;

	/* store values in config file */
	userpref_device_record_set_keys_and_certs(udid, &root_key_pem, &root_cert_pem, &host_key_pem, &host_cert_pem);

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
static userpref_error_t userpref_device_record_import_key(const char* udid, const char* name, key_data_t* key)
#else
static userpref_error_t userpref_device_record_import_key(const char* udid, const char* name, gnutls_x509_privkey_t key)
#endif
{
#ifdef HAVE_OPENSSL
	if (!key)
		return USERPREF_E_SUCCESS;
#endif
	userpref_error_t ret = USERPREF_E_INVALID_CONF;
	char* buffer = NULL;
	uint64_t length = 0;

	plist_t crt = NULL;
	if (userpref_device_record_get_value(udid, name, &crt)) {
		if (crt && plist_get_node_type(crt) == PLIST_DATA) {
			plist_get_data_val(crt, &buffer, &length);
#ifdef HAVE_OPENSSL
			key->data = (unsigned char*)malloc(length);
			memcpy(key->data, buffer, length);
			key->size = length;
			ret = USERPREF_E_SUCCESS;
#else
			key_data_t pem = { (unsigned char*)buffer, length };
			if (GNUTLS_E_SUCCESS == gnutls_x509_privkey_import(key, &pem, GNUTLS_X509_FMT_PEM))
				ret = USERPREF_E_SUCCESS;
			else
				ret = USERPREF_E_SSL_ERROR;
#endif
		}
	}

	if (crt)
		plist_free(crt);

	if (buffer)
		free(buffer);

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
static userpref_error_t userpref_device_record_import_crt(const char* udid, const char* name, key_data_t* cert)
#else
static userpref_error_t userpref_device_record_import_crt(const char* udid, const char* name, gnutls_x509_crt_t cert)
#endif
{
#ifdef HAVE_OPENSSL
	if (!cert)
		return USERPREF_E_SUCCESS;
#endif
	userpref_error_t ret = USERPREF_E_INVALID_CONF;
	char* buffer = NULL;
	uint64_t length = 0;

	plist_t crt = NULL;
	if (userpref_device_record_get_value(udid, name, &crt)) {
		if (crt && plist_get_node_type(crt) == PLIST_DATA) {
			plist_get_data_val(crt, &buffer, &length);
#ifdef HAVE_OPENSSL
			cert->data = (unsigned char*)malloc(length);
			memcpy(cert->data, buffer, length);
			cert->size = length;
			ret = USERPREF_E_SUCCESS;
#else
			key_data_t pem = { (unsigned char*)buffer, length };
			if (GNUTLS_E_SUCCESS == gnutls_x509_crt_import(cert, &pem, GNUTLS_X509_FMT_PEM))
				ret = USERPREF_E_SUCCESS;
			else
				ret = USERPREF_E_SSL_ERROR;
#endif
		}
	}

	if (crt)
		plist_free(crt);

	if (buffer)
		free(buffer);

	return ret;
}

/**
 * Function to retrieve host keys and certificates.
 * This function trigger key generation if they do not exists yet or are invalid.
 *
 * @note This function can take few seconds to complete (typically 5 seconds)
 *
 * @param root_privkey The root private key.
 * @param root_crt The root certificate.
 * @param host_privkey The host private key.
 * @param host_crt The host certificate.
 *
 * @return 1 if the keys and certificates were successfully retrieved, 0 otherwise
 */
#ifdef HAVE_OPENSSL
userpref_error_t userpref_device_record_get_keys_and_certs(const char *udid, key_data_t* root_privkey, key_data_t* root_crt, key_data_t* host_privkey, key_data_t* host_crt)
#else
userpref_error_t userpref_device_record_get_keys_and_certs(const char *udid, gnutls_x509_privkey_t root_privkey, gnutls_x509_crt_t root_crt, gnutls_x509_privkey_t host_privkey, gnutls_x509_crt_t host_crt)
#endif
{
	userpref_error_t ret = USERPREF_E_SUCCESS;

	if (ret == USERPREF_E_SUCCESS)
		ret = userpref_device_record_import_key(udid, USERPREF_ROOT_PRIVATE_KEY_KEY, root_privkey);

	if (ret == USERPREF_E_SUCCESS)
		ret = userpref_device_record_import_key(udid, USERPREF_HOST_PRIVATE_KEY_KEY, host_privkey);

	if (ret == USERPREF_E_SUCCESS)
		ret = userpref_device_record_import_crt(udid, USERPREF_ROOT_CERTIFICATE_KEY, root_crt);

	if (ret == USERPREF_E_SUCCESS)
		ret = userpref_device_record_import_crt(udid, USERPREF_HOST_CERTIFICATE_KEY, host_crt);

	if (USERPREF_E_SUCCESS != ret) {
		/* we had problem reading or importing root cert, try with new ones */
		ret = userpref_device_record_gen_keys_and_cert(udid);

		if (ret == USERPREF_E_SUCCESS)
			ret = userpref_device_record_import_key(udid, USERPREF_ROOT_PRIVATE_KEY_KEY, root_privkey);

		if (ret == USERPREF_E_SUCCESS)
			ret = userpref_device_record_import_key(udid, USERPREF_HOST_PRIVATE_KEY_KEY, host_privkey);

		if (ret == USERPREF_E_SUCCESS)
			ret = userpref_device_record_import_crt(udid, USERPREF_ROOT_CERTIFICATE_KEY, root_crt);

		if (ret == USERPREF_E_SUCCESS)
			ret = userpref_device_record_import_crt(udid, USERPREF_ROOT_CERTIFICATE_KEY, host_crt);
	}

	return ret;
}

/**
 * Function to retrieve certificates encoded in PEM format.
 *
 * @param pem_root_cert The root certificate.
 * @param pem_host_cert The host certificate.
 * @param pem_device_cert The device certificate (optional).
 *
 * @return 1 if the certificates were successfully retrieved, 0 otherwise
 */
userpref_error_t userpref_device_record_get_certs_as_pem(const char *udid, key_data_t *pem_root_cert, key_data_t *pem_host_cert, key_data_t *pem_device_cert)
{
	if (!udid || !pem_root_cert || !pem_host_cert)
		return USERPREF_E_INVALID_ARG;

	char* buffer = NULL;
	uint64_t length = 0;

	plist_t root_cert = NULL;
	plist_t host_cert = NULL;
	plist_t dev_cert = NULL;

	if (userpref_device_record_get_value(udid, USERPREF_HOST_CERTIFICATE_KEY, &host_cert) &&
		userpref_device_record_get_value(udid, USERPREF_ROOT_CERTIFICATE_KEY, &root_cert)) {
		if (host_cert && plist_get_node_type(host_cert) == PLIST_DATA) {
			plist_get_data_val(host_cert, &buffer, &length);
			pem_host_cert->data = (unsigned char*)malloc(length);
			memcpy(pem_host_cert->data, buffer, length);
			pem_host_cert->size = length;
			free(buffer);
			buffer = NULL;
		}
		if (root_cert && plist_get_node_type(root_cert) == PLIST_DATA) {
			plist_get_data_val(root_cert, &buffer, &length);
			pem_root_cert->data = (unsigned char*)malloc(length);
			memcpy(pem_root_cert->data, buffer, length);
			pem_root_cert->size = length;
			free(buffer);
			buffer = NULL;
		}

		if (pem_device_cert) {
			userpref_device_record_get_value(udid, USERPREF_DEVICE_CERTIFICATE_KEY, &dev_cert);
			if (dev_cert && plist_get_node_type(dev_cert) == PLIST_DATA) {
				plist_get_data_val(dev_cert, &buffer, &length);
				pem_device_cert->data = (unsigned char*)malloc(length);
				memcpy(pem_device_cert->data, buffer, length);
				pem_device_cert->size = length;
				free(buffer);
				buffer = NULL;
			}
		}

		if (root_cert)
			plist_free(root_cert);
		if (host_cert)
			plist_free(host_cert);
		if (dev_cert)
			plist_free(dev_cert);

		return USERPREF_E_SUCCESS;
	} else {
		if (pem_root_cert->data) {
			free(pem_root_cert->data);
			pem_root_cert->size = 0;
		}
		if (pem_host_cert->data) {
			free(pem_host_cert->data);
			pem_host_cert->size = 0;
		}
	}

	if (root_cert)
		plist_free(root_cert);
	if (host_cert)
		plist_free(host_cert);
	if (dev_cert)
		plist_free(dev_cert);

	debug_info("configuration invalid");

	return USERPREF_E_INVALID_CONF;
}

/**
 * Create and save a configuration file containing the given data.
 *
 * @note: All fields must specified and be non-null
 *
 * @param root_key The root key
 * @param root_cert The root certificate
 * @param host_key The host key
 * @param host_cert The host certificate
 *
 * @return 1 on success and 0 otherwise.
 */
userpref_error_t userpref_device_record_set_keys_and_certs(const char* udid, key_data_t * root_key, key_data_t * root_cert, key_data_t * host_key, key_data_t * host_cert)
{
	userpref_error_t ret = USERPREF_E_SUCCESS;

	debug_info("saving keys and certs for udid %s", udid);

	if (!root_key || !host_key || !root_cert || !host_cert) {
		debug_info("missing key or cert (root_key=%p, host_key=%p, root=cert=%p, host_cert=%p", root_key, host_key, root_cert, host_cert);
		return USERPREF_E_INVALID_ARG;
	}

	/* now write keys and certificates to disk */
	if (userpref_device_record_set_value(udid, USERPREF_HOST_PRIVATE_KEY_KEY, plist_new_data((char*)host_key->data, host_key->size)) &&
		userpref_device_record_set_value(udid, USERPREF_HOST_CERTIFICATE_KEY, plist_new_data((char*)host_cert->data, host_cert->size)) &&
		userpref_device_record_set_value(udid, USERPREF_ROOT_PRIVATE_KEY_KEY, plist_new_data((char*)root_key->data, root_key->size)) &&
		userpref_device_record_set_value(udid, USERPREF_ROOT_CERTIFICATE_KEY, plist_new_data((char*)root_cert->data, root_cert->size)))
	{
		ret = USERPREF_E_SUCCESS;
	} else {
		ret = 1;
	}

	return ret;
}
