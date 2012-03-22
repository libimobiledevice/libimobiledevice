/*
 * userpref.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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

#define LIBIMOBILEDEVICE_CONF_DIR  "libimobiledevice"
#define LIBIMOBILEDEVICE_CONF_FILE "libimobiledevicerc"

#define LIBIMOBILEDEVICE_ROOT_PRIVKEY "RootPrivateKey.pem"
#define LIBIMOBILEDEVICE_HOST_PRIVKEY "HostPrivateKey.pem"
#define LIBIMOBILEDEVICE_ROOT_CERTIF "RootCertificate.pem"
#define LIBIMOBILEDEVICE_HOST_CERTIF "HostCertificate.pem"

#ifdef WIN32
#define DIR_SEP '\\'
#define DIR_SEP_S "\\"
#else
#define DIR_SEP '/'
#define DIR_SEP_S "/"
#endif

static char __config_dir[512] = {0, };

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

static const char *userpref_get_config_dir()
{
	if (__config_dir[0]) return __config_dir;
#ifdef WIN32
	wchar_t path[MAX_PATH+1];
	HRESULT hr;
	LPITEMIDLIST pidl = NULL;
	BOOL b = FALSE;

	hr = SHGetSpecialFolderLocation (NULL, CSIDL_LOCAL_APPDATA, &pidl);
	if (hr == S_OK) {
		b = SHGetPathFromIDListW (pidl, path);
		if (b) {
			char *cdir = userpref_utf16_to_utf8 (path, wcslen(path), NULL, NULL);
			strcpy(__config_dir, cdir);
			free(cdir);
			CoTaskMemFree (pidl);
		}
	}
#else
	const char *cdir = getenv("XDG_CONFIG_HOME");
	if (!cdir) {
		cdir = getenv("HOME");
		strcpy(__config_dir, cdir);
		strcat(__config_dir, DIR_SEP_S);
		strcat(__config_dir, ".config");
	} else {
		strcpy(__config_dir, cdir);
	}
#endif
	strcat(__config_dir, DIR_SEP_S);
	strcat(__config_dir, LIBIMOBILEDEVICE_CONF_DIR);

	int i = strlen(__config_dir)-1;	
	while ((i > 0) && (__config_dir[i] == DIR_SEP)) {
		__config_dir[i--] = '\0';
	}

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
	parent = dirname(parent);
	if (parent) {
		res = mkdir_with_parents(parent, mode);
	} else {
		res = -1;	
	}
	free(parent);
	if (res == 0) {
		mkdir_with_parents(dir, mode);
	}
	return res;
}

static int config_write(const char *cfgfile, plist_t dict)
{
	if (!cfgfile || !dict || (plist_get_node_type(dict) != PLIST_DICT)) {
		return -1;
	}
	int res = -1;

#if 1 // old style config
	plist_t hostid = plist_dict_get_item(dict, "HostID");
	if (hostid && (plist_get_node_type(hostid) == PLIST_STRING)) {
		char *hostidstr = NULL;
		plist_get_string_val(hostid, &hostidstr);
		if (hostidstr) {
			FILE *fd = fopen(cfgfile, "wb");
			if (fd) {
				fprintf(fd, "\n[Global]\nHostID=%s\n", hostidstr);
				fclose(fd);
				res = 0;
			} else {
				debug_info("could not open '%s' for writing: %s", cfgfile, strerror(errno));
			}
			free(hostidstr);
		}
	}
#endif
#if 0
	char *xml = NULL;
	uint32_t length = 0;

	plist_to_xml(dict, &xml, &length);
	if (!xml) {
		return res;
	}

	FILE *fd = fopen(cfgfile, "wb");
	if (!fd) {
		free(xml);
		return res;
	}

	if (fwrite(xml, 1, length, fd) == length) {
		res = 0;
	} else {
		fprintf(stderr, "%s: ERROR: failed to write configuration to '%s'\n", __func__, cfgfile);
	}
	fclose(fd);

	free(xml);
#endif
	return res;
}

static int config_read(const char *cfgfile, plist_t *dict)
{
	if (!cfgfile || !dict) {
		return -1;
	}

	int res = -1;
	FILE *fd = fopen(cfgfile, "rb");
	if (!fd) {
		debug_info("could not open '%s' for reading: %s", cfgfile, strerror(errno));
		return -1;
	}

	fseek(fd, 0, SEEK_END);
	unsigned long int size = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	unsigned char *contents = NULL;

	contents = malloc(size);
	if (fread(contents, 1, size, fd) != size) {
		free(contents);
		fclose(fd);
		return -1;
	}
	plist_t plist = NULL;

	if (!memcmp(contents, "bplist00", 8)) {
		plist_from_bin((const char*)contents, (uint32_t)size, &plist);
		fclose(fd);
	} else {
		if (memchr(contents, '<', size)) {
			plist_from_xml((const char*)contents, (uint32_t)size, &plist);
		}
		if (plist) {
			fclose(fd);
		} else {
			// try parsing old format config file
			char line[256];
			fseek(fd, 0, SEEK_SET);
			while (fgets(line, 256, fd)) {
				char *p = &line[0];
				size_t llen = strlen(p)-1;
				while ((llen > 0) && ((p[llen] == '\n') || (p[llen] == '\r'))) {
					p[llen] = '\0';
					llen--;
				}
				if (llen == 0) continue;
				while ((p[0] == '\n') || (p[0] == '\r')) {
					p++;
				}
				if (!strncmp(p, "HostID=", 7)) {
					plist = plist_new_dict();
					plist_dict_insert_item(plist, "HostID", plist_new_string(p+7));
					break;
				}
			}
			fclose(fd);
#if 0
			if (plist) {
				// write new format config
				config_write(cfgfile, plist);
			}
#endif
		}
	}
	free(contents);
	if (plist) {
		*dict = plist;
		res = 0;
	}
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
static char *userpref_generate_host_id()
{
	/* HostID's are just UUID's, and UUID's are 36 characters long */
	char *hostid = (char *) malloc(sizeof(char) * 37);
	const char *chars = "ABCDEF0123456789";
	srand(time(NULL));
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
 * Store HostID in config file.
 *
 * @param host_id A null terminated string containing a valid HostID.
 */
static int userpref_set_host_id(const char *host_id)
{
	const char *config_path;
	char *config_file;

	if (!host_id)
		return 0;

	/* Make sure config directory exists */
	userpref_create_config_dir();

	config_path = userpref_get_config_dir();
	config_file = (char*)malloc(strlen(config_path)+1+strlen(LIBIMOBILEDEVICE_CONF_FILE)+1);
	strcpy(config_file, config_path);
	strcat(config_file, DIR_SEP_S);
	strcat(config_file, LIBIMOBILEDEVICE_CONF_FILE);

	/* Now parse file to get the HostID */
	plist_t config = NULL;
	config_read(config_file, &config);
	if (!config) {
		config = plist_new_dict();
		plist_dict_insert_item(config, "HostID", plist_new_string(host_id));
	} else {
		plist_t n = plist_dict_get_item(config, "HostID");
		if (n) {
			plist_set_string_val(n, host_id);
		} else {
			plist_dict_insert_item(config, "HostID", plist_new_string(host_id));
		}
	}

	/* Store in config file */
	debug_info("setting hostID to %s", host_id);

	config_write(config_file, config);
	plist_free(config);

	free(config_file);
	return 1;
}

/**
 * Reads the HostID from a previously generated configuration file.
 *
 * @note It is the responsibility of the calling function to free the returned host_id
 *
 * @return The string containing the HostID or NULL
 */
void userpref_get_host_id(char **host_id)
{
	const char *config_path;
	char *config_file;

	config_path = userpref_get_config_dir();
	config_file = (char*)malloc(strlen(config_path)+1+strlen(LIBIMOBILEDEVICE_CONF_FILE)+1);
	strcpy(config_file, config_path);
	strcat(config_file, DIR_SEP_S);
	strcat(config_file, LIBIMOBILEDEVICE_CONF_FILE);

	/* now parse file to get the HostID */
	plist_t config = NULL;
	if (config_read(config_file, &config) == 0) {
		plist_t n_host_id = plist_dict_get_item(config, "HostID");
		if (n_host_id && (plist_get_node_type(n_host_id) == PLIST_STRING)) {
			plist_get_string_val(n_host_id, host_id);
		}
	}
	plist_free(config);
	free(config_file);

	if (!*host_id) {
		/* no config, generate host_id */
		*host_id = userpref_generate_host_id();
		userpref_set_host_id(*host_id);
	}

	debug_info("Using %s as HostID", *host_id);
}

/**
 * Determines whether this device has been connected to this system before.
 *
 * @param udid The device UDID as given by the device.
 *
 * @return 1 if the device has been connected previously to this configuration
 *         or 0 otherwise.
 */
int userpref_has_device_public_key(const char *udid)
{
	int ret = 0;
	const char *config_path;
	char *config_file;
	struct stat st;

	if (!udid) return 0;

	/* first get config file */
	config_path = userpref_get_config_dir();
	config_file = (char*)malloc(strlen(config_path)+1+strlen(udid)+4+1);
	strcpy(config_file, config_path);
	strcat(config_file, DIR_SEP_S);
	strcat(config_file, udid);
	strcat(config_file, ".pem");

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
	const char *config_path;
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
			char *ext = strstr(entry->d_name, ".pem");
			if (ext && ((ext - entry->d_name) == 40) && (strlen(entry->d_name) == 44)) {
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
 * Mark the device (as represented by the key) as having connected to this
 * configuration.
 *
 * @param udid The device UDID as given by the device
 * @param public_key The public key given by the device
 *
 * @return 1 on success and 0 if no public key is given or if it has already
 *         been marked as connected previously.
 */
userpref_error_t userpref_set_device_public_key(const char *udid, key_data_t public_key)
{
	if (NULL == public_key.data)
		return USERPREF_E_INVALID_ARG;
	
	if (userpref_has_device_public_key(udid))
		return USERPREF_E_SUCCESS;

	/* ensure config directory exists */
	userpref_create_config_dir();

	/* build file path */
	const char *config_path = userpref_get_config_dir();
	char *pem = (char*)malloc(strlen(config_path)+1+strlen(udid)+4+1);
	strcpy(pem, config_path);
	strcat(pem, DIR_SEP_S);
	strcat(pem, udid);
	strcat(pem, ".pem");

	/* store file */
	FILE *pFile = fopen(pem, "wb");
	if (pFile) {
		fwrite(public_key.data, 1, public_key.size, pFile);
		fclose(pFile);
	} else {
		debug_info("could not open '%s' for writing: %s", pem, strerror(errno));
	}
	free(pem);

	return USERPREF_E_SUCCESS;
}

/**
 * Remove the public key stored for the device with udid from this host.
 *
 * @param udid The udid of the device
 *
 * @return USERPREF_E_SUCCESS on success.
 */
userpref_error_t userpref_remove_device_public_key(const char *udid)
{
	if (!userpref_has_device_public_key(udid))
		return USERPREF_E_SUCCESS;

	/* build file path */
	const char *config_path = userpref_get_config_dir();
	char *pem = (char*)malloc(strlen(config_path)+1+strlen(udid)+4+1);
	strcpy(pem, config_path);
	strcat(pem, DIR_SEP_S);
	strcat(pem, udid);
	strcat(pem, ".pem");

	/* remove file */
	remove(pem);

	free(pem);

	return USERPREF_E_SUCCESS;
}

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
	const char *config_path;
	char *filepath;
	FILE *fd;

	if (NULL == file || NULL == data)
		return 0;

	/* Read file */
	config_path = userpref_get_config_dir();
	filepath = (char*)malloc(strlen(config_path)+1+strlen(file)+1);
	strcpy(filepath, config_path);
	strcat(filepath, DIR_SEP_S);
	strcat(filepath, file);

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

/**
 * Private function which generate private keys and certificates.
 *
 * @return 1 if keys were successfully generated, 0 otherwise
 */
static userpref_error_t userpref_gen_keys_and_cert(void)
{
	userpref_error_t ret = USERPREF_E_SSL_ERROR;

	key_data_t root_key_pem = { NULL, 0 };
	key_data_t root_cert_pem = { NULL, 0 };
	key_data_t host_key_pem = { NULL, 0 };
	key_data_t host_cert_pem = { NULL, 0 };

	debug_info("Generating keys and certificates");
#ifdef HAVE_OPENSSL
	RSA* root_keypair = RSA_generate_key(2048, 65537, NULL, NULL);
	RSA* host_keypair = RSA_generate_key(2048, 65537, NULL, NULL);

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

		membp = BIO_new(BIO_s_mem());
		if (PEM_write_bio_X509(membp, root_cert) > 0) {
			root_cert_pem.size = BIO_get_mem_data(membp, &root_cert_pem.data);
		}
		membp = BIO_new(BIO_s_mem());
		if (PEM_write_bio_PrivateKey(membp, root_pkey, NULL, NULL, 0, 0, NULL) > 0) {
			root_key_pem.size = BIO_get_mem_data(membp, &root_key_pem.data);
		}
		membp = BIO_new(BIO_s_mem());
		if (PEM_write_bio_X509(membp, host_cert) > 0) {
			host_cert_pem.size = BIO_get_mem_data(membp, &host_cert_pem.data);
		}
		membp = BIO_new(BIO_s_mem());
		if (PEM_write_bio_PrivateKey(membp, host_pkey, NULL, NULL, 0, 0, NULL) > 0) {
			host_key_pem.size = BIO_get_mem_data(membp, &host_key_pem.data);
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

	//use less secure random to speed up key generation
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

	//restore gnutls env
	gnutls_global_deinit();
	gnutls_global_init();
#endif
	if (NULL != root_cert_pem.data && 0 != root_cert_pem.size &&
		NULL != host_cert_pem.data && 0 != host_cert_pem.size)
		ret = USERPREF_E_SUCCESS;

	/* store values in config file */
	userpref_set_keys_and_certs( &root_key_pem, &root_cert_pem, &host_key_pem, &host_cert_pem);

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
 * @param key_name The filename of the private key to import.
 * @param key the gnutls key structure.
 *
 * @return 1 if the key was successfully imported.
 */
#ifdef HAVE_OPENSSL
static userpref_error_t userpref_import_key(const char* key_name, key_data_t* key)
#else
static userpref_error_t userpref_import_key(const char* key_name, gnutls_x509_privkey_t key)
#endif
{
#ifdef HAVE_OPENSSL
	if (!key)
		return USERPREF_E_SUCCESS;
#endif
	userpref_error_t ret = USERPREF_E_INVALID_CONF;
	key_data_t pem_key = { NULL, 0 };
	if (userpref_get_file_contents(key_name, &pem_key)) {
#ifdef HAVE_OPENSSL
		key->data = (unsigned char*)malloc(pem_key.size);
		memcpy(key->data, pem_key.data, pem_key.size);
		key->size = pem_key.size;
		ret = USERPREF_E_SUCCESS;
#else
		if (GNUTLS_E_SUCCESS == gnutls_x509_privkey_import(key, &pem_key, GNUTLS_X509_FMT_PEM))
			ret = USERPREF_E_SUCCESS;
		else
			ret = USERPREF_E_SSL_ERROR;
#endif
	}
	if (pem_key.data)
		free(pem_key.data);
	return ret;
}

/**
 * Private function which import the given certificate into a gnutls structure.
 *
 * @param crt_name The filename of the certificate to import.
 * @param cert the gnutls certificate structure.
 *
 * @return IDEVICE_E_SUCCESS if the certificate was successfully imported.
 */
#ifdef HAVE_OPENSSL
static userpref_error_t userpref_import_crt(const char* crt_name, key_data_t* cert)
#else
static userpref_error_t userpref_import_crt(const char* crt_name, gnutls_x509_crt_t cert)
#endif
{
#ifdef HAVE_OPENSSL
	if (!cert)
		return USERPREF_E_SUCCESS;
#endif
	userpref_error_t ret = USERPREF_E_INVALID_CONF;
	key_data_t pem_cert = { NULL, 0 };

	if (userpref_get_file_contents(crt_name, &pem_cert)) {
#ifdef HAVE_OPENSSL
		cert->data = (unsigned char*)malloc(pem_cert.size);
		memcpy(cert->data, pem_cert.data, pem_cert.size);
		cert->size = pem_cert.size;
		ret = USERPREF_E_SUCCESS;
#else
		if (GNUTLS_E_SUCCESS == gnutls_x509_crt_import(cert, &pem_cert, GNUTLS_X509_FMT_PEM))
			ret = USERPREF_E_SUCCESS;
		else
			ret = USERPREF_E_SSL_ERROR;
#endif
	}
	if (pem_cert.data)
		free(pem_cert.data);
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
userpref_error_t userpref_get_keys_and_certs(key_data_t* root_privkey, key_data_t* root_crt, key_data_t* host_privkey, key_data_t* host_crt)
#else
userpref_error_t userpref_get_keys_and_certs(gnutls_x509_privkey_t root_privkey, gnutls_x509_crt_t root_crt, gnutls_x509_privkey_t host_privkey, gnutls_x509_crt_t host_crt)
#endif
{
	userpref_error_t ret = USERPREF_E_SUCCESS;

	if (ret == USERPREF_E_SUCCESS)
		ret = userpref_import_key(LIBIMOBILEDEVICE_ROOT_PRIVKEY, root_privkey);

	if (ret == USERPREF_E_SUCCESS)
		ret = userpref_import_key(LIBIMOBILEDEVICE_HOST_PRIVKEY, host_privkey);

	if (ret == USERPREF_E_SUCCESS)
		ret = userpref_import_crt(LIBIMOBILEDEVICE_ROOT_CERTIF, root_crt);

	if (ret == USERPREF_E_SUCCESS)
		ret = userpref_import_crt(LIBIMOBILEDEVICE_HOST_CERTIF, host_crt);

	if (USERPREF_E_SUCCESS != ret) {
		//we had problem reading or importing root cert
		//try with a new ones.
		ret = userpref_gen_keys_and_cert();

		if (ret == USERPREF_E_SUCCESS)
			ret = userpref_import_key(LIBIMOBILEDEVICE_ROOT_PRIVKEY, root_privkey);

		if (ret == USERPREF_E_SUCCESS)
			ret = userpref_import_key(LIBIMOBILEDEVICE_HOST_PRIVKEY, host_privkey);

		if (ret == USERPREF_E_SUCCESS)
			ret = userpref_import_crt(LIBIMOBILEDEVICE_ROOT_CERTIF, root_crt);

		if (ret == USERPREF_E_SUCCESS)
			ret = userpref_import_crt(LIBIMOBILEDEVICE_HOST_CERTIF, host_crt);
	}

	return ret;
}

/**
 * Function to retrieve certificates encoded in PEM format.
 *
 * @param pem_root_cert The root certificate.
 * @param pem_host_cert The host certificate.
 *
 * @return 1 if the certificates were successfully retrieved, 0 otherwise
 */
userpref_error_t userpref_get_certs_as_pem(key_data_t *pem_root_cert, key_data_t *pem_host_cert)
{
	if (!pem_root_cert || !pem_host_cert)
		return USERPREF_E_INVALID_ARG;

	if (userpref_get_file_contents(LIBIMOBILEDEVICE_ROOT_CERTIF, pem_root_cert) && userpref_get_file_contents(LIBIMOBILEDEVICE_HOST_CERTIF, pem_host_cert))
		return USERPREF_E_SUCCESS;
	else {
		if (pem_root_cert->data) {
			free(pem_root_cert->data);
			pem_root_cert->size = 0;
		}
		if (pem_host_cert->data) {
			free(pem_host_cert->data);
			pem_host_cert->size = 0;
		}
	}
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
userpref_error_t userpref_set_keys_and_certs(key_data_t * root_key, key_data_t * root_cert, key_data_t * host_key, key_data_t * host_cert)
{
	FILE *pFile;
	char *pem;
	const char *config_path;
	userpref_error_t ret = USERPREF_E_SUCCESS;

	debug_info("saving keys and certs");

	if (!root_key || !host_key || !root_cert || !host_cert) {
		debug_info("missing key or cert (root_key=%p, host_key=%p, root=cert=%p, host_cert=%p", root_key, host_key, root_cert, host_cert);
		return USERPREF_E_INVALID_ARG;
	}

	/* Make sure config directory exists */
	userpref_create_config_dir();

	config_path = userpref_get_config_dir();

	/* Now write keys and certificates to disk */
	pem = (char*)malloc(strlen(config_path)+1+strlen(LIBIMOBILEDEVICE_ROOT_PRIVKEY)+1);
	strcpy(pem, config_path);
	strcat(pem, DIR_SEP_S);
	strcat(pem, LIBIMOBILEDEVICE_ROOT_PRIVKEY);
	pFile = fopen(pem, "wb");
	if (pFile) {
		fwrite(root_key->data, 1, root_key->size, pFile);
		fclose(pFile);
	} else {
		debug_info("could not open '%s' for writing: %s", pem, strerror(errno));
		ret = USERPREF_E_WRITE_ERROR;
	}
	free(pem);

	pem = (char*)malloc(strlen(config_path)+1+strlen(LIBIMOBILEDEVICE_HOST_PRIVKEY)+1);
	strcpy(pem, config_path);
	strcat(pem, DIR_SEP_S);
	strcat(pem, LIBIMOBILEDEVICE_HOST_PRIVKEY);
	pFile = fopen(pem, "wb");
	if (pFile) {
		fwrite(host_key->data, 1, host_key->size, pFile);
		fclose(pFile);
	} else {
		debug_info("could not open '%s' for writing: %s", pem, strerror(errno));
		ret = USERPREF_E_WRITE_ERROR;
	}
	free(pem);

	pem = (char*)malloc(strlen(config_path)+1+strlen(LIBIMOBILEDEVICE_ROOT_CERTIF)+1);
	strcpy(pem, config_path);
	strcat(pem, DIR_SEP_S);
	strcat(pem, LIBIMOBILEDEVICE_ROOT_CERTIF);
	pFile = fopen(pem, "wb");
	if (pFile) {
		fwrite(root_cert->data, 1, root_cert->size, pFile);
		fclose(pFile);
	} else {
		debug_info("could not open '%s' for writing: %s", pem, strerror(errno));
		ret = USERPREF_E_WRITE_ERROR;
	}
	free(pem);

	pem = (char*)malloc(strlen(config_path)+1+strlen(LIBIMOBILEDEVICE_HOST_CERTIF)+1);
	strcpy(pem, config_path);
	strcat(pem, DIR_SEP_S);
	strcat(pem, LIBIMOBILEDEVICE_HOST_CERTIF);
	pFile = fopen(pem, "wb");
	if (pFile) {
		fwrite(host_cert->data, 1, host_cert->size, pFile);
		fclose(pFile);
	} else {
		debug_info("could not open '%s' for writing: %s", pem, strerror(errno));
		ret = USERPREF_E_WRITE_ERROR;
	}
	free(pem);

	return ret;
}
