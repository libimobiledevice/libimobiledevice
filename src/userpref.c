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

#include <glib.h>
#include <glib/gprintf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gcrypt.h>

#include "userpref.h"
#include "utils.h"

#define LIBIPHONE_CONF_DIR  "libiphone"
#define LIBIPHONE_CONF_FILE "libiphonerc"

#define LIBIPHONE_ROOT_PRIVKEY "RootPrivateKey.pem"
#define LIBIPHONE_HOST_PRIVKEY "HostPrivateKey.pem"
#define LIBIPHONE_ROOT_CERTIF "RootCertificate.pem"
#define LIBIPHONE_HOST_CERTIF "HostCertificate.pem"


/** Creates a freedesktop compatible configuration directory for libiphone.
 */
static void create_config_dir(void)
{
	gchar *config_dir = g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, NULL);

	if (!g_file_test(config_dir, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR)))
		g_mkdir_with_parents(config_dir, 0755);

	g_free(config_dir);
}

static int get_rand(int min, int max)
{
	int retval = (rand() % (max - min)) + min;
	return retval;
}

/** Generates a valid HostID (which is actually a UUID).
 *
 * @return A null terminated string containing a valid HostID.
 */
static char *lockdownd_generate_hostid()
{
	char *hostid = (char *) malloc(sizeof(char) * 37);	// HostID's are just UUID's, and UUID's are 36 characters long
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
	hostid[36] = '\0';			// make it a real string
	return hostid;
}

/** Store HostID in config file.
 *
 * @param host_id A null terminated string containing a valid HostID.
 */
static int write_host_id(char *host_id)
{
	GKeyFile *key_file;
	gsize length;
	gchar *buf, *config_file;
	GIOChannel *file;

	if (!host_id)
		return 0;

	/* Make sure config directory exists */
	create_config_dir();

	/* Now parse file to get the HostID */
	key_file = g_key_file_new();

	/* Store in config file */
	log_debug_msg("%s: setting hostID to %s\n", __func__, host_id);
	g_key_file_set_value(key_file, "Global", "HostID", host_id);

	/* Write config file on disk */
	buf = g_key_file_to_data(key_file, &length, NULL);
	config_file =
		g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, LIBIPHONE_CONF_FILE, NULL);
	file = g_io_channel_new_file(config_file, "w", NULL);
	g_free(config_file);
	g_io_channel_write_chars(file, buf, length, NULL, NULL);
	g_io_channel_shutdown(file, TRUE, NULL);
	g_io_channel_unref(file);

	g_key_file_free(key_file);
	return 1;
}

/** Reads the HostID from a previously generated configuration file.
 *
 * @note It is the responsibility of the calling function to free the returned host_id
 *
 * @return The string containing the HostID or NULL
 */
char *get_host_id(void)
{
	char *host_id = NULL;
	gchar *config_file;
	GKeyFile *key_file;
	gchar *loc_host_id;

	config_file =
		g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, LIBIPHONE_CONF_FILE, NULL);

	/* now parse file to get the HostID */
	key_file = g_key_file_new();
	if (g_key_file_load_from_file(key_file, config_file, G_KEY_FILE_KEEP_COMMENTS, NULL)) {
		loc_host_id = g_key_file_get_value(key_file, "Global", "HostID", NULL);
		if (loc_host_id)
			host_id = strdup((char *) loc_host_id);
		g_free(loc_host_id);
	}
	g_key_file_free(key_file);
	g_free(config_file);

	if (!host_id) {
		//no config, generate host_id
		host_id = lockdownd_generate_hostid();
		write_host_id(host_id);
	}

	log_debug_msg("%s: Using %s as HostID\n", __func__, host_id);
	return host_id;
}

/** Determines whether this iPhone has been connected to this system before.
 *
 * @param uid The device uid as given by the iPhone.
 *
 * @return 1 if the iPhone has been connected previously to this configuration
 *         or 0 otherwise.
 */
int is_device_known(char *uid)
{
	int ret = 0;
	gchar *config_file;

	/* first get config file */
	gchar *device_file = g_strconcat(uid, ".pem", NULL);
	config_file = g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, device_file, NULL);
	if (g_file_test(config_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)))
		ret = 1;
	g_free(config_file);
	g_free(device_file);
	return ret;
}

/** Mark the iPhone (as represented by the key) as having connected to this
 *  configuration.
 *
 * @param public_key The public key given by the iPhone
 *
 * @return 1 on success and 0 if no public key is given or if it has already
 *         been marked as connected previously.
 */
int store_device_public_key(char *uid, gnutls_datum_t public_key)
{

	if (NULL == public_key.data || is_device_known(uid))
		return 0;

	/* ensure config directory exists */
	create_config_dir();

	/* build file path */
	gchar *device_file = g_strconcat(uid, ".pem", NULL);
	gchar *pem = g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, device_file, NULL);

	/* store file */
	FILE *pFile = fopen(pem, "wb");
	fwrite(public_key.data, 1, public_key.size, pFile);
	fclose(pFile);
	g_free(pem);
	g_free(device_file);
	return 1;
}

/** Private function which reads the given file into a gnutls structure.
 *
 * @param file The filename of the file to read
 * @param data The pointer at which to store the data.
 *
 * @return 1 if the file contents where read successfully and 0 otherwise.
 */
static int read_file_in_confdir(const char *file, gnutls_datum_t * data)
{
	gboolean success;
	gsize size;
	char *content;
	gchar *filepath;

	if (NULL == file || NULL == data)
		return 0;

	/* Read file */
	filepath = g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, file, NULL);
	success = g_file_get_contents(filepath, &content, &size, NULL);
	g_free(filepath);

	/* Add it to the gnutls_datnum_t structure */
	data->data = (uint8_t*) content;
	data->size = size;

	return success;
}


/** Private function which generate private keys and certificates.
 *
 * @return IPHONE_E_SUCCESS if keys were successfully generated.
 */
static iphone_error_t gen_keys_and_cert(void)
{
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	gnutls_x509_privkey_t root_privkey;
	gnutls_x509_privkey_t host_privkey;
	gnutls_x509_crt_t root_cert;
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
	gnutls_datum_t root_key_pem = { NULL, 0 };
	gnutls_datum_t host_key_pem = { NULL, 0 };

	gnutls_x509_privkey_export(root_privkey, GNUTLS_X509_FMT_PEM, NULL, &root_key_pem.size);
	gnutls_x509_privkey_export(host_privkey, GNUTLS_X509_FMT_PEM, NULL, &host_key_pem.size);

	root_key_pem.data = gnutls_malloc(root_key_pem.size);
	host_key_pem.data = gnutls_malloc(host_key_pem.size);

	gnutls_x509_privkey_export(root_privkey, GNUTLS_X509_FMT_PEM, root_key_pem.data, &root_key_pem.size);
	gnutls_x509_privkey_export(host_privkey, GNUTLS_X509_FMT_PEM, host_key_pem.data, &host_key_pem.size);

	gnutls_datum_t root_cert_pem = { NULL, 0 };
	gnutls_datum_t host_cert_pem = { NULL, 0 };

	gnutls_x509_crt_export(root_cert, GNUTLS_X509_FMT_PEM, NULL, &root_cert_pem.size);
	gnutls_x509_crt_export(host_cert, GNUTLS_X509_FMT_PEM, NULL, &host_cert_pem.size);

	root_cert_pem.data = gnutls_malloc(root_cert_pem.size);
	host_cert_pem.data = gnutls_malloc(host_cert_pem.size);

	gnutls_x509_crt_export(root_cert, GNUTLS_X509_FMT_PEM, root_cert_pem.data, &root_cert_pem.size);
	gnutls_x509_crt_export(host_cert, GNUTLS_X509_FMT_PEM, host_cert_pem.data, &host_cert_pem.size);

	if (NULL != root_cert_pem.data && 0 != root_cert_pem.size &&
		NULL != host_cert_pem.data && 0 != host_cert_pem.size)
		ret = IPHONE_E_SUCCESS;

	/* store values in config file */
	init_config_file( &root_key_pem, &host_key_pem, &root_cert_pem, &host_cert_pem);

	gnutls_free(root_key_pem.data);
	gnutls_free(host_key_pem.data);
	gnutls_free(root_cert_pem.data);
	gnutls_free(host_cert_pem.data);

	//restore gnutls env
	gnutls_global_deinit();
	gnutls_global_init();

	return ret;
}

/** Private function which import the given key into a gnutls structure.
 *
 * @param key_name The filename of the private key to import.
 * @param key the gnutls key structure.
 *
 * @return IPHONE_E_SUCCESS if the key was successfully imported.
 */
static iphone_error_t import_key(const char* key_name, gnutls_x509_privkey_t key)
{
	iphone_error_t ret = IPHONE_E_INVALID_CONF;
	gnutls_datum_t pem_key = { NULL, 0 };

	if ( read_file_in_confdir(key_name, &pem_key) ) {
			if (GNUTLS_E_SUCCESS == gnutls_x509_privkey_import(key, &pem_key, GNUTLS_X509_FMT_PEM))
				ret = IPHONE_E_SUCCESS;
			else
				ret = IPHONE_E_SSL_ERROR;
	}
	gnutls_free(pem_key.data);
	return ret;
}

/** Private function which import the given certificate into a gnutls structure.
 *
 * @param crt_name The filename of the certificate to import.
 * @param cert the gnutls certificate structure.
 *
 * @return IPHONE_E_SUCCESS if the certificate was successfully imported.
 */
static iphone_error_t import_crt(const char* crt_name, gnutls_x509_crt_t cert)
{
	iphone_error_t ret = IPHONE_E_INVALID_CONF;
	gnutls_datum_t pem_cert = { NULL, 0 };

	if ( read_file_in_confdir(crt_name, &pem_cert) ) {
			if (GNUTLS_E_SUCCESS == gnutls_x509_crt_import(cert, &pem_cert, GNUTLS_X509_FMT_PEM))
				ret = IPHONE_E_SUCCESS;
			else
				ret = IPHONE_E_SSL_ERROR;
	}
	gnutls_free(pem_cert.data);
	return ret;
}

/** Function to retrieve host keys and certificates.
 * This function trigger key generation if they do not exists yet or are invalid.
 *
 * @note This function can take few seconds to complete (typically 5 seconds)
 *
 * @param root_privkey The root private key.
 * @param root_crt The root certificate.
 * @param host_privkey The host private key.
 * @param host_crt The host certificate.
 *
 * @return IPHONE_E_SUCCESS if the keys and certificates were successfully retrieved.
 */
iphone_error_t get_keys_and_certs(gnutls_x509_privkey_t root_privkey, gnutls_x509_crt_t root_crt, gnutls_x509_privkey_t host_privkey, gnutls_x509_crt_t host_crt)
{
  iphone_error_t ret = IPHONE_E_SUCCESS;

	if (ret == IPHONE_E_SUCCESS)
		ret = import_key(LIBIPHONE_ROOT_PRIVKEY, root_privkey);

	if (ret == IPHONE_E_SUCCESS)
		ret = import_key(LIBIPHONE_HOST_PRIVKEY, host_privkey);

	if (ret == IPHONE_E_SUCCESS)
		ret = import_crt(LIBIPHONE_ROOT_CERTIF, root_crt);

	if (ret == IPHONE_E_SUCCESS)
		ret = import_crt(LIBIPHONE_HOST_CERTIF, host_crt);


	if (IPHONE_E_SUCCESS != ret) {
		//we had problem reading or importing root cert
		//try with a new ones.
		ret = gen_keys_and_cert();

		if (ret == IPHONE_E_SUCCESS)
			ret = import_key(LIBIPHONE_ROOT_PRIVKEY, root_privkey);

		if (ret == IPHONE_E_SUCCESS)
			ret = import_key(LIBIPHONE_HOST_PRIVKEY, host_privkey);

		if (ret == IPHONE_E_SUCCESS)
			ret = import_crt(LIBIPHONE_ROOT_CERTIF, root_crt);

		if (ret == IPHONE_E_SUCCESS)
			ret = import_crt(LIBIPHONE_HOST_CERTIF, host_crt);
	}

	return ret;
}

/** Function to retrieve certificates encoded in PEM format.
 *
 * @param pem_root_cert The root certificate.
 * @param pem_host_cert The host certificate.
 *
 * @return IPHONE_E_SUCCESS if the certificates were successfully retrieved.
 */
iphone_error_t get_certs_as_pem(gnutls_datum_t *pem_root_cert, gnutls_datum_t *pem_host_cert)
{
	iphone_error_t ret = IPHONE_E_INVALID_CONF;

	if ( !pem_root_cert || !pem_host_cert)
		return IPHONE_E_INVALID_ARG;

	if ( read_file_in_confdir(LIBIPHONE_ROOT_CERTIF, pem_root_cert) && read_file_in_confdir(LIBIPHONE_HOST_CERTIF, pem_host_cert))
		ret = IPHONE_E_SUCCESS;
	else {
		g_free(pem_root_cert->data);
		g_free(pem_host_cert->data);
	}
	return ret;
}
/** Create and save a configuration file containing the given data.
 *
 * @note: All fields must specified and be non-null
 *
 * @param host_id The UUID of the host
 * @param root_key The root key
 * @param host_key The host key
 * @param root_cert The root certificate
 * @param host_cert The host certificate
 *
 * @return 1 on success and 0 otherwise.
 */
int init_config_file( gnutls_datum_t * root_key, gnutls_datum_t * host_key, gnutls_datum_t * root_cert,
					 gnutls_datum_t * host_cert)
{
	FILE *pFile;
	gchar *pem;

	if (!root_key || !host_key || !root_cert || !host_cert)
		return 0;

	/* Make sure config directory exists */
	create_config_dir();

	/* Now write keys and certificates to disk */
	pem = g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, LIBIPHONE_ROOT_PRIVKEY, NULL);
	pFile = fopen(pem, "wb");
	fwrite(root_key->data, 1, root_key->size, pFile);
	fclose(pFile);
	g_free(pem);

	pem = g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, LIBIPHONE_HOST_PRIVKEY, NULL);
	pFile = fopen(pem, "wb");
	fwrite(host_key->data, 1, host_key->size, pFile);
	fclose(pFile);
	g_free(pem);

	pem = g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, LIBIPHONE_ROOT_CERTIF, NULL);
	pFile = fopen(pem, "wb");
	fwrite(root_cert->data, 1, root_cert->size, pFile);
	fclose(pFile);
	g_free(pem);

	pem = g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, LIBIPHONE_HOST_CERTIF, NULL);
	pFile = fopen(pem, "wb");
	fwrite(host_cert->data, 1, host_cert->size, pFile);
	fclose(pFile);
	g_free(pem);

	return 1;
}
