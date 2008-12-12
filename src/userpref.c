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
#include <string.h>
#include "userpref.h"
#include "utils.h"
#include <string.h>
#include <stdlib.h>

#define LIBIPHONE_CONF_DIR  "libiphone"
#define LIBIPHONE_CONF_FILE "libiphonerc"

#define LIBIPHONE_ROOT_PRIVKEY "RootPrivateKey.pem"
#define LIBIPHONE_HOST_PRIVKEY "HostPrivateKey.pem"
#define LIBIPHONE_ROOT_CERTIF "RootCertificate.pem"
#define LIBIPHONE_HOST_CERTIF "HostCertificate.pem"


/** Creates a freedesktop compatible configuration directory for libiphone.
 */
inline void create_config_dir()
{
	gchar *config_dir = g_build_path(G_DIR_SEPARATOR_S, g_get_user_config_dir(), LIBIPHONE_CONF_DIR, NULL);

	if (!g_file_test(config_dir, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR)))
		g_mkdir_with_parents(config_dir, 0755);

	g_free(config_dir);
}


/** Reads the HostID from a previously generated configuration file. 
 * 
 * @note It is the responsibility of the calling function to free the returned host_id
 *
 * @return The string containing the HostID or NULL
 */
char *get_host_id()
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

	log_debug_msg("get_host_id(): Using %s as HostID\n", host_id);
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
	GKeyFile *key_file;
	gchar **devices_list, **pcur, *keyfilepath, *stored_key;
	GIOChannel *keyfile;

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
int read_file_in_confdir(char *file, gnutls_datum_t * data)
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
	data->data = content;
	data->size = size;

	return success;
}

/** Read the root private key
 *
 * @param root_privkey A pointer to the appropriate gnutls structure
 *
 * @return 1 if the file was successfully read and 0 otherwise.
 */
int get_root_private_key(gnutls_datum_t * root_privkey)
{
	return read_file_in_confdir(LIBIPHONE_ROOT_PRIVKEY, root_privkey);
}

/** Read the host private key
 *
 * @param host_privkey A pointer to the appropriate gnutls structure
 *
 * @return 1 if the file was successfully read and 0 otherwise.
 */
int get_host_private_key(gnutls_datum_t * host_privkey)
{
	return read_file_in_confdir(LIBIPHONE_HOST_PRIVKEY, host_privkey);
}

/** Read the root certificate
 *
 * @param root_privkey A pointer to the appropriate gnutls structure
 *
 * @return 1 if the file was successfully read and 0 otherwise.
 */
int get_root_certificate(gnutls_datum_t * root_cert)
{
	return read_file_in_confdir(LIBIPHONE_ROOT_CERTIF, root_cert);
}

/** Read the host certificate
 *
 * @param root_privkey A pointer to the appropriate gnutls structure
 *
 * @return 1 if the file was successfully read and 0 otherwise.
 */
int get_host_certificate(gnutls_datum_t * host_cert)
{
	return read_file_in_confdir(LIBIPHONE_HOST_CERTIF, host_cert);
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
int init_config_file(char *host_id, gnutls_datum_t * root_key, gnutls_datum_t * host_key, gnutls_datum_t * root_cert,
					 gnutls_datum_t * host_cert)
{
	FILE *pFile;
	gchar *pem;
	GKeyFile *key_file;
	gsize length;
	gchar *buf, *config_file;
	GIOChannel *file;

	if (!host_id || !root_key || !host_key || !root_cert || !host_cert)
		return 0;

	/* Make sure config directory exists */
	create_config_dir();

	/* Now parse file to get the HostID */
	key_file = g_key_file_new();

	/* Store in config file */
	log_debug_msg("init_config_file(): setting hostID to %s\n", host_id);
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
