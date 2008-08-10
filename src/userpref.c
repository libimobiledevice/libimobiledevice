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
#include <stdio.h>
#include <string.h>
#include "userpref.h"
#include <string.h>
#include <stdio.h>


#define LIBIPHONE_CONF_DIR  "libiphone"
#define LIBIPHONE_CONF_FILE "libiphonerc"

#define LIBIPHONE_ROOT_PRIVKEY  "RootPrivateKey.pem"
#define LIBIPHONE_HOST_PRIVKEY  "HostPrivateKey.pem"
#define LIBIPHONE_ROOT_CERTIF  "RootCertificate.pem"
#define LIBIPHONE_HOST_CERTIF  "HostCertificate.pem"


extern int debug;

inline void create_config_dir() {
	gchar* config_dir = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR, NULL);
	g_mkdir_with_parents (config_dir, 755);
	g_free(config_dir);
	return;
}

char* get_host_id()
{
	char* host_id = NULL;
	gchar* config_file =  g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  LIBIPHONE_CONF_FILE, NULL);

	/* now parse file to get the HostID */
	GKeyFile* key_file = g_key_file_new ();
	if( g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_KEEP_COMMENTS, NULL) ) {

		gchar* loc_host_id = g_key_file_get_value(key_file, "Global", "HostID", NULL);
		if (loc_host_id)
			host_id = strdup((char*)loc_host_id);
		g_free(loc_host_id);
	}
	g_key_file_free(key_file);
	g_free(config_file);

	if (debug) printf("Using %s as HostID\n",host_id);
	return host_id;
}

int is_device_known(char* public_key)
{
	int ret = 0;

	/* first get config file */
	gchar* config_file = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  LIBIPHONE_CONF_FILE, NULL);
	if (g_file_test(config_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {

		/* now parse file to get knwon devices list */
		GKeyFile* key_file = g_key_file_new ();
		if( g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_KEEP_COMMENTS, NULL) ) {

			gchar** devices_list = g_key_file_get_string_list (key_file, "Global", "DevicesList", NULL, NULL);
			if (devices_list) {
				gchar** pcur = devices_list;
				while(*pcur && !ret) {
					/* open associated base64 encoded key */
					gchar* keyfilepath = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR, *pcur, NULL);
					if (g_file_test(keyfilepath, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
						GIOChannel* keyfile = g_io_channel_new_file (keyfilepath, "r", NULL);
						
						gchar* stored_key = NULL;
						g_io_channel_read_to_end (keyfile, &stored_key, NULL, NULL);

						/* now compare to input */
						if (strcmp(public_key, stored_key) == 2 || !strcmp(public_key, stored_key))
							ret = 1;
						g_free(stored_key);
						g_io_channel_shutdown(keyfile, FALSE, NULL);
						pcur++;
					}
					g_free(keyfilepath);
				}
			}
			g_strfreev(devices_list);
		}
		g_key_file_free(key_file);
		g_free(config_file);
	}
	return ret;
}

int store_device_public_key(char* public_key)
{
	if (NULL == public_key || is_device_known(public_key))
		return 0;

	/* first get config file */
	gchar* config_file = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  LIBIPHONE_CONF_FILE, NULL);
	if (g_file_test(config_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {


		GKeyFile* key_file = g_key_file_new ();
		if( g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_KEEP_COMMENTS, NULL) ) {

	 		gchar** devices_list = g_key_file_get_string_list (key_file, "Global", "DevicesList", NULL, NULL);

			guint length = 0;
			guint wlength = 0;
			if (devices_list)
				g_strv_length(devices_list);
			g_strfreev(devices_list);

			gchar dev_file[20];
			g_sprintf (dev_file, "Device%i", length);

			gchar* device_file = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  dev_file, NULL);
			GIOChannel* file = g_io_channel_new_file (device_file, "w", NULL);
			g_free (device_file);
			wlength = strlen(public_key); // why this wasn't discovered before... ugh
			g_io_channel_write_chars (file, public_key, wlength, NULL, NULL);
			g_io_channel_shutdown(file, TRUE, NULL);
				
			/* append device to list */
			gchar** new_devices_list = (gchar**)g_malloc(sizeof(gchar*)* (length + 2));
			int i;
			for( i = 0; i < length; i++)
				new_devices_list[i] = devices_list[i];
			new_devices_list[length] = dev_file;
			new_devices_list[length+1] = NULL;
			g_key_file_set_string_list (key_file,"Global", "DevicesList", new_devices_list, length+1);
			g_free(new_devices_list);

		}
		gsize length;
		gchar* buf = g_key_file_to_data (key_file, &length,NULL);
		GIOChannel* file = g_io_channel_new_file (config_file, "w", NULL);
		g_io_channel_write_chars (file, buf, length, NULL, NULL);
		g_io_channel_shutdown(file, TRUE, NULL);
		g_key_file_free(key_file);
	}

	return 1;
}

int read_file_in_confdir(char* file, gnutls_datum_t* data)
{
	if (NULL == file || NULL == data)
		return 0;

	gchar* filepath = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  file, NULL);
	gboolean success;
	gsize size;
	char *content;		
	success = g_file_get_contents (filepath, &content, &size, NULL);
	g_free (filepath);
	data->data = content;
	data->size = size;
	return success;
}

int get_root_private_key(gnutls_datum_t* root_privkey)
{
	return read_file_in_confdir(LIBIPHONE_ROOT_PRIVKEY, root_privkey);
}

int get_host_private_key(gnutls_datum_t* host_privkey)
{
	return read_file_in_confdir(LIBIPHONE_HOST_PRIVKEY, host_privkey);
}

int get_root_certificate(gnutls_datum_t* root_cert)
{
	return read_file_in_confdir(LIBIPHONE_ROOT_CERTIF, root_cert);
}

int get_host_certificate(gnutls_datum_t* host_cert)
{
	return read_file_in_confdir(LIBIPHONE_HOST_CERTIF, host_cert);
}

int init_config_file(char* host_id, gnutls_datum_t* root_key, gnutls_datum_t* host_key, gnutls_datum_t* root_cert, gnutls_datum_t* host_cert)
{
	if (!host_id || !root_key || !host_key || !root_cert || !host_cert)
		return 0;

	/* make sure config directory exists*/
	create_config_dir();

	/* now parse file to get the HostID */
	GKeyFile* key_file = g_key_file_new ();

	/* store in config file */
	if (debug) printf("init_config_file setting hostID to %s\n", host_id);
	g_key_file_set_value (key_file, "Global", "HostID", host_id);

	/* write config file on disk */
	gsize length;
	gchar* buf = g_key_file_to_data (key_file, &length,NULL);
	gchar* config_file =  g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  LIBIPHONE_CONF_FILE, NULL);
	GIOChannel* file = g_io_channel_new_file (config_file, "w", NULL);
	g_free (config_file);
	g_io_channel_write_chars (file, buf, length, NULL, NULL);
	g_io_channel_shutdown(file, TRUE, NULL);

	g_key_file_free(key_file);

	//now write keys and certifs to disk
	FILE * pFile;
	gchar* pem;
	pem = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR, LIBIPHONE_ROOT_PRIVKEY, NULL);
	pFile = fopen ( pem , "wb" );
	fwrite ( root_key->data, 1 , root_key->size , pFile );
	fclose (pFile);
	g_free (pem);

	pem = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR, LIBIPHONE_HOST_PRIVKEY, NULL);
	pFile = fopen ( pem , "wb" );
	fwrite ( host_key->data, 1 , host_key->size , pFile );
	fclose (pFile);
	g_free (pem);

	pem = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR, LIBIPHONE_ROOT_CERTIF, NULL);
	pFile = fopen ( pem , "wb" );
	fwrite ( root_cert->data, 1 , root_cert->size , pFile );
	fclose (pFile);
	g_free (pem);

	pem = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR, LIBIPHONE_HOST_CERTIF, NULL);
	pFile = fopen ( pem , "wb" );
	fwrite ( host_cert->data, 1 , host_cert->size , pFile );
	fclose (pFile);
	g_free (pem);

	return 1;
}
