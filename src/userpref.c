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

#define LIBIPHONE_CONF_DIR  "libiphone"
#define LIBIPHONE_CONF_FILE "libiphonerc"

extern int debug;

inline void create_config_dir() {
	gchar* config_dir = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR, NULL);
	g_mkdir_with_parents (config_dir, 755);
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
						if (strcmp(public_key, stored_key) == 2)
							ret = 1;
						g_free(stored_key);
						g_io_channel_shutdown(keyfile, FALSE, NULL);
						pcur++;
					}
				}
			}
			g_strfreev(devices_list);
		}
		g_key_file_free(key_file);
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
			if (devices_list)
				g_strv_length(devices_list);
			g_strfreev(devices_list);

			gchar dev_file[20];
			g_sprintf (dev_file, "Device%i", length);

			gchar* device_file = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  dev_file, NULL);
			GIOChannel* file = g_io_channel_new_file (device_file, "w", NULL);
			g_io_channel_write_chars (file, public_key, length, NULL, NULL);
			g_io_channel_shutdown(file, FALSE, NULL);
				
			/* append device to list */
			gchar** new_devices_list = (gchar**)g_malloc(sizeof(gchar*)* (length + 1));
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
		g_io_channel_shutdown(file, FALSE, NULL);
		g_key_file_free(key_file);
	}

	return 1;
}


char* get_root_private_key()
{
	char* private_key = NULL;

	/* first get config file */
	gchar* config_file = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  LIBIPHONE_CONF_FILE, NULL);
	if (g_file_test(config_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {

		/* now parse file to get knwon devices list */
		GKeyFile* key_file = g_key_file_new ();
		if( g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_KEEP_COMMENTS, NULL) ) {

			gchar* loc_private_key = g_key_file_get_value(key_file, "Global", "RootPrivateKey", NULL);
			if (loc_private_key)
				private_key = strdup((char*)loc_private_key);
			g_free(loc_private_key);
		}
		g_key_file_free(key_file);
	}
	return private_key;
}

char* get_host_private_key()
{
	char* private_key = NULL;

	/* first get config file */
	gchar* config_file = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  LIBIPHONE_CONF_FILE, NULL);
	if (g_file_test(config_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {

		/* now parse file to get knwon devices list */
		GKeyFile* key_file = g_key_file_new ();
		if( g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_KEEP_COMMENTS, NULL) ) {

			gchar* loc_private_key = g_key_file_get_value(key_file, "Global", "HostPrivateKey", NULL);
			if (loc_private_key)
				private_key = strdup((char*)loc_private_key);
			g_free(loc_private_key);
		}
		g_key_file_free(key_file);
	}
	return private_key;
}


char* get_root_certificate()
{
	char* cert = NULL;

	/* first get config file */
	gchar* config_file = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  LIBIPHONE_CONF_FILE, NULL);
	if (g_file_test(config_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {

		/* now parse file to get knwon devices list */
		GKeyFile* key_file = g_key_file_new ();
		if( g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_KEEP_COMMENTS, NULL) ) {

			gchar* loc_cert = g_key_file_get_value(key_file, "Global", "RootCertificate", NULL);
			if (loc_cert)
				cert = strdup((char*)loc_cert);
			g_free(loc_cert);
		}
		g_key_file_free(key_file);
	}
	return cert;
}

char* get_host_certificate()
{
	char* cert = NULL;

	/* first get config file */
	gchar* config_file = g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  LIBIPHONE_CONF_FILE, NULL);
	if (g_file_test(config_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {

		/* now parse file to get knwon devices list */
		GKeyFile* key_file = g_key_file_new ();
		if( g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_KEEP_COMMENTS, NULL) ) {

			gchar* loc_cert = g_key_file_get_value(key_file, "Global", "HostCertificate", NULL);
			if (loc_cert)
				cert = strdup((char*)loc_cert);
			g_free(loc_cert);
		}
		g_key_file_free(key_file);
	}
	return cert;
}

int init_config_file(char* host_id, char* root_private_key, char* host_private_key, char* root_cert, char* host_cert)
{
	if (!host_id || !root_private_key || !host_private_key)
		return 0;

	gchar* config_file =  g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  LIBIPHONE_CONF_FILE, NULL);
	/* make sure config directory exists*/
	create_config_dir();

	/* now parse file to get the HostID */
	GKeyFile* key_file = g_key_file_new ();

	/* store in config file */
	g_key_file_set_value (key_file, "Global", "HostID", host_id);
	g_key_file_set_value (key_file, "Global", "RootPrivateKey", root_private_key);
	g_key_file_set_value (key_file, "Global", "HostPrivateKey", host_private_key);
	g_key_file_set_value (key_file, "Global", "RootCertificate", root_cert);
	g_key_file_set_value (key_file, "Global", "HostCertificate", host_cert);

	/* write config file on disk */
	gsize length;
	gchar* buf = g_key_file_to_data (key_file, &length,NULL);
	GIOChannel* file = g_io_channel_new_file (config_file, "w", NULL);
	g_io_channel_write_chars (file, buf, length, NULL, NULL);
	g_io_channel_shutdown(file, FALSE, NULL);

	g_key_file_free(key_file);

	return 1;
}
