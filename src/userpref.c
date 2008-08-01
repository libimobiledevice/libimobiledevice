/*
 * userpref.c
 * contains methods to access user specific certificates IDs and more.
 *
 * Copyright (c) 2008 Jonathan Beck All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. 
 */

#include <glib.h>
#include "userpref.h"

#define LIBIPHONE_CONF_DIR  "libiphone"
#define LIBIPHONE_CONF_FILE "libiphonerc"

extern int debug;

char* get_host_id()
{
	char* host_id = NULL;
	gchar* config_file = NULL;

	/* first get config file */
	config_file =  g_build_path(G_DIR_SEPARATOR_S,  g_get_user_config_dir(), LIBIPHONE_CONF_DIR,  LIBIPHONE_CONF_FILE, NULL);
	if (g_file_test(config_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {

		/*now parse file to get the HostID*/
		GKeyFile* key_file = g_key_file_new ();
		if( g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_KEEP_COMMENTS, NULL) ) {

			gchar* loc_host_id =  g_key_file_get_value(key_file, "Global", "HostID", NULL);
			if (loc_host_id)
				host_id = strdup(loc_host_id);
			g_free(loc_host_id);
		}
		g_key_file_free(key_file);
	}
	if (debug) printf("Using %s as HostID\n",host_id);
	return host_id;
}

