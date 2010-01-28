/*
 * lckdclient.c
 * Rudimentary command line interface to the Lockdown protocol
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <readline/readline.h>
#include <readline/history.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

int main(int argc, char *argv[])
{
	lockdownd_client_t client = NULL;
	idevice_t phone = NULL;

	idevice_set_debug_level(1);

	if (IDEVICE_E_SUCCESS != idevice_new(&phone, NULL)) {
		printf("No device found, is it plugged in?\n");
		return -1;
	}

	char *uuid = NULL;
	if (IDEVICE_E_SUCCESS == idevice_get_uuid(phone, &uuid)) {
		printf("DeviceUniqueID : %s\n", uuid);
	}
	if (uuid)
		free(uuid);

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(phone, &client, "lckdclient")) {
		idevice_free(phone);
		return -1;
	}

	using_history();
	int loop = TRUE;
	while (loop) {
		char *cmd = readline("> ");
		if (cmd) {

			gchar **args = g_strsplit(cmd, " ", 0);

			int len = 0;
			if (args) {
				while (*(args + len)) {
					g_strstrip(*(args + len));
					len++;
				}
			}

			if (len > 0) {
				add_history(cmd);
				if (!strcmp(*args, "quit"))
					loop = FALSE;

				if (!strcmp(*args, "get") && len >= 2) {
					plist_t value = NULL;
					if (LOCKDOWN_E_SUCCESS == lockdownd_get_value(client, len == 3 ? *(args + 1):NULL,  len == 3 ? *(args + 2):*(args + 1), &value))
					{
						char *xml = NULL;
						uint32_t length;
						plist_to_xml(value, &xml, &length);
						printf("Success : value = %s\n", xml);
						free(xml);
					}
					else
						printf("Error\n");

					if (value)
						plist_free(value);
				}

				if (!strcmp(*args, "start") && len == 2) {
					uint16_t port = 0;
					if(LOCKDOWN_E_SUCCESS == lockdownd_start_service(client, *(args + 1), &port)) {
						printf("started service %s on port %i\n", *(args + 1), port);
					}
					else
					{
						printf("failed to start service %s on device.\n", *(args + 1));
					}
				}
			}
			g_strfreev(args);
		}
		free(cmd);
		cmd = NULL;
	}
	clear_history();
	lockdownd_client_free(client);
	idevice_free(phone);

	return 0;
}
