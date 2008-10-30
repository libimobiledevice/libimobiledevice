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
#include <string.h>
#include <glib.h>
#include <readline/readline.h>
#include <readline/history.h>

#include <libiphone/libiphone.h>


int main(int argc, char *argv[])
{
	int bytes = 0, port = 0, i = 0;
	iphone_lckd_client_t control = NULL;
	iphone_device_t phone = NULL;

	iphone_set_debug(1);

	if (IPHONE_E_SUCCESS != iphone_get_device(&phone)) {
		printf("No iPhone found, is it plugged in?\n");
		return -1;
	}

	if (IPHONE_E_SUCCESS != iphone_lckd_new_client(phone, &control)) {
		iphone_free_device(phone);
		return -1;
	}

	char *uid = NULL;
	if (IPHONE_E_SUCCESS == lockdownd_get_device_uid(control, &uid)) {
		printf("DeviceUniqueID : %s\n", uid);
		free(uid);
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

				if (!strcmp(*args, "get") && len == 3) {
					char *value = NULL;
					if (IPHONE_E_SUCCESS == lockdownd_generic_get_value(control, *(args + 1), *(args + 2), &value))
						printf("Success : value = %s\n", value);
					else
						printf("Error\n");
				}

				if (!strcmp(*args, "start") && len == 2) {
					int port = 0;
					iphone_lckd_start_service(control, *(args + 1), &port);
					printf("%i\n", port);
				}
			}
			g_strfreev(args);
		}
		free(cmd);
		cmd = NULL;
	}
	clear_history();
	iphone_lckd_free_client(control);
	iphone_free_device(phone);

	return 0;
}
