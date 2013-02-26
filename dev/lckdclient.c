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
#include <readline/readline.h>
#include <readline/history.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

static char** get_tokens(const char *str)
{
	char *strcp = strdup(str);
	char *p;
	char res_max = 8;
	char **result = NULL;
	int cnt = 0;

	p = strtok(strcp, " ");
	if (!p) {
		result = (char**)malloc(2 * sizeof(char*));
		result[0] = strdup(str);
		result[1] = NULL;
		return result;
	}

	result = (char**)malloc(res_max * sizeof(char*));
	memset(result, 0, res_max * sizeof(char*));

	while (p) {
		if (cnt >= res_max) {
			res_max += 8;
			result = (char**)realloc(result, res_max * sizeof(char*));
		}
		result[cnt] = strdup(p);
		cnt++;
		p = strtok(NULL, " ");
	}

	if (cnt >= res_max) {
		res_max += 1;
		result = (char**)realloc(result, res_max * sizeof(char*));
		result[cnt] = NULL;
	}

	return result;
}

static void strfreev(char **strs)
{
	int i = 0;
	while (strs && strs[i]) {
		free(strs[i]);
		i++;
	}
	free(strs);
}

int main(int argc, char *argv[])
{
	lockdownd_client_t client = NULL;
	idevice_t phone = NULL;

	idevice_set_debug_level(1);

	if (IDEVICE_E_SUCCESS != idevice_new(&phone, NULL)) {
		printf("No device found, is it plugged in?\n");
		return -1;
	}

	char *udid = NULL;
	if (IDEVICE_E_SUCCESS == idevice_get_udid(phone, &udid)) {
		printf("DeviceUniqueID : %s\n", udid);
	}
	if (udid)
		free(udid);

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(phone, &client, "lckdclient")) {
		idevice_free(phone);
		return -1;
	}

	using_history();
	int loop = 1;
	while (loop) {
		char *cmd = readline("> ");
		if (cmd) {

			char **args = get_tokens(cmd);

			int len = 0;
			while (args && args[len]) {
				len++;
			}

			if (len > 0) {
				add_history(cmd);
				if (!strcmp(*args, "quit"))
					loop = 0;

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
					lockdownd_service_descriptor_t service = NULL;
					if(LOCKDOWN_E_SUCCESS == lockdownd_start_service(client, *(args + 1), &service)) {
						printf("started service %s on port %i\n", *(args + 1), service->port);
						if (service) {
							lockdownd_service_descriptor_free(service);
							service = NULL;
						}
					}
					else
					{
						printf("failed to start service %s on device.\n", *(args + 1));
					}
				}
			}
			strfreev(args);
		}
		free(cmd);
		cmd = NULL;
	}
	clear_history();
	lockdownd_client_free(client);
	idevice_free(phone);

	return 0;
}
