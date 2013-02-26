/*
 * housearresttest.c
 * Simple Test program showing the usage of the house_arrest interface.
 *
 * Copyright (c) 2010 Nikias Bassen All Rights Reserved.
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

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/house_arrest.h>
#include <libimobiledevice/afc.h>

static void print_usage(int argc, char **argv)
{
	char *name = NULL;
	
	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] APPID\n", (name ? name + 1: argv[0]));
	printf("Test the house_arrest service.\n\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
	printf("  -t, --test\t\ttest creating, writing, and deleting a file\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
}

int main(int argc, char **argv)
{
	idevice_t dev = NULL;
	lockdownd_client_t client = NULL;
	house_arrest_client_t hac = NULL;
	house_arrest_error_t res;
	int i;
	char *udid = NULL;
	const char *appid = NULL;
	int test_file_io = 0;

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udid")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) != 40)) {
				print_usage(argc, argv);
				return 0;
			}
			udid = strdup(argv[i]);
			continue;
		}
		else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--test")) {
			test_file_io = 1;
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
		else {
			appid = argv[i];
			break;
		}
	}

	if (!appid) {
		print_usage(argc, argv);
		return 0;
	}

	if (idevice_new(&dev, udid) != IDEVICE_E_SUCCESS) {
		printf("no device connected?!\n");
		goto leave_cleanup;
	}

	if (lockdownd_client_new_with_handshake(dev, &client, NULL) != LOCKDOWN_E_SUCCESS) {
		printf("could not connect to lockdownd!\n");
		goto leave_cleanup;
	}

	lockdownd_service_descriptor_t service = NULL;
	if (lockdownd_start_service(client, "com.apple.mobile.house_arrest", &service) != LOCKDOWN_E_SUCCESS) {
		printf("could not start house_arrest service!\n");
		goto leave_cleanup;
	}

	if (client) {
		lockdownd_client_free(client);
		client = NULL;
	}

	if (house_arrest_client_new(dev, service, &hac) != HOUSE_ARREST_E_SUCCESS) {
		printf("could not connect to house_arrest service!\n");
		goto leave_cleanup;
	}

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

	res = house_arrest_send_command(hac, "VendDocuments", appid);
	if (res != HOUSE_ARREST_E_SUCCESS) {
		printf("error %d when trying to get VendDocuments\n", res);
		goto leave_cleanup;
	}

	plist_t dict = NULL;
	if (house_arrest_get_result(hac, &dict) != HOUSE_ARREST_E_SUCCESS) {
		if (house_arrest_get_result(hac, &dict) != HOUSE_ARREST_E_SUCCESS) {
			printf("hmmm....\n");
			goto leave_cleanup;
		}
	}

	plist_t node = plist_dict_get_item(dict, "Error");
	if (node) {
		char *str = NULL;
		plist_get_string_val(node, &str);
		printf("Error: %s\n", str);
		if (str) free(str);
		plist_free(dict);
		dict = NULL;
		goto leave_cleanup;
	}
	node = plist_dict_get_item(dict, "Status");
	if (node) {
		char *str = NULL;
		plist_get_string_val(node, &str);
		if (str && (strcmp(str, "Complete") != 0)) {
			printf("Warning: Status is not 'Complete' but '%s'\n", str);
		}
		if (str) free(str);
		plist_free(dict);
		dict = NULL;
	}
	if (dict) {
		plist_free(dict);
	}

	afc_client_t afc = NULL;
	afc_error_t ae = afc_client_new_from_house_arrest_client(hac, &afc);
	if (ae != AFC_E_SUCCESS) {
		printf("afc error %d\n", ae);
	}
	if (ae == AFC_E_SUCCESS) {
		char **list = NULL;
		afc_read_directory(afc, "/", &list);
		printf("Directory contents:\n");
		if (list) {
			while (list[0]) {
				if (strcmp(list[0], ".") && strcmp(list[0], "..")) {
					puts(list[0]);
				}
				list++;
			}
		}

		if (test_file_io) {
			uint64_t tf = 0;
			printf("\n==== Performing file tests ====\n");
			printf("Opening file 'foobar' for writing: ");
			if (afc_file_open(afc, "/foobar", AFC_FOPEN_RW, &tf) == AFC_E_SUCCESS) {
				uint32_t wb = 0;
				printf("OK\n");

				printf("Writing to file: ");
				if (afc_file_write(afc, tf, "test\r\n", 6, &wb) != AFC_E_SUCCESS) {
					printf("ERROR\n");
				} else {
					printf("OK\n");
				}
				afc_file_close(afc, tf);
				printf("Deleting file 'foobar': ");
				if (afc_remove_path(afc, "/foobar") == AFC_E_SUCCESS) {
					printf("OK\n");
				} else {
					printf("ERROR\n");
				}
			} else {
				printf("ERROR\n");
			}
		}
		afc_client_free(afc);
	} else {
		printf("failed to connect to afc service, error %d\n", ae);
	}

leave_cleanup:
	if (hac) {
		house_arrest_client_free(hac);
	}
	if (client) {
		lockdownd_client_free(client);
	}
	if (dev) {
		idevice_free(dev);
	}

	return 0;
}
