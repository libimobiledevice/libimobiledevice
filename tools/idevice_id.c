/*
 * idevice_id.c
 * Prints device name or a list of attached devices
 *
 * Copyright (C) 2010-2018 Nikias Bassen <nikias@gmx.li>
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

#define TOOL_NAME "idevice_id"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define MODE_NONE 0
#define MODE_SHOW_ID 1
#define MODE_LIST_DEVICES 2

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] [UDID]\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"List attached devices or print device name of given device.\n"
		"\n" \
		"  If UDID is given, the name of the connected device with that UDID"
		"  will be retrieved.\n"
		"\n" \
		"OPTIONS:\n"
		"  -l, --list      list UDIDs of all devices attached via USB\n"
		"  -n, --network   list UDIDs of all devices available via network\n"
		"  -d, --debug     enable communication debugging\n"
		"  -h, --help      prints usage information\n"
		"  -v, --version   prints version information\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	lockdownd_client_t client = NULL;
	idevice_info_t *dev_list = NULL;
	char *device_name = NULL;
	int ret = 0;
	int i;
	int mode = MODE_LIST_DEVICES;
	int include_usb = 0;
	int include_network = 0;
	const char* udid = NULL;

	int c = 0;
	const struct option longopts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help",  no_argument, NULL, 'h' },
		{ "list",  no_argument, NULL, 'l' },
		{ "network", no_argument, NULL, 'n' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0}
	};

	while ((c = getopt_long(argc, argv, "dhlnv", longopts, NULL)) != -1) {
		switch (c) {
		case 'd':
			idevice_set_debug_level(1);
			break;
		case 'h':
			print_usage(argc, argv, 0);
			exit(EXIT_SUCCESS);
		case 'l':
			mode = MODE_LIST_DEVICES;
			include_usb = 1;
			break;
		case 'n':
			mode = MODE_LIST_DEVICES;
			include_network = 1;
			break;
		case 'v':
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			return 0;
		default:
			print_usage(argc, argv, 1);
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 1) {
		mode = MODE_SHOW_ID;
	} else if (argc == 0 && optind == 1) {
		include_usb = 1;
		include_network = 1;
	}
	udid = argv[0];

	switch (mode) {
	case MODE_SHOW_ID:
		idevice_new_with_options(&device, udid, IDEVICE_LOOKUP_USBMUX | IDEVICE_LOOKUP_NETWORK);
		if (!device) {
			fprintf(stderr, "ERROR: No device with UDID %s attached.\n", udid);
			return -2;
		}

		if (LOCKDOWN_E_SUCCESS != lockdownd_client_new(device, &client, TOOL_NAME)) {
			idevice_free(device);
			fprintf(stderr, "ERROR: Connecting to device failed!\n");
			return -2;
		}

		if ((LOCKDOWN_E_SUCCESS != lockdownd_get_device_name(client, &device_name)) || !device_name) {
			fprintf(stderr, "ERROR: Could not get device name!\n");
			ret = -2;
		}

		lockdownd_client_free(client);
		idevice_free(device);

		if (ret == 0) {
			printf("%s\n", device_name);
		}

		if (device_name) {
			free(device_name);
		}
		break;

	case MODE_LIST_DEVICES:
	default:
		if (idevice_get_device_list_extended(&dev_list, &i) < 0) {
			fprintf(stderr, "ERROR: Unable to retrieve device list!\n");
			return -1;
		}
		for (i = 0; dev_list[i] != NULL; i++) {
			if (dev_list[i]->conn_type == CONNECTION_USBMUXD && !include_usb) continue;
			if (dev_list[i]->conn_type == CONNECTION_NETWORK && !include_network) continue;
			printf("%s", dev_list[i]->udid);
			if (include_usb && include_network) {
				if (dev_list[i]->conn_type == CONNECTION_NETWORK) {
					printf(" (Network)");
				} else {
					printf(" (USB)");
				}
			}
			printf("\n");
		}
		idevice_device_list_extended_free(dev_list);
		break;
	}
	return ret;
}
