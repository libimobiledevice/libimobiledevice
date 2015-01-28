/*
 * idevice_id.c
 * Prints device name or a list of attached devices
 *
 * Copyright (C) 2010 Nikias Bassen <nikias@gmx.li>
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
#include <stdlib.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define MODE_NONE 0
#define MODE_SHOW_ID 1
#define MODE_LIST_DEVICES 2

static void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] [UDID]\n", (name ? name + 1: argv[0]));
	printf("Prints device name or a list of attached devices.\n\n");
	printf("  The UDID is a 40-digit hexadecimal number of the device\n");
	printf("  for which the name should be retrieved.\n\n");
	printf("  -l, --list\t\tlist UDID of all attached devices\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
	printf("Homepage: <http://libimobiledevice.org>\n");
}

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	lockdownd_client_t client = NULL;
	char **dev_list = NULL;
	char *device_name = NULL;
	int ret = 0;
	int i;
	int mode = MODE_SHOW_ID;
	const char* udid = NULL;

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--list")) {
			mode = MODE_LIST_DEVICES;
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
	}

	/* check if udid was passed */
	if (mode == MODE_SHOW_ID) {
		i--;
		if (!argv[i] || (strlen(argv[i]) != 40)) {
			print_usage(argc, argv);
			return 0;
		}
		udid = argv[i];
	}

	switch (mode) {
	case MODE_SHOW_ID:
		idevice_new(&device, udid);
		if (!device) {
			fprintf(stderr, "ERROR: No device with UDID=%s attached.\n", udid);
			return -2;
		}

		if (LOCKDOWN_E_SUCCESS != lockdownd_client_new(device, &client, "idevice_id")) {
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

		return ret;
	case MODE_LIST_DEVICES:
	default:
		if (idevice_get_device_list(&dev_list, &i) < 0) {
			fprintf(stderr, "ERROR: Unable to retrieve device list!\n");
			return -1;
		}
		for (i = 0; dev_list[i] != NULL; i++) {
			printf("%s\n", dev_list[i]);
		}
		idevice_device_list_free(dev_list);
		return 0;
	}
}
