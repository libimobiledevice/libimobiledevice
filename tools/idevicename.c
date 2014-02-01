/*
 * idevicename.c
 * Simple utility to get or set the device name
 *
 * Copyright (c) 2014  Nikias Bassen, All Rights Reserved.
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
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

static void print_usage()
{
	printf("\nUsage: idevicename [OPTIONS] [NAME]\n");
	printf("  --udid|-u UDID  use UDID to target a specific device\n");
	printf("\n");
}

int main(int argc, char** argv)
{
	int res = -1;
	char* udid = NULL;

	int c = 0;
	int optidx = 0;
	const struct option longopts[] = {
		{ "udid", required_argument, NULL, 'u' },
		{ NULL, 0, NULL, 0}
	};

	signal(SIGPIPE, SIG_IGN);

	while ((c = getopt_long(argc, argv, "u:", longopts, &optidx)) != -1) {
		switch (c) {
		case 'u':
			udid = strdup(optarg);
			break;
		default:
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1) {
		print_usage();
		return -1;
	}

	idevice_t device = NULL;
	if (idevice_new(&device, udid) != IDEVICE_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not connect to device\n");
		return -1;
	}

	lockdownd_client_t lockdown = NULL;
	lockdownd_error_t lerr = lockdownd_client_new_with_handshake(device, &lockdown, "idevicename");
	if (lerr != LOCKDOWN_E_SUCCESS) {
		idevice_free(device);
		fprintf(stderr, "ERROR: lockdown connection failed, lockdown error %d\n", lerr);
		return -1;
	}

	plist_t node = NULL;

	if (argc == 0) {
		// getting device name
		char* name = NULL;
		lerr = lockdownd_get_value(lockdown, NULL, "DeviceName", &node);
		if (node) {
			plist_get_string_val(node, &name);
			plist_free(node);
		}
		if (name) {
			printf("%s\n", name);
			free(name);
			res = 0;
		} else {
			fprintf(stderr, "ERROR: Could not get device name, lockdown error %d\n", lerr);
		}
	} else {
		// setting device name
		lerr = lockdownd_set_value(lockdown, NULL, "DeviceName", plist_new_string(argv[0]));
		if (lerr == LOCKDOWN_E_SUCCESS) {
			printf("device name set to '%s'\n", argv[0]);
			res = 0;
		} else {
			fprintf(stderr, "ERROR: Could not set device name, lockdown error %d\n", lerr);
		}
	}

	lockdownd_client_free(lockdown);
	idevice_free(device);

	if (udid) {
		free(udid);
	}

	return res;
}
