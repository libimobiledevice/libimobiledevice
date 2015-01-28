/*
 * ideviceenterrecovery.c
 * Simple utility to make a device in normal mode enter recovery mode.
 *
 * Copyright (c) 2009 Martin Szulecki All Rights Reserved.
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
#include <errno.h>
#include <stdlib.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

static void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] UDID\n", (name ? name + 1: argv[0]));
	printf("Makes a device with the supplied 40-digit UDID enter recovery mode immediately.\n\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
	printf("Homepage: <http://libimobiledevice.org>\n");
}

int main(int argc, char *argv[])
{
	lockdownd_client_t client = NULL;
	lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	int i;
	const char* udid = NULL;

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
	}

	i--;
	if (!argv[i] || (strlen(argv[i]) != 40)) {
		print_usage(argc, argv);
		return 0;
	}
	udid = argv[i];

	ret = idevice_new(&device, udid);
	if (ret != IDEVICE_E_SUCCESS) {
		printf("No device found with udid %s, is it plugged in?\n", udid);
		return -1;
	}

	if (LOCKDOWN_E_SUCCESS != (ldret = lockdownd_client_new(device, &client, "ideviceenterrecovery"))) {
		printf("ERROR: Could not connect to lockdownd, error code %d\n", ldret);
		idevice_free(device);
		return -1;
	}

	/* run query and output information */
	printf("Telling device with udid %s to enter recovery mode.\n", udid);
	if(lockdownd_enter_recovery(client) != LOCKDOWN_E_SUCCESS)
	{
		printf("Failed to enter recovery mode.\n");
	}
	printf("Device is successfully switching to recovery mode.\n");

	lockdownd_client_free(client);
	idevice_free(device);

	return 0;
}
