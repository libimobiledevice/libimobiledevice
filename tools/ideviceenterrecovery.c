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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define TOOL_NAME "ideviceenterrecovery"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#ifndef WIN32
#include <signal.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

static void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] UDID\n", (name ? name + 1: argv[0]));
	printf("\n");
	printf("Makes a device with the supplied UDID enter recovery mode immediately.\n");
	printf("\n");
	printf("OPTIONS:\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("  -v, --version\t\tprints version information\n");
	printf("\n");
	printf("Homepage:    <" PACKAGE_URL ">\n");
	printf("Bug Reports: <" PACKAGE_BUGREPORT ">\n");
}

int main(int argc, char *argv[])
{
	lockdownd_client_t client = NULL;
	lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	int i;
	const char* udid = NULL;

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
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
		else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			return 0;
		}
	}

	i--;
	if (argc < 2 || !argv[i] || !*argv[i]) {
		print_usage(argc, argv);
		return 0;
	}
	udid = argv[i];

	ret = idevice_new(&device, udid);
	if (ret != IDEVICE_E_SUCCESS) {
		printf("No device found with udid %s.\n", udid);
		return 1;
	}

	if (LOCKDOWN_E_SUCCESS != (ldret = lockdownd_client_new(device, &client, TOOL_NAME))) {
		printf("ERROR: Could not connect to lockdownd: %s (%d)\n", lockdownd_strerror(ldret), ldret);
		idevice_free(device);
		return 1;
	}

	int res = 0;
	printf("Telling device with udid %s to enter recovery mode.\n", udid);
	ldret = lockdownd_enter_recovery(client);
	if (ldret == LOCKDOWN_E_SESSION_INACTIVE) {
		lockdownd_client_free(client);
		client = NULL;
		if (LOCKDOWN_E_SUCCESS != (ldret = lockdownd_client_new_with_handshake(device, &client, TOOL_NAME))) {
			printf("ERROR: Could not connect to lockdownd: %s (%d)\n", lockdownd_strerror(ldret), ldret);
			idevice_free(device);
			return 1;
		}
		ldret = lockdownd_enter_recovery(client);
	}
	if (ldret != LOCKDOWN_E_SUCCESS) {
		printf("Failed to enter recovery mode.\n");
		res = 1;
	} else {
		printf("Device is successfully switching to recovery mode.\n");
	}

	lockdownd_client_free(client);
	idevice_free(device);

	return res;
}
