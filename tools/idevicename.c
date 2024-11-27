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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define TOOL_NAME "idevicename"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#ifndef _WIN32
#include <signal.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

static void print_usage(int argc, char** argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] [NAME]\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Display the device name or set it to NAME if specified.\n"
		"\n"
		"OPTIONS:\n"
		"  -u, --udid UDID       target specific device by UDID\n"
		"  -n, --network         connect to network device\n"
		"  -d, --debug           enable communication debugging\n"
		"  -h, --help            print usage information\n"
		"  -v, --version         print version information\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

int main(int argc, char** argv)
{
	int c = 0;
	const struct option longopts[] = {
		{ "udid",    required_argument, NULL, 'u' },
		{ "network", no_argument,       NULL, 'n' },
		{ "debug",   no_argument,       NULL, 'd' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'v' },
		{ NULL, 0, NULL, 0}
	};
	int res = -1;
	const char* udid = NULL;
	int use_network = 0;

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	while ((c = getopt_long(argc, argv, "du:hnv", longopts, NULL)) != -1) {
		switch (c) {
		case 'u':
			if (!*optarg) {
				fprintf(stderr, "ERROR: UDID must not be empty!\n");
				print_usage(argc, argv, 1);
				exit(2);
			}
			udid = optarg;
			break;
		case 'n':
			use_network = 1;
			break;
		case 'h':
			print_usage(argc, argv, 0);
			return 0;
		case 'd':
			idevice_set_debug_level(1);
			break;
		case 'v':
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			return 0;
		default:
			print_usage(argc, argv, 1);
			return 2;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1) {
		print_usage(argc, argv, 1);
		return 2;
	}

	idevice_t device = NULL;
	if (idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX) != IDEVICE_E_SUCCESS) {
		if (udid) {
			fprintf(stderr, "ERROR: No device found with udid %s.\n", udid);
		} else {
			fprintf(stderr, "ERROR: No device found.\n");
		}
		return -1;
	}

	lockdownd_client_t lockdown = NULL;
	lockdownd_error_t lerr = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME);
	if (lerr != LOCKDOWN_E_SUCCESS) {
		idevice_free(device);
		fprintf(stderr, "ERROR: Could not connect to lockdownd, error code %d\n", lerr);
		return -1;
	}

	if (argc == 0) {
		// getting device name
		char* name = NULL;
		lerr = lockdownd_get_device_name(lockdown, &name);
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

	return res;
}
