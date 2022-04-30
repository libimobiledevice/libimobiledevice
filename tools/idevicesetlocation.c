/*
 * idevicesetlocation.c
 * Simulate location on iOS device with mounted developer disk image
 *
 * Copyright (c) 2016-2020 Nikias Bassen, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define TOOL_NAME "idevicesetlocation"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/service.h>

#include <endianness.h>

#define DT_SIMULATELOCATION_SERVICE "com.apple.dt.simulatelocation"

enum {
	SET_LOCATION = 0,
	RESET_LOCATION = 1
};

static void print_usage(int argc, char **argv, int is_error)
{
	char *bname = strrchr(argv[0], '/');
	bname = (bname) ? bname + 1 : argv[0];

	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] -- <LAT> <LONG>\n", bname);
	fprintf(is_error ? stderr : stdout, "       %s [OPTIONS] reset\n", bname);
	fprintf(is_error ? stderr : stdout,
		"\n"
		"OPTIONS:\n"
		"  -u, --udid UDID       target specific device by UDID\n"
		"  -n, --network         connect to network device\n"
		"  -d, --debug           enable communication debugging\n"
		"  -h, --help            prints usage information\n"
		"  -v, --version         prints version information\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

int main(int argc, char **argv)
{
	int c = 0;
	const struct option longopts[] = {
		{ "help",    no_argument,       NULL, 'h' },
		{ "udid",    required_argument, NULL, 'u' },
		{ "debug",   no_argument,       NULL, 'd' },
		{ "network", no_argument,       NULL, 'n' },
		{ "version", no_argument,       NULL, 'v' },
		{ NULL, 0, NULL, 0}
	};
	uint32_t mode = 0;
	const char *udid = NULL;
	int use_network = 0;

	while ((c = getopt_long(argc, argv, "dhu:nv", longopts, NULL)) != -1) {
		switch (c) {
		case 'd':
			idevice_set_debug_level(1);
			break;
		case 'u':
			if (!*optarg) {
				fprintf(stderr, "ERROR: UDID must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			}
			udid = optarg;
			break;
		case 'n':
			use_network = 1;
			break;
		case 'h':
			print_usage(argc, argv, 0);
			return 0;
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

	if ((argc > 2) || (argc < 1)) {
		print_usage(argc+optind, argv-optind, 1);
		return -1;
	}

	if (argc == 2) {
		mode = SET_LOCATION;
	} else if (argc == 1) {
		if (strcmp(argv[0], "reset") == 0) {
			mode = RESET_LOCATION;
		} else {
			print_usage(argc+optind, argv-optind, 1);
			return -1;
		}
	}

	idevice_t device = NULL;

	if (idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX) != IDEVICE_E_SUCCESS) {
		if (udid) {
			printf("ERROR: Device %s not found!\n", udid);
		} else {
			printf("ERROR: No device found!\n");
		}
		return -1;
	}

	lockdownd_client_t lockdown;
	lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME);

	lockdownd_service_descriptor_t svc = NULL;
	lockdownd_error_t lerr = lockdownd_start_service(lockdown, DT_SIMULATELOCATION_SERVICE, &svc);
	if (lerr != LOCKDOWN_E_SUCCESS) {
		lockdownd_client_free(lockdown);
		idevice_free(device);
		printf("ERROR: Could not start the simulatelocation service: %s\nMake sure a developer disk image is mounted!\n", lockdownd_strerror(lerr));
		return -1;
	}
	lockdownd_client_free(lockdown);

	service_client_t service = NULL;

	service_error_t serr = service_client_new(device, svc, &service);

	lockdownd_service_descriptor_free(svc);

	if (serr != SERVICE_E_SUCCESS) {
		lockdownd_client_free(lockdown);
		idevice_free(device);
		printf("ERROR: Could not connect to simulatelocation service (%d)\n", serr);
		return -1;
	}

	uint32_t l;
	uint32_t s = 0;

	l = htobe32(mode);
	service_send(service, (const char*)&l, 4, &s);
	if (mode == SET_LOCATION) {
		int len = 4 + strlen(argv[0]) + 4 + strlen(argv[1]);
		char *buf = malloc(len);
		uint32_t latlen;
		latlen = strlen(argv[0]);
		l = htobe32(latlen);
		memcpy(buf, &l, 4);
		memcpy(buf+4, argv[0], latlen);
		uint32_t longlen = strlen(argv[1]);
		l = htobe32(longlen);
		memcpy(buf+4+latlen, &l, 4);
		memcpy(buf+4+latlen+4, argv[1], longlen);

		s = 0;
		service_send(service, buf, len, &s);
	}

	idevice_free(device);

	return 0;
}
