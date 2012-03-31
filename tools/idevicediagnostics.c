/**
 * idevicediagnostics -- Retrieves diagnostics information from device
 *
 * Copyright (c) 2012 Martin Szulecki All Rights Reserved.
 *
 * Licensed under the GNU General Public License Version 2
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more profile.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 
 * USA
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/diagnostics_relay.h>

static void print_xml(plist_t node)
{
	char *xml = NULL;
	uint32_t len = 0;
	plist_to_xml(node, &xml, &len);
	if (xml)
		puts(xml);
}

void print_usage(int argc, char **argv);

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	lockdownd_client_t lckd = NULL;
	diagnostics_relay_client_t diagc = NULL;
	uint16_t port = 0;
	int result = -1;
	int i;
	char *udid = NULL;

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
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
		else {
			print_usage(argc, argv);
			return 0;
		}
	}

	if (IDEVICE_E_SUCCESS != idevice_new(&device, udid)) {
		printf("No device found, is it plugged in?\n");
		if (udid) {
			free(udid);
		}
		return -1;
	}
	if (udid) {
		free(udid);
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(device, &lckd, NULL)) {
		idevice_free(device);
		printf("Exiting.\n");
		return -1;
	}

	lockdownd_start_service(lckd, "com.apple.mobile.diagnostics_relay", &port);
	lockdownd_client_free(lckd);
	if (port > 0) {
		if (diagnostics_relay_client_new(device, port, &diagc) != DIAGNOSTICS_RELAY_E_SUCCESS) {
			printf("Could not connect to diagnostics_relay!\n");
			result = -1;
		} else {
			plist_t node = NULL;
			if (diagnostics_relay_request_diagnostics(diagc, &node) != DIAGNOSTICS_RELAY_E_SUCCESS) {
				printf("Unable to retrieve diagnostics");
			}
			if (node) {
				print_xml(node);
				plist_free(node);
			}
			diagnostics_relay_goodbye(diagc);
			diagnostics_relay_client_free(diagc);
		}
	} else {
		printf("Could not start diagnostics service!\n");
	}
	idevice_free(device);
	
	return result;
}

void print_usage(int argc, char **argv)
{
        char *name = NULL;

        name = strrchr(argv[0], '/');
        printf("Usage: %s [OPTIONS]\n", (name ? name + 1: argv[0]));
        printf("Retrieves diagnostics information from a device.\n\n");
        printf("  -d, --debug\t\tenable communication debugging\n");
        printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
        printf("  -h, --help\t\tprints usage information\n");
        printf("\n");
}
