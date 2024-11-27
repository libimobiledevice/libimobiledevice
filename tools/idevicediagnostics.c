/*
 * idevicediagnostics.c
 * Retrieves diagnostics information from device
 *
 * Copyright (c) 2012 Martin Szulecki All Rights Reserved.
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

#define TOOL_NAME "idevicediagnostics"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#ifndef _WIN32
#include <signal.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/diagnostics_relay.h>

enum cmd_mode {
	CMD_NONE = 0,
	CMD_SLEEP,
	CMD_RESTART,
	CMD_SHUTDOWN,
	CMD_DIAGNOSTICS,
	CMD_MOBILEGESTALT,
	CMD_IOREGISTRY,
	CMD_IOREGISTRY_ENTRY
};

static void print_xml(plist_t node)
{
	char *xml = NULL;
	uint32_t len = 0;
	plist_to_xml(node, &xml, &len);
	if (xml) {
		puts(xml);
	}
}

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Use diagnostics interface of a device running iOS 4 or later.\n"
		"\n"
		"Where COMMAND is one of:\n"
		"  diagnostics [TYPE]         print diagnostics information from device by TYPE (All, WiFi, GasGauge, NAND)\n"
		"  mobilegestalt KEY [...]    print mobilegestalt keys passed as arguments separated by a space.\n"
		"  ioreg [PLANE]              print IORegistry of device, optionally by PLANE (IODeviceTree, IOPower, IOService) (iOS 5+ only)\n"
		"  ioregentry [KEY]           print IORegistry entry of device (AppleARMPMUCharger, ASPStorage, ...) (iOS 5+ only)\n"
		"  shutdown                   shutdown device\n"
		"  restart                    restart device\n"
		"  sleep                      put device into sleep mode (disconnects from host)\n"
		"\n"
		"The following OPTIONS are accepted:\n"
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
	idevice_t device = NULL;
	lockdownd_client_t lockdown_client = NULL;
	diagnostics_relay_client_t diagnostics_client = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	lockdownd_service_descriptor_t service = NULL;
	int result = EXIT_FAILURE;
	const char *udid = NULL;
	int use_network = 0;
	int cmd = CMD_NONE;
	char* cmd_arg = NULL;
	plist_t node = NULL;
	plist_t keys = NULL;
	int c = 0;
	const struct option longopts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "udid", required_argument, NULL, 'u' },
		{ "network", no_argument, NULL, 'n' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0}
	};

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	/* parse cmdline args */
	while ((c = getopt_long(argc, argv, "dhu:nv", longopts, NULL)) != -1) {
		switch (c) {
		case 'd':
			idevice_set_debug_level(1);
			break;
		case 'u':
			if (!*optarg) {
				fprintf(stderr, "ERROR: UDID argument must not be empty!\n");
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

	if (!argv[0]) {
		fprintf(stderr, "ERROR: No command specified\n");
		print_usage(argc+optind, argv-optind, 1);
		return 2;
	}

	if (!strcmp(argv[0], "sleep")) {
		cmd = CMD_SLEEP;
	}
	else if (!strcmp(argv[0], "restart")) {
		cmd = CMD_RESTART;
	}
	else if (!strcmp(argv[0], "shutdown")) {
		cmd = CMD_SHUTDOWN;
	}
	else if (!strcmp(argv[0], "diagnostics")) {
		cmd = CMD_DIAGNOSTICS;
		/*  read type */
		if (!argv[1] || ((strcmp(argv[1], "All") != 0) && (strcmp(argv[1], "WiFi") != 0) && (strcmp(argv[1], "GasGauge") != 0) && (strcmp(argv[1], "NAND") != 0) && (strcmp(argv[1], "HDMI") != 0))) {
			if (argv[1] == NULL) {
				cmd_arg = strdup("All");
			} else {
				fprintf(stderr, "ERROR: Unknown TYPE %s\n", argv[1]);
				print_usage(argc+optind, argv-optind, 1);
				goto cleanup;
			}
		}
		cmd_arg = strdup(argv[1]);
	}
	else if (!strcmp(argv[0], "mobilegestalt")) {
		cmd = CMD_MOBILEGESTALT;
		/*  read keys */
		if (!argv[1] || !*argv[1]) {
			fprintf(stderr, "ERROR: Please supply the key to query.\n");
			print_usage(argc, argv, 1);
			goto cleanup;
		}
		int i = 1;
		keys = plist_new_array();
		while (argv[i] && *argv[i]) {
			plist_array_append_item(keys, plist_new_string(argv[i]));
			i++;
		}
	}
	else if (!strcmp(argv[0], "ioreg")) {
		cmd = CMD_IOREGISTRY;
		/*  read plane */
		if (argv[1]) {
			cmd_arg = strdup(argv[1]);
		}
	}
	else if (!strcmp(argv[0], "ioregentry")) {
		cmd = CMD_IOREGISTRY_ENTRY;
		/* read key */
		if (argv[1]) {
			cmd_arg = strdup(argv[1]);
		}
	}

	/* verify options */
	if (cmd == CMD_NONE) {
		fprintf(stderr, "ERROR: Unsupported command '%s'\n", argv[0]);
		print_usage(argc+optind, argv-optind, 1);
		goto cleanup;
	}

	if (IDEVICE_E_SUCCESS != idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX)) {
		if (udid) {
			printf("No device found with udid %s.\n", udid);
		} else {
			printf("No device found.\n");
		}
		goto cleanup;
	}

	if (LOCKDOWN_E_SUCCESS != (ret = lockdownd_client_new_with_handshake(device, &lockdown_client, TOOL_NAME))) {
		idevice_free(device);
		printf("ERROR: Could not connect to lockdownd, error code %d\n", ret);
		goto cleanup;
	}

	/*  attempt to use newer diagnostics service available on iOS 5 and later */
	ret = lockdownd_start_service(lockdown_client, "com.apple.mobile.diagnostics_relay", &service);
	if (ret == LOCKDOWN_E_INVALID_SERVICE) {
		/*  attempt to use older diagnostics service */
		ret = lockdownd_start_service(lockdown_client, "com.apple.iosdiagnostics.relay", &service);
	}
	lockdownd_client_free(lockdown_client);

	if (ret != LOCKDOWN_E_SUCCESS) {
		idevice_free(device);
		printf("ERROR: Could not start diagnostics relay service: %s\n", lockdownd_strerror(ret));
		goto cleanup;
	}

	result = EXIT_FAILURE;

	if ((ret == LOCKDOWN_E_SUCCESS) && service && (service->port > 0)) {
		if (diagnostics_relay_client_new(device, service, &diagnostics_client) != DIAGNOSTICS_RELAY_E_SUCCESS) {
			printf("ERROR: Could not connect to diagnostics_relay!\n");
		} else {
			switch (cmd) {
				case CMD_SLEEP:
					if (diagnostics_relay_sleep(diagnostics_client) == DIAGNOSTICS_RELAY_E_SUCCESS) {
						printf("Putting device into deep sleep mode.\n");
						result = EXIT_SUCCESS;
					} else {
						printf("ERROR: Failed to put device into deep sleep mode.\n");
					}
				break;
				case CMD_RESTART:
					if (diagnostics_relay_restart(diagnostics_client, DIAGNOSTICS_RELAY_ACTION_FLAG_WAIT_FOR_DISCONNECT) == DIAGNOSTICS_RELAY_E_SUCCESS) {
						printf("Restarting device.\n");
						result = EXIT_SUCCESS;
					} else {
						printf("ERROR: Failed to restart device.\n");
					}
				break;
				case CMD_SHUTDOWN:
					if (diagnostics_relay_shutdown(diagnostics_client, DIAGNOSTICS_RELAY_ACTION_FLAG_WAIT_FOR_DISCONNECT) == DIAGNOSTICS_RELAY_E_SUCCESS) {
						printf("Shutting down device.\n");
						result = EXIT_SUCCESS;
					} else {
						printf("ERROR: Failed to shutdown device.\n");
					}
				break;
				case CMD_MOBILEGESTALT:
					if (diagnostics_relay_query_mobilegestalt(diagnostics_client, keys, &node) == DIAGNOSTICS_RELAY_E_SUCCESS) {
						if (node) {
							print_xml(node);
							result = EXIT_SUCCESS;
						}
					} else {
						printf("ERROR: Unable to query mobilegestalt keys.\n");
					}
				break;
				case CMD_IOREGISTRY_ENTRY:
					if (diagnostics_relay_query_ioregistry_entry(diagnostics_client, cmd_arg == NULL ? "": cmd_arg, "", &node) == DIAGNOSTICS_RELAY_E_SUCCESS) {
						if (node) {
							print_xml(node);
							result = EXIT_SUCCESS;
						}
					} else {
						printf("ERROR: Unable to retrieve IORegistry from device.\n");
					}
					break;
				case CMD_IOREGISTRY:
					if (diagnostics_relay_query_ioregistry_plane(diagnostics_client, cmd_arg == NULL ? "": cmd_arg, &node) == DIAGNOSTICS_RELAY_E_SUCCESS) {
						if (node) {
							print_xml(node);
							result = EXIT_SUCCESS;
						}
					} else {
						printf("ERROR: Unable to retrieve IORegistry from device.\n");
					}
					break;
				case CMD_DIAGNOSTICS:
				default:
					if (diagnostics_relay_request_diagnostics(diagnostics_client, cmd_arg, &node) == DIAGNOSTICS_RELAY_E_SUCCESS) {
						if (node) {
							print_xml(node);
							result = EXIT_SUCCESS;
						}
					} else {
						printf("ERROR: Unable to retrieve diagnostics from device.\n");
					}
					break;
			}

			diagnostics_relay_goodbye(diagnostics_client);
			diagnostics_relay_client_free(diagnostics_client);
		}
	} else {
		printf("ERROR: Could not start diagnostics service!\n");
	}

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

	idevice_free(device);

cleanup:
	if (node) {
		plist_free(node);
	}
	if (keys) {
		plist_free(keys);
	}
	if (cmd_arg) {
		free(cmd_arg);
	}
	return result;
}
