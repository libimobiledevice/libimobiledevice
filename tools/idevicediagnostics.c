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
#include <errno.h>
#include <time.h>
#ifndef WIN32
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

void print_usage(int argc, char **argv);

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	lockdownd_client_t lockdown_client = NULL;
	diagnostics_relay_client_t diagnostics_client = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	lockdownd_service_descriptor_t service = NULL;
	int result = EXIT_FAILURE;
	int i;
	const char *udid = NULL;
	int use_network = 0;
	int cmd = CMD_NONE;
	char* cmd_arg = NULL;
	plist_t node = NULL;
	plist_t keys = NULL;

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udid")) {
			i++;
			if (!argv[i] || !*argv[i]) {
				print_usage(argc, argv);
				result = EXIT_SUCCESS;
				goto cleanup;
			}
			udid = argv[i];
			continue;
		}
		else if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--network")) {
			use_network = 1;
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			result = EXIT_SUCCESS;
			goto cleanup;
		}
		else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			result = EXIT_SUCCESS;
			goto cleanup;
		}
		else if (!strcmp(argv[i], "sleep")) {
			cmd = CMD_SLEEP;
		}
		else if (!strcmp(argv[i], "restart")) {
			cmd = CMD_RESTART;
		}
		else if (!strcmp(argv[i], "shutdown")) {
			cmd = CMD_SHUTDOWN;
		}
		else if (!strcmp(argv[i], "diagnostics")) {
			cmd = CMD_DIAGNOSTICS;
			/*  read type */
			i++;
			if (!argv[i] || ((strcmp(argv[i], "All") != 0) && (strcmp(argv[i], "WiFi") != 0) && (strcmp(argv[i], "GasGauge") != 0) && (strcmp(argv[i], "NAND") != 0) && (strcmp(argv[i], "HDMI") != 0))) {
				if (argv[i] == NULL) {
					cmd_arg = strdup("All");
					continue;
				}

				if (!strncmp(argv[i], "-", 1)) {
					cmd_arg = strdup("All");
					i--;
					continue;
				}

				printf("ERROR: Unknown TYPE %s\n", argv[i]);
				print_usage(argc, argv);
				goto cleanup;
			}

			cmd_arg = strdup(argv[i]);
			continue;
		}
		else if (!strcmp(argv[i], "mobilegestalt")) {
			cmd = CMD_MOBILEGESTALT;
			/*  read keys */
			i++;

			if (!argv[i] || argv[i] == NULL || (!strncmp(argv[i], "-", 1))) {
				printf("ERROR: Please supply the key to query.\n");
				print_usage(argc, argv);
				goto cleanup;
			}

			keys = plist_new_array();
			while(1) {
				if (argv[i] && (strlen(argv[i]) >= 2) && (strncmp(argv[i], "-", 1) != 0)) {
					plist_array_append_item(keys, plist_new_string(argv[i]));
					i++;
				} else {
					i--;
					break;
				}
			}
			continue;
		}
		else if (!strcmp(argv[i], "ioreg")) {
			cmd = CMD_IOREGISTRY;
			/*  read plane */
			i++;
			if (argv[i]) {
				cmd_arg = strdup(argv[i]);
			}
			continue;
		}
		else if (!strcmp(argv[i], "ioregentry")) {
			cmd = CMD_IOREGISTRY_ENTRY;
			/* read key */
			i++;
			if (argv[i]) {
				cmd_arg = strdup(argv[i]);
			}
			continue;
		}
		else {
			print_usage(argc, argv);
			return EXIT_SUCCESS;
		}
	}

	/* verify options */
	if (cmd == CMD_NONE) {
		print_usage(argc, argv);
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
	if (ret != LOCKDOWN_E_SUCCESS) {
		/*  attempt to use older diagnostics service */
		ret = lockdownd_start_service(lockdown_client, "com.apple.iosdiagnostics.relay", &service);
	}

	lockdownd_client_free(lockdown_client);

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

void print_usage(int argc, char **argv)
{
	char *name = NULL;
	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
	printf("\n");
	printf("Use diagnostics interface of a device running iOS 4 or later.\n");
	printf("\n");
	printf("Where COMMAND is one of:\n");
	printf("  diagnostics [TYPE]\t\tprint diagnostics information from device by TYPE (All, WiFi, GasGauge, NAND)\n");
	printf("  mobilegestalt KEY [...]\tprint mobilegestalt keys passed as arguments separated by a space.\n");
	printf("  ioreg [PLANE]\t\t\tprint IORegistry of device, optionally by PLANE (IODeviceTree, IOPower, IOService) (iOS 5+ only)\n");
	printf("  ioregentry [KEY]\t\tprint IORegistry entry of device (AppleARMPMUCharger, ASPStorage, ...) (iOS 5+ only)\n");
	printf("  shutdown\t\t\tshutdown device\n");
	printf("  restart\t\t\trestart device\n");
	printf("  sleep\t\t\t\tput device into sleep mode (disconnects from host)\n");
	printf("\n");
	printf("The following OPTIONS are accepted:\n");
	printf("  -u, --udid UDID\ttarget specific device by UDID\n");
	printf("  -n, --network\t\tconnect to network device\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("  -v, --version\t\tprints version information\n");
	printf("\n");
	printf("Homepage:    <" PACKAGE_URL ">\n");
	printf("Bug Reports: <" PACKAGE_BUGREPORT ">\n");
}
