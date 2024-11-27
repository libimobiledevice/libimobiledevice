/*
 * idevicedevmodectl.c
 * List or enable Developer Mode on iOS 16+ devices
 *
 * Copyright (c) 2022 Nikias Bassen, All Rights Reserved.
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

#define TOOL_NAME "idevicedevmodectl"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#ifndef _WIN32
#include <signal.h>
#endif

#ifdef _WIN32
#include <windows.h>
#define __usleep(x) Sleep(x/1000)
#else
#include <arpa/inet.h>
#include <unistd.h>
#define __usleep(x) usleep(x)
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/property_list_service.h>
#include <libimobiledevice-glue/utils.h>

#define AMFI_LOCKDOWN_SERVICE_NAME "com.apple.amfi.lockdown"

static char* udid = NULL;
static int use_network = 0;

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Enable Developer Mode on iOS 16+ devices or print the current status.\n"
		"\n"
		"Where COMMAND is one of:\n"
		"  list          Print the Developer Mode status of all connected devices\n"
                "                or for a specific one if --udid is given.\n"
		"  enable        Enable Developer Mode (device will reboot),\n"
		"                and confirm it after device booted up again.\n"
		"\n"
		"  arm           Arm the Developer Mode (device will reboot)\n"
		"  confirm       Confirm enabling of Developer Mode\n"
		"  reveal        Reveal the Developer Mode menu on the device\n"
		"\n"
		"The following OPTIONS are accepted:\n"
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

enum {
	OP_LIST,
	OP_ENABLE,
	OP_ARM,
	OP_CONFIRM,
	OP_REVEAL,
	NUM_OPS
};
#define DEV_MODE_REVEAL   0
#define DEV_MODE_ARM      1
#define DEV_MODE_ENABLE   2

static int get_developer_mode_status(const char* device_udid, int _use_network)
{
	idevice_error_t ret;
	idevice_t device = NULL;
	lockdownd_client_t lockdown = NULL;
	lockdownd_error_t lerr = LOCKDOWN_E_UNKNOWN_ERROR;
	plist_t val = NULL;

	ret = idevice_new_with_options(&device, device_udid, (_use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX);
	if (ret != IDEVICE_E_SUCCESS) {
		return -1;
	}

	if (LOCKDOWN_E_SUCCESS != (lerr = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME))) {
		idevice_free(device);
		return -1;
	}

	lerr = lockdownd_get_value(lockdown, "com.apple.security.mac.amfi", "DeveloperModeStatus", &val);
	if (lerr != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not get DeveloperModeStatus: %s\nPlease note that this feature is only available on iOS 16+.\n", lockdownd_strerror(lerr));
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -2;
	}

	uint8_t dev_mode_status = 0;
	plist_get_bool_val(val, &dev_mode_status);
	plist_free(val);

	lockdownd_client_free(lockdown);
	idevice_free(device);

	return dev_mode_status;
}

static int amfi_service_send_msg(property_list_service_client_t amfi, plist_t msg)
{
	int res;
	property_list_service_error_t perr;

	perr = property_list_service_send_xml_plist(amfi, plist_copy(msg));
	if (perr != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		fprintf(stderr, "Could not send request to device: %d\n", perr);
		res = 2;
	} else {
		plist_t reply = NULL;
		perr = property_list_service_receive_plist(amfi, &reply);
		if (perr == PROPERTY_LIST_SERVICE_E_SUCCESS) {
			plist_t val = plist_dict_get_item(reply, "Error");
			if (val) {
				const char* err = plist_get_string_ptr(val, NULL);
				fprintf(stderr, "Request failed: %s\n", err);
				if (strstr(err, "passcode")) {
					res = 2;
				} else {
					res = 1;
				}
			} else {
				res = plist_dict_get_item(reply, "success") ? 0 : 1;
			}
		} else {
			fprintf(stderr, "Could not receive reply from device: %d\n", perr);
			res = 2;
		}
		plist_free(reply);
	}
	return res;
}

static int amfi_send_action(idevice_t device, unsigned int action)
{
	lockdownd_client_t lockdown = NULL;
	lockdownd_service_descriptor_t service = NULL;
	lockdownd_error_t lerr;

	if (LOCKDOWN_E_SUCCESS != (lerr = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME))) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd, error code %d\n", lerr);
		return 1;
	}

	lerr = lockdownd_start_service(lockdown, AMFI_LOCKDOWN_SERVICE_NAME, &service);
	if (lerr != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "Could not start service %s: %s\nPlease note that this feature is only available on iOS 16+.\n", AMFI_LOCKDOWN_SERVICE_NAME, lockdownd_strerror(lerr));
		lockdownd_client_free(lockdown);
		return 1;
	}
	lockdownd_client_free(lockdown);
	lockdown = NULL;

	property_list_service_client_t amfi = NULL;
	if (property_list_service_client_new(device, service, &amfi) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		fprintf(stderr, "Could not connect to %s on device\n", AMFI_LOCKDOWN_SERVICE_NAME);
		if (service)
			lockdownd_service_descriptor_free(service);
		idevice_free(device);
		return 1;
	}
	lockdownd_service_descriptor_free(service);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "action", plist_new_uint(action));

	int result = amfi_service_send_msg(amfi, dict);
	plist_free(dict);

	property_list_service_client_free(amfi);
	amfi = NULL;

	return result;
}

static int device_connected = 0;

static void device_event_cb(const idevice_event_t* event, void* userdata)
{
	if (use_network && event->conn_type != CONNECTION_NETWORK) {
		return;
	}
	if (!use_network && event->conn_type != CONNECTION_USBMUXD) {
		return;
	}
	if (event->event == IDEVICE_DEVICE_ADD) {
		if (!udid) {
			udid = strdup(event->udid);
		}
		if (strcmp(udid, event->udid) == 0) {
			device_connected = 1;
		}
	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		if (strcmp(udid, event->udid) == 0) {
			device_connected = 0;
		}
	}
}


#define WAIT_INTERVAL 200000
#define WAIT_MAX(x) (x * (1000000 / WAIT_INTERVAL))
#define WAIT_FOR(cond, timeout) { int __repeat = WAIT_MAX(timeout); while (!(cond) && __repeat-- > 0) { __usleep(WAIT_INTERVAL); } }

int main(int argc, char *argv[])
{
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	lockdownd_client_t lockdown = NULL;
	lockdownd_error_t lerr = LOCKDOWN_E_UNKNOWN_ERROR;
	int res = 0;
	int i;
	int op = -1;
	plist_t val = NULL;

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
		fprintf(stderr, "ERROR: Missing command.\n");
		print_usage(argc+optind, argv-optind, 1);
		return 2;
	}

	i = 0;
	if (!strcmp(argv[i], "list")) {
		op = OP_LIST;
	}
	else if (!strcmp(argv[i], "enable")) {
		op = OP_ENABLE;
	}
	else if (!strcmp(argv[i], "arm")) {
		op = OP_ARM;
	}
	else if (!strcmp(argv[i], "confirm")) {
		op = OP_CONFIRM;
	}
	else if (!strcmp(argv[i], "reveal")) {
		op = OP_REVEAL;
	}

	if ((op == -1) || (op >= NUM_OPS)) {
		fprintf(stderr, "ERROR: Unsupported command '%s'\n", argv[i]);
		print_usage(argc+optind, argv-optind, 1);
		return 2;
	}

	if (op == OP_LIST) {
		idevice_info_t *dev_list = NULL;

		if (idevice_get_device_list_extended(&dev_list, &i) < 0) {
			fprintf(stderr, "ERROR: Unable to retrieve device list!\n");
			return -1;
		}
		if (i > 0) {
			printf("%-40s    %s\n", "Device", "DeveloperMode");
		}
		for (i = 0; dev_list[i] != NULL; i++) {
			if (dev_list[i]->conn_type == CONNECTION_USBMUXD && use_network) continue;
			if (dev_list[i]->conn_type == CONNECTION_NETWORK && !use_network) continue;
			if (udid && (strcmp(dev_list[i]->udid, udid) != 0)) continue;
			int mode = get_developer_mode_status(dev_list[i]->udid, use_network);
			const char *mode_str = "N/A";
			if (mode == 1) {
				mode_str = "enabled";
			} else if (mode == 0) {
				mode_str = "disabled";
			}
			printf("%-40s    %s\n", dev_list[i]->udid, mode_str);
		}
		idevice_device_list_extended_free(dev_list);

		return 0;
	}

	idevice_subscription_context_t context = NULL;
	idevice_events_subscribe(&context, device_event_cb, NULL);

	WAIT_FOR(device_connected, 10);

	ret = idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX);
	if (ret != IDEVICE_E_SUCCESS) {
		if (udid) {
			printf("No device found with udid %s.\n", udid);
		} else {
			printf("No device found.\n");
		}
		return 1;
	}

	if (!udid) {
		idevice_get_udid(device, &udid);
	}

	if (LOCKDOWN_E_SUCCESS != (lerr = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME))) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd, error code %d\n", lerr);
		idevice_free(device);
		return 1;
	}

	lerr = lockdownd_get_value(lockdown, "com.apple.security.mac.amfi", "DeveloperModeStatus", &val);
	lockdownd_client_free(lockdown);
	lockdown = NULL;
	if (lerr != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not get DeveloperModeStatus: %s\nPlease note that this feature is only available on iOS 16+.\n", lockdownd_strerror(lerr));
		idevice_free(device);
		return 1;
	}

	uint8_t dev_mode_status = 0;
	plist_get_bool_val(val, &dev_mode_status);

	if ((op == OP_ENABLE || op == OP_ARM) && dev_mode_status) {
		if (dev_mode_status) {
			idevice_free(device);
			printf("DeveloperMode is already enabled.\n");
			return 0;
		}
		res = 0;
	} else {	
		if (op == OP_ENABLE || op == OP_ARM) {
			res = amfi_send_action(device, DEV_MODE_ARM);
			if (res == 0) {
				if (op == OP_ARM) {
					printf("%s: Developer Mode armed, device will reboot now.\n", udid);
				} else {
					printf("%s: Developer Mode armed, waiting for reboot...\n", udid);

					do {
						// waiting for device to disconnect...
						idevice_free(device);
						device = NULL;
						WAIT_FOR(!device_connected, 40);
						if (device_connected) {
							printf("%s: ERROR: Device didn't reboot?!\n", udid);
							res = 2;
							break;
						}
						printf("disconnected\n");

						// waiting for device to reconnect...
						WAIT_FOR(device_connected, 60);
						if (!device_connected) {
							printf("%s: ERROR: Device didn't re-connect?!\n", udid);
							res = 2;
							break;
						}
						printf("connected\n");

						idevice_new(&device, udid);
						res = amfi_send_action(device, DEV_MODE_ENABLE);
					} while (0);
					if (res == 0) {
						printf("%s: Developer Mode successfully enabled.\n", udid);
					} else {
						printf("%s: Failed to enable developer mode (%d)\n", udid, res);
					}
				}
			} else if (res == 2) {
				amfi_send_action(device, DEV_MODE_REVEAL);
				printf("%s: Developer Mode could not be enabled because the device has a passcode set. You have to enable it on the device itself under Settings -> Privacy & Security -> Developer Mode.\n", udid);
			} else {
				printf("%s: Failed to arm Developer Mode (%d)\n", udid, res);
			}
		} else if (op == OP_CONFIRM) {
			res = amfi_send_action(device, DEV_MODE_ENABLE);
			if (res == 0) {
				printf("%s: Developer Mode successfully enabled.\n", udid);
			} else {
				printf("%s: Failed to enable Developer Mode (%d)\n", udid, res);
			}
		} else if (op == OP_REVEAL) {
			res = amfi_send_action(device, DEV_MODE_REVEAL);
			if (res == 0) {
				printf("%s: Developer Mode menu revealed successfully.\n", udid);
			} else {
				printf("%s: Failed to reveal Developer Mode menu (%d)\n", udid, res);
			}
		}
	}

	idevice_free(device);

	return res;
}
