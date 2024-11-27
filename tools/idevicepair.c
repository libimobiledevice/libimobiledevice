/*
 * idevicepair.c
 * Manage pairings with devices and this host
 *
 * Copyright (c) 2010-2021 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2014 Martin Szulecki, All Rights Reserved.
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

#define TOOL_NAME "idevicepair"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <signal.h>
#endif

#include "common/userpref.h"

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <plist/plist.h>

static char *udid = NULL;

#ifdef HAVE_WIRELESS_PAIRING

#ifdef _WIN32
#define BS_CC '\b'
#define my_getch getch
#else
#define BS_CC 0x7f
static int my_getch(void)
{
	struct termios oldt, newt;
	int ch;
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return ch;
}
#endif

static int get_hidden_input(char *buf, int maxlen)
{
	int pwlen = 0;
	int c;

	while ((c = my_getch())) {
		if ((c == '\r') || (c == '\n')) {
			break;
		} else if (isprint(c)) {
			if (pwlen < maxlen-1)
				buf[pwlen++] = c;
			fputc('*', stderr);
		} else if (c == BS_CC) {
			if (pwlen > 0) {
				fputs("\b \b", stderr);
				pwlen--;
			}
		}
	}
	buf[pwlen] = 0;
	return pwlen;
}

static void pairing_cb(lockdownd_cu_pairing_cb_type_t cb_type, void *user_data, void* data_ptr, unsigned int* data_size)
{
	if (cb_type == LOCKDOWN_CU_PAIRING_PIN_REQUESTED) {
		printf("Enter PIN: ");
		fflush(stdout);

		*data_size = get_hidden_input((char*)data_ptr, *data_size);

		printf("\n");
	} else if (cb_type == LOCKDOWN_CU_PAIRING_DEVICE_INFO) {
		printf("Device info:\n");
		plist_write_to_stream((plist_t)data_ptr, stdout, PLIST_FORMAT_LIMD, PLIST_OPT_INDENT | PLIST_OPT_INDENT_BY(2));
	} else if (cb_type == LOCKDOWN_CU_PAIRING_ERROR) {
		printf("ERROR: %s\n", (data_ptr) ? (char*)data_ptr : "(unknown)");
	}
}

#endif /* HAVE_WIRELESS_PAIRING */

static void print_error_message(lockdownd_error_t err)
{
	switch (err) {
		case LOCKDOWN_E_PASSWORD_PROTECTED:
			printf("ERROR: Could not validate with device %s because a passcode is set. Please enter the passcode on the device and retry.\n", udid);
			break;
		case LOCKDOWN_E_INVALID_CONF:
		case LOCKDOWN_E_INVALID_HOST_ID:
			printf("ERROR: Device %s is not paired with this host\n", udid);
			break;
		case LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING:
			printf("ERROR: Please accept the trust dialog on the screen of device %s, then attempt to pair again.\n", udid);
			break;
		case LOCKDOWN_E_USER_DENIED_PAIRING:
			printf("ERROR: Device %s said that the user denied the trust dialog.\n", udid);
			break;
		case LOCKDOWN_E_PAIRING_FAILED:
			printf("ERROR: Pairing with device %s failed.\n", udid);
			break;
		case LOCKDOWN_E_GET_PROHIBITED:
		case LOCKDOWN_E_PAIRING_PROHIBITED_OVER_THIS_CONNECTION:
			printf("ERROR: Pairing is not possible over this connection.\n");
#ifdef HAVE_WIRELESS_PAIRING
			printf("To perform a wireless pairing use the -w command line switch. See usage or man page for details.\n");
#endif
			break;
		default:
			printf("ERROR: Device %s returned unhandled error code %d\n", udid, err);
			break;
	}
}

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Manage host pairings with devices and usbmuxd.\n"
		"\n"
		"Where COMMAND is one of:\n"
		"  systembuid   print the system buid of the usbmuxd host\n"
		"  hostid       print the host id for target device\n"
		"  pair         pair device with this host\n"
		"  validate     validate if device is paired with this host\n"
		"  unpair       unpair device with this host\n"
		"  list         list devices paired with this host\n"
		"\n"
		"The following OPTIONS are accepted:\n"
		"  -u, --udid UDID  target specific device by UDID\n"
	);
#ifdef HAVE_WIRELESS_PAIRING
	fprintf(is_error ? stderr : stdout,
		"  -w, --wireless   perform wireless pairing (see NOTE)\n"
		"  -n, --network    connect to network device (see NOTE)\n"
	);
#endif
	fprintf(is_error ? stderr : stdout,
		"  -d, --debug      enable communication debugging\n"
		"  -h, --help       prints usage information\n"
		"  -v, --version    prints version information\n"
	);
#ifdef HAVE_WIRELESS_PAIRING
	fprintf(is_error ? stderr : stdout,
		"\n"
		"NOTE: Pairing over network (wireless pairing) is only supported by Apple TV\n"
		"devices. To perform a wireless pairing, you need to use the -w command line\n"
		"switch. Make sure to put the device into pairing mode first by opening\n"
		"Settings > Remotes and Devices > Remote App and Devices.\n"
	);
#endif
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

int main(int argc, char **argv)
{
	int c = 0;
	static struct option longopts[] = {
		{ "help",    no_argument,       NULL, 'h' },
		{ "udid",    required_argument, NULL, 'u' },
#ifdef HAVE_WIRELESS_PAIRING
		{ "wireless", no_argument,      NULL, 'w' },
		{ "network", no_argument,       NULL, 'n' },
		{ "hostinfo", required_argument, NULL,  1 },
#endif
		{ "debug",   no_argument,       NULL, 'd' },
		{ "version", no_argument,       NULL, 'v' },
		{ NULL, 0, NULL, 0}
	};
#ifdef HAVE_WIRELESS_PAIRING
#define SHORT_OPTIONS "hu:wndv"
#else
#define SHORT_OPTIONS "hu:dv"
#endif
	lockdownd_client_t client = NULL;
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	lockdownd_error_t lerr;
	int result;

	char *type = NULL;
	int use_network = 0;
	int wireless_pairing = 0;
#ifdef HAVE_WIRELESS_PAIRING
	plist_t host_info_plist = NULL;
#endif
	char *cmd;
	typedef enum {
		OP_NONE = 0, OP_PAIR, OP_VALIDATE, OP_UNPAIR, OP_LIST, OP_HOSTID, OP_SYSTEMBUID
	} op_t;
	op_t op = OP_NONE;

	while ((c = getopt_long(argc, argv, SHORT_OPTIONS, longopts, NULL)) != -1) {
		switch (c) {
		case 'h':
			print_usage(argc, argv, 0);
			exit(EXIT_SUCCESS);
		case 'u':
			if (!*optarg) {
				fprintf(stderr, "ERROR: UDID must not be empty!\n");
				print_usage(argc, argv, 1);
				result = EXIT_FAILURE;
				goto leave;
			}
			free(udid);
			udid = strdup(optarg);
			break;
#ifdef HAVE_WIRELESS_PAIRING
		case 'w':
			wireless_pairing = 1;
			break;
		case 'n':
			use_network = 1;
			break;
		case 1:
			if (!*optarg) {
				fprintf(stderr, "ERROR: --hostinfo argument must not be empty!\n");
				result = EXIT_FAILURE;
				goto leave;
			}
			if (*optarg == '@') {
				plist_read_from_file(optarg+1, &host_info_plist, NULL);
				if (!host_info_plist) {
					fprintf(stderr, "ERROR: Could not read from file '%s'\n", optarg+1);
					result = EXIT_FAILURE;
					goto leave;
				}
			}
#ifdef HAVE_PLIST_JSON
			else if (*optarg == '{') {
				if (plist_from_json(optarg, strlen(optarg), &host_info_plist) != PLIST_ERR_SUCCESS) {
					fprintf(stderr, "ERROR: --hostinfo argument not valid. Make sure it is a JSON dictionary.\n");
					result = EXIT_FAILURE;
					goto leave;
				}
			}
#endif
			else {
				fprintf(stderr, "ERROR: --hostinfo argument not valid. To specify a path prefix with '@'\n");
				result = EXIT_FAILURE;
				goto leave;
			}
			break;
#endif
		case 'd':
			idevice_set_debug_level(1);
			break;
		case 'v':
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			result = EXIT_SUCCESS;
			goto leave;
		default:
			print_usage(argc, argv, 1);
			result = EXIT_FAILURE;
			goto leave;
		}
	}

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	if ((argc - optind) < 1) {
		fprintf(stderr, "ERROR: You need to specify a COMMAND!\n");
		print_usage(argc, argv, 1);
		result = EXIT_FAILURE;
		goto leave;
	}

	if (wireless_pairing && use_network) {
		fprintf(stderr, "ERROR: You cannot use -w and -n together.\n");
		print_usage(argc, argv, 1);
		result = EXIT_FAILURE;
		goto leave;
	}

	cmd = (argv+optind)[0];

	if (!strcmp(cmd, "pair")) {
		op = OP_PAIR;
	} else if (!strcmp(cmd, "validate")) {
		op = OP_VALIDATE;
	} else if (!strcmp(cmd, "unpair")) {
		op = OP_UNPAIR;
	} else if (!strcmp(cmd, "list")) {
		op = OP_LIST;
	} else if (!strcmp(cmd, "hostid")) {
		op = OP_HOSTID;
	} else if (!strcmp(cmd, "systembuid")) {
		op = OP_SYSTEMBUID;
	} else {
		fprintf(stderr, "ERROR: Invalid command '%s' specified\n", cmd);
		print_usage(argc, argv, 1);
		result = EXIT_FAILURE;
		goto leave;
	}

	if (wireless_pairing) {
		if (op == OP_VALIDATE || op == OP_UNPAIR) {
			fprintf(stderr, "ERROR: Command '%s' is not supported with -w\n", cmd);
			print_usage(argc, argv, 1);
			result = EXIT_FAILURE;
			goto leave;
		}
		use_network = 1;
	}

	if (op == OP_SYSTEMBUID) {
		char *systembuid = NULL;
		userpref_read_system_buid(&systembuid);

		printf("%s\n", systembuid);

		free(systembuid);

		result = EXIT_SUCCESS;
		goto leave;
	}

	if (op == OP_LIST) {
		unsigned int i;
		char **udids = NULL;
		unsigned int count = 0;
		userpref_get_paired_udids(&udids, &count);
		for (i = 0; i < count; i++) {
			printf("%s\n", udids[i]);
			free(udids[i]);
		}
		free(udids);
		result = EXIT_SUCCESS;
		goto leave;
	}

	ret = idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX);
	if (ret != IDEVICE_E_SUCCESS) {
		if (udid) {
			printf("No device found with udid %s.\n", udid);
		} else {
			printf("No device found.\n");
		}
		result = EXIT_FAILURE;
		goto leave;
	}
	if (!udid) {
		ret = idevice_get_udid(device, &udid);
		if (ret != IDEVICE_E_SUCCESS) {
			printf("ERROR: Could not get device udid, error code %d\n", ret);
			result = EXIT_FAILURE;
			goto leave;
		}
	}

	if (op == OP_HOSTID) {
		plist_t pair_record = NULL;
		char *hostid = NULL;

		userpref_read_pair_record(udid, &pair_record);
		pair_record_get_host_id(pair_record, &hostid);

		printf("%s\n", hostid);

		free(hostid);
		plist_free(pair_record);

		result = EXIT_SUCCESS;
		goto leave;
	}

	lerr = lockdownd_client_new(device, &client, TOOL_NAME);
	if (lerr != LOCKDOWN_E_SUCCESS) {
		printf("ERROR: Could not connect to lockdownd, error code %d\n", lerr);
		result = EXIT_FAILURE;
		goto leave;
	}

	result = EXIT_SUCCESS;

	lerr = lockdownd_query_type(client, &type);
	if (lerr != LOCKDOWN_E_SUCCESS) {
		printf("QueryType failed, error code %d\n", lerr);
		result = EXIT_FAILURE;
		goto leave;
	} else {
		if (strcmp("com.apple.mobile.lockdown", type) != 0) {
			printf("WARNING: QueryType request returned '%s'\n", type);
		}
		free(type);
	}

	switch(op) {
		default:
		case OP_PAIR:
#ifdef HAVE_WIRELESS_PAIRING
		if (wireless_pairing) {
			lerr = lockdownd_cu_pairing_create(client, pairing_cb, NULL, host_info_plist, NULL);
			if (lerr == LOCKDOWN_E_SUCCESS) {
				lerr = lockdownd_pair_cu(client);
			}
		} else
#endif
		{
			lerr = lockdownd_pair(client, NULL);
		}
		if (lerr == LOCKDOWN_E_SUCCESS) {
			printf("SUCCESS: Paired with device %s\n", udid);
		} else {
			result = EXIT_FAILURE;
			print_error_message(lerr);
		}
		break;

		case OP_VALIDATE:
		lockdownd_client_free(client);
		client = NULL;
		lerr = lockdownd_client_new_with_handshake(device, &client, TOOL_NAME);
		if (lerr == LOCKDOWN_E_SUCCESS) {
			printf("SUCCESS: Validated pairing with device %s\n", udid);
		} else {
			result = EXIT_FAILURE;
			print_error_message(lerr);
		}
		break;

		case OP_UNPAIR:
		lerr = lockdownd_unpair(client, NULL);
		if (lerr == LOCKDOWN_E_SUCCESS) {
			printf("SUCCESS: Unpaired with device %s\n", udid);
		} else {
			result = EXIT_FAILURE;
			print_error_message(lerr);
		}
		break;
	}

leave:
	lockdownd_client_free(client);
	idevice_free(device);
	free(udid);

	return result;
}

