/*
 * idevicepair.c
 * Simple utility to pair/unpair an iDevice
 *
 * Copyright (c) 2010 Nikias Bassen All Rights Reserved.
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
#include <stdlib.h>
#include <getopt.h>
#include "userpref.h"

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

static char *uuid = NULL;

static void print_usage(int argc, char **argv)
{
	char *name = NULL;
	
	name = strrchr(argv[0], '/');
	printf("\n%s - Pair or unpair a connected iPhone/iPod Touch/iPad.\n\n", (name ? name + 1: argv[0]));
	printf("Usage: %s [OPTIONS] COMMAND\n\n", (name ? name + 1: argv[0]));
	printf(" Where COMMAND is one of:\n");
	printf("  pair         pair device\n");
	printf("  validate     validate if paired with device\n");
	printf("  unpair       unpair device\n");
	printf("  list         list currently paired devices\n\n");
	printf(" The following OPTIONS are accepted:\n");
	printf("  -d, --debug      enable communication debugging\n");
	printf("  -u, --uuid UUID  target specific device by its 40-digit device UUID\n");
	printf("  -h, --help       prints usage information\n");
	printf("\n");
}

static void parse_opts(int argc, char **argv)
{
	static struct option longopts[] = {
		{"help", 0, NULL, 'h'},
		{"uuid", 0, NULL, 'u'},
		{"debug", 0, NULL, 'd'},
		{NULL, 0, NULL, 0}
	};
	int c;

	while (1) {
		c = getopt_long(argc, argv, "hu:d", longopts, (int*)0);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_usage(argc, argv);
			exit(0);
		case 'u':
			if (strlen(optarg) != 40) {
				printf("%s: invalid UUID specified (length != 40)\n", argv[0]);
				print_usage(argc, argv);
				exit(2);
			}
			uuid = strdup(optarg);
			break;
		case 'd':
			idevice_set_debug_level(1);
			break;
		default:
			print_usage(argc, argv);
			exit(2);
		}
	}
}

int main(int argc, char **argv)
{
	lockdownd_client_t client = NULL;
	idevice_t phone = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	lockdownd_error_t lerr;
	int result;
	char *type = NULL;
	char *cmd;
	typedef enum {
		OP_NONE = 0, OP_PAIR, OP_VALIDATE, OP_UNPAIR, OP_LIST
	} op_t;
	op_t op = OP_NONE;

	parse_opts(argc, argv);

	if ((argc - optind) < 1) {
		printf("ERROR: You need to specify a COMMAND!\n");
		print_usage(argc, argv);
		exit(2);
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
	} else {
		printf("ERROR: Invalid command '%s' specified\n", cmd);
		print_usage(argc, argv);
		exit(2);
	}

	if (op == OP_LIST) {
		unsigned int i;
		char **uuids = NULL;
		unsigned int count = 0;
		userpref_get_paired_uuids(&uuids, &count);
		for (i = 0; i < count; i++) {
			printf("%s\n", uuids[i]);
		}
		if (uuids) {
			g_strfreev(uuids);
		}
		if (uuid) {
			free(uuid);
		}
		return 0;
	}
		
	if (uuid) {
		ret = idevice_new(&phone, uuid);
		free(uuid);
		uuid = NULL;
		if (ret != IDEVICE_E_SUCCESS) {
			printf("No device found with uuid %s, is it plugged in?\n", uuid);
			return -1;
		}
	} else {
		ret = idevice_new(&phone, NULL);
		if (ret != IDEVICE_E_SUCCESS) {
			printf("No device found, is it plugged in?\n");
			return -1;
		}
	}

	lerr = lockdownd_client_new(phone, &client, "idevicepair");
	if (lerr != LOCKDOWN_E_SUCCESS) {
		idevice_free(phone);
		printf("ERROR: lockdownd_client_new failed with error code %d\n", lerr);
		return -1;
	}

	result = 0;
	lerr = lockdownd_query_type(client, &type);
	if (lerr != LOCKDOWN_E_SUCCESS) {
		printf("QueryType failed, error code %d\n", lerr);
		result = -1;
		goto leave;
	} else {
		if (strcmp("com.apple.mobile.lockdown", type)) {
			printf("WARNING: QueryType request returned '%s'\n", type);
		}
		if (type) {
			free(type);
		}
	}

	ret = idevice_get_uuid(phone, &uuid);
	if (ret != IDEVICE_E_SUCCESS) {
		printf("Could not get device uuid, error code %d\n", ret);
		result = -1;
		goto leave;
	}

	if ((op == OP_PAIR) || (op == OP_VALIDATE)) {
		/* TODO */
		lerr = lockdownd_pair(client, NULL);
		if (op == OP_VALIDATE) {
			ret = lockdownd_validate_pair(client, NULL);
		}
		if (lerr == LOCKDOWN_E_SUCCESS) {
			printf("SUCCESS -  device %s paired\n", uuid);
		} else if (lerr == LOCKDOWN_E_PASSWORD_PROTECTED) {
			printf("ERROR - Could not pair device because a passcode is set. Enter the passcode on the device and try again.\n");
		} else {
			printf("ERROR - Pairing failed, error code %d\n", lerr);
		}
	} else if (op == OP_UNPAIR) {
		lerr = lockdownd_unpair(client, NULL);
		if (lerr == LOCKDOWN_E_SUCCESS) {
			printf("SUCCESS - device %s unpaired\n", uuid);
		} else {
			if (lerr == LOCKDOWN_E_INVALID_HOST_ID) {
				printf("ERROR - Unpair %s failed: device is not paired with this system\n", uuid);
			} else {
				printf("ERROR - Unpair %s failed: return code %d\n", uuid, lerr);
			}
		}
	}

leave:
	lockdownd_client_free(client);
	idevice_free(phone);
	if (uuid) {
		free(uuid);
	}
	return result;
}

