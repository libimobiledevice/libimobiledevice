/*
 * ideviceheartbeat.c
 * Simple utility which keeps a "heartbeat service" connection alive
 *
 * Copyright (c) 2013 Martin Szulecki All Rights Reserved.
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
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/heartbeat.h>

static int quit_flag = 0;

/**
 * signal handler function for cleaning up properly
 */
static void clean_exit(int sig)
{
	fprintf(stderr, "Exiting...\n");
	quit_flag++;
}

static void print_usage(int argc, char **argv)
{
	char *name = NULL;
	
	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS]\n", (name ? name + 1: argv[0]));
	printf("Runs in the foreground and keeps a \"heartbeat\" connection alive.\n\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	heartbeat_client_t heartbeat = NULL;
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	int i;
	const char* udid = NULL;

	signal(SIGINT, clean_exit);
	signal(SIGTERM, clean_exit);
#ifndef WIN32
	signal(SIGQUIT, clean_exit);
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
			if (!argv[i] || (strlen(argv[i]) != 40)) {
				print_usage(argc, argv);
				return 0;
			}
			udid = argv[i];
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

	ret = idevice_new(&device, udid);
	if (ret != IDEVICE_E_SUCCESS) {
		if (udid) {
			printf("No device found with udid %s, is it plugged in?\n", udid);
		} else {
			printf("No device found, is it plugged in?\n");
		}
		return -1;
	}

	/* start heartbeat service on device */
	heartbeat_client_start_service(device, &heartbeat, "ideviceheartbeat");
	if (heartbeat) {
		printf("< heartbeat started, listening...\n");
	} else {
		printf("Failed to start heartbeat service\n");
		idevice_free(device);
		return -1;
	}

	/* main loop */
	uint8_t b = 0;
	uint64_t interval = 10000;
	plist_t message = NULL;
	plist_t node = NULL;
	do {
		/* await a "ping" message from the device every interval seconds */
		heartbeat_receive_with_timeout(heartbeat, &message, (uint32_t)interval);
		if (message) {
			/* report device beat settings */
			node = plist_dict_get_item(message, "SupportsSleepyTime");
			if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
				plist_get_bool_val(node, &b);
			}
			node = plist_dict_get_item(message, "Interval");
			if (node && plist_get_node_type(node) == PLIST_UINT) {
				plist_get_uint_val(node, &interval);
			}

			printf("> marco: supports_sleepy_time %d, interval %"PRIu64"\n", b, interval);

			plist_free(message);
			message = NULL;

			/* answer with a "pong" message */
			message = plist_new_dict();
			plist_dict_set_item(message, "Command", plist_new_string("Polo"));
			heartbeat_send(heartbeat, message);

			printf("< polo\n");

			if (message) {
				plist_free(message);
				message = NULL;
			}
		}
	} while(!quit_flag);

	heartbeat_client_free(heartbeat);

	idevice_free(device);

	return 0;
}
