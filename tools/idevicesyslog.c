/*
 * idevicesyslog.c
 * Relay the syslog of a device to stdout
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <endianness.h>

static int quit_flag = 0;

void print_usage(int argc, char **argv);

/**
 * signal handler function for cleaning up properly
 */
static void clean_exit(int sig)
{
	fprintf(stderr, "Exiting...\n");
	quit_flag++;
}

int main(int argc, char *argv[])
{
	lockdownd_client_t client = NULL;
	idevice_t phone = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	int i;
	char udid[41];
	uint16_t port = 0;
	udid[0] = 0;

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
			strcpy(udid, argv[i]);
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

	if (udid[0] != 0) {
		ret = idevice_new(&phone, udid);
		if (ret != IDEVICE_E_SUCCESS) {
			printf("No device found with udid %s, is it plugged in?\n", udid);
			return -1;
		}
	}
	else
	{
		ret = idevice_new(&phone, NULL);
		if (ret != IDEVICE_E_SUCCESS) {
			printf("No device found, is it plugged in?\n");
			return -1;
		}
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(phone, &client, "idevicesyslog")) {
		idevice_free(phone);
		return -1;
	}

	/* start syslog_relay service and retrieve port */
	ret = lockdownd_start_service(client, "com.apple.syslog_relay", &port);
	if ((ret == LOCKDOWN_E_SUCCESS) && port) {
		lockdownd_client_free(client);
		
		/* connect to socket relay messages */
		idevice_connection_t conn = NULL;
		if ((idevice_connect(phone, port, &conn) != IDEVICE_E_SUCCESS) || !conn) {
			printf("ERROR: Could not open usbmux connection.\n");
		} else {
			while (!quit_flag) {
				char c;
				uint32_t bytes = 0;
				if (idevice_connection_receive(conn, &c, 1, &bytes) < 0) {
					fprintf(stderr, "Error receiving data. Exiting...\n");
					break;
				}
				if (c != 0) {
					putchar(c);
					fflush(stdout);
				}
			}
		}
		idevice_disconnect(conn);
	} else {
		printf("ERROR: Could not start service com.apple.syslog_relay.\n");
	}

	idevice_free(phone);

	return 0;
}

void print_usage(int argc, char **argv)
{
	char *name = NULL;
	
	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS]\n", (name ? name + 1: argv[0]));
	printf("Relay syslog of a connected device.\n\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
}

