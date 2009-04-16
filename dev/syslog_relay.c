/*
 * syslog_relay.c
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
#include <netinet/in.h>
#include <signal.h>
#include <usb.h>

#include <libiphone/libiphone.h>

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
	iphone_lckd_client_t control = NULL;
	iphone_device_t phone = NULL;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	int i;
	int bus_n = -1, dev_n = -1;
	int port = 0;

	signal(SIGINT, clean_exit);
	signal(SIGQUIT, clean_exit);
	signal(SIGTERM, clean_exit);
	signal(SIGPIPE, SIG_IGN);

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			iphone_set_debug_mask(DBGMASK_ALL);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--usb")) {
			if (sscanf(argv[++i], "%d,%d", &bus_n, &dev_n) < 2) {
				print_usage(argc, argv);
				return 0;
			}
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

	if (bus_n != -1) {
		ret = iphone_get_specific_device(bus_n, dev_n, &phone);
		if (ret != IPHONE_E_SUCCESS) {
			printf("No device found for usb bus %d and dev %d, is it plugged in?\n", bus_n, dev_n);
			return -1;
		}
	}
	else
	{
		ret = iphone_get_device(&phone);
		if (ret != IPHONE_E_SUCCESS) {
			printf("No device found, is it plugged in?\n");
			return -1;
		}
	}

	if (IPHONE_E_SUCCESS != iphone_lckd_new_client(phone, &control)) {
		iphone_free_device(phone);
		return -1;
	}

	/* start syslog_relay service and retrieve port */
	ret = iphone_lckd_start_service(control, "com.apple.syslog_relay", &port);
	if ((ret == IPHONE_E_SUCCESS) && port) {
		/* connect to socket relay messages */
		iphone_umux_client_t syslog_client = NULL;
		
		ret = iphone_mux_new_client(phone, 514, port, &syslog_client);
		if (ret == IPHONE_E_SUCCESS) {
			while (!quit_flag) {
				char *receive = NULL;
				uint32_t datalen = 0, bytes = 0, recv_bytes = 0;

				ret = iphone_mux_recv(syslog_client, (char *) &datalen, sizeof(datalen), &bytes);
				datalen = ntohl(datalen);

				if (datalen == 0)
					continue;

				recv_bytes += bytes;
				receive = (char *) malloc(sizeof(char) * datalen);

				while (!quit_flag && (recv_bytes <= datalen)) {
					ret = iphone_mux_recv(syslog_client, receive, datalen, &bytes);

					if (bytes == 0)
						break;

					recv_bytes += bytes;

					fwrite(receive, sizeof(char), bytes, stdout);
				}

				free(receive);
			}
		} else {
			printf("ERROR: Could not open usbmux connection.\n");
		}
		iphone_mux_free_client(syslog_client);
	} else {
		printf("ERROR: Could not start service com.apple.syslog_relay.\n");
	}

	iphone_lckd_free_client(control);
	iphone_free_device(phone);

	return 0;
}

void print_usage(int argc, char **argv)
{
	printf("Usage: %s [OPTIONS]\n", (strrchr(argv[0], '/') + 1));
	printf("Relay syslog of a connected iPhone/iPod Touch.\n\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --usb=BUS,DEV\ttarget specific device by usb bus/dev number\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
}

