/*
 * idevicesyslog.c
 * Relay the syslog of a device to stdout
 *
 * Copyright (c) 2010-2019 Nikias Bassen, All Rights Reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#ifdef WIN32
#include <windows.h>
#define sleep(x) Sleep(x*1000)
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/syslog_relay.h>

static int quit_flag = 0;

static char* udid = NULL;

static idevice_t device = NULL;
static syslog_relay_client_t syslog = NULL;

enum idevice_options lookup_opts = IDEVICE_LOOKUP_USBMUX | IDEVICE_LOOKUP_NETWORK;

static void syslog_callback(char c, void *user_data)
{
	putchar(c);
	if (c == '\n') {
		fflush(stdout);
	}
}

static int start_logging(void)
{
	idevice_error_t ret = idevice_new_with_options(&device, udid, lookup_opts);
	if (ret != IDEVICE_E_SUCCESS) {
		fprintf(stderr, "Device with udid %s not found!?\n", udid);
		return -1;
	}

	lockdownd_client_t lockdown = NULL;
	lockdownd_error_t lerr = lockdownd_client_new_with_handshake(device, &lockdown, "idevicesyslog");
	if (lerr != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd: %d\n", lerr);
		idevice_free(device);
		device = NULL;
		return -1;
	}

	/* start syslog_relay service */
	lockdownd_service_descriptor_t svc = NULL;
	lerr = lockdownd_start_service(lockdown, SYSLOG_RELAY_SERVICE_NAME, &svc);
	if (lerr == LOCKDOWN_E_PASSWORD_PROTECTED) {
		fprintf(stderr, "*** Device is passcode protected, enter passcode on the device to continue ***\n");
		while (!quit_flag) {
			lerr = lockdownd_start_service(lockdown, SYSLOG_RELAY_SERVICE_NAME, &svc);
			if (lerr != LOCKDOWN_E_PASSWORD_PROTECTED) {
				break;
			}
			sleep(1);
		}
	}
	if (lerr != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd: %d\n", lerr);
		idevice_free(device);
		device = NULL;
		return -1;
	}
	lockdownd_client_free(lockdown);

	/* connect to syslog_relay service */
	syslog_relay_error_t serr = SYSLOG_RELAY_E_UNKNOWN_ERROR;
	serr = syslog_relay_client_new(device, svc, &syslog);
	lockdownd_service_descriptor_free(svc);
	if (serr != SYSLOG_RELAY_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not start service com.apple.syslog_relay.\n");
		idevice_free(device);
		device = NULL;
		return -1;
	}

	/* start capturing syslog */
	serr = syslog_relay_start_capture(syslog, syslog_callback, NULL);
	if (serr != SYSLOG_RELAY_E_SUCCESS) {
		fprintf(stderr, "ERROR: Unable tot start capturing syslog.\n");
		syslog_relay_client_free(syslog);
		syslog = NULL;
		idevice_free(device);
		device = NULL;
		return -1;
	}

	fprintf(stdout, "[connected]\n");
	fflush(stdout);

	return 0;
}

static void stop_logging(void)
{
	fflush(stdout);

	if (syslog) {
		syslog_relay_client_free(syslog);
		syslog = NULL;
	}

	if (device) {
		idevice_free(device);
		device = NULL;
	}
}

static void device_event_cb(const idevice_event_t* event, void* userdata)
{
	if (event->event == IDEVICE_DEVICE_ADD) {
		if (!syslog) {
			if (!udid) {
				udid = strdup(event->udid);
			}
			if (strcmp(udid, event->udid) == 0) {
				if (start_logging() != 0) {
					fprintf(stderr, "Could not start logger for udid %s\n", udid);
				}
			}
		}
	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		if (syslog && (strcmp(udid, event->udid) == 0)) {
			stop_logging();
			fprintf(stdout, "[disconnected]\n");
		}
	}
}

/**
 * signal handler function for cleaning up properly
 */
static void clean_exit(int sig)
{
	fprintf(stderr, "\nExiting...\n");
	quit_flag++;
}

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = NULL;
	name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS]\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
	  "Relay syslog of a connected device.\n\n" \
	  "  -u, --udid UDID  target specific device by UDID\n" \
	  "  -n, --network    connect to network device even if available via USB\n" \
	  "  -h, --help       prints usage information\n" \
	  "  -d, --debug      enable communication debugging\n" \
	  "\n" \
	  "Homepage: <" PACKAGE_URL ">\n"
	);
}

int main(int argc, char *argv[])
{
	int c = 0;
	const struct option longopts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "udid", required_argument, NULL, 'u' },
		{ NULL, 0, NULL, 0}
	};

	signal(SIGINT, clean_exit);
	signal(SIGTERM, clean_exit);
#ifndef WIN32
	signal(SIGQUIT, clean_exit);
	signal(SIGPIPE, SIG_IGN);
#endif

	while ((c = getopt_long(argc, argv, "dhu:n", longopts, NULL)) != -1) {
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
			free(udid);
			udid = strdup(optarg);
			break;
		case 'n':
			lookup_opts |= IDEVICE_LOOKUP_PREFER_NETWORK;
			break;
		case 'h':
			print_usage(argc, argv, 0);
			return 0;
		default:
			print_usage(argc, argv, 1);
			return 2;
		}
	}

	argc -= optind;
	argv += optind;

	int num = 0;
	idevice_info_t *devices = NULL;
	idevice_get_device_list_extended(&devices, &num);
	idevice_device_list_extended_free(devices);
	if (num == 0) {
		if (!udid) {
			fprintf(stderr, "No device found. Plug in a device or pass UDID with -u to wait for device to be available.\n");
			return -1;
		} else {
			fprintf(stderr, "Waiting for device with UDID %s to become available...\n", udid);
		}
	}

	idevice_event_subscribe(device_event_cb, NULL);

	while (!quit_flag) {
		sleep(1);
	}
	idevice_event_unsubscribe();
	stop_logging();

	free(udid);

	return 0;
}
