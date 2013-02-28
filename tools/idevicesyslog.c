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
#include <unistd.h>

#ifdef WIN32
#include <windows.h>
#define sleep(x) Sleep(x*1000)
#else
#include <pthread.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <endianness.h>
#include "../src/service.h"

static int quit_flag = 0;

void print_usage(int argc, char **argv);

static char* udid = NULL;

static idevice_t device = NULL;
static service_client_t syslog = NULL;

#ifdef WIN32
HANDLE worker = NULL;
#else
pthread_t worker;
#endif

static int logging = 0;

static void *syslog_worker(void *arg)
{
	service_error_t ret = SERVICE_E_UNKNOWN_ERROR;

	fprintf(stdout, "[connected]\n");
	fflush(stdout);
	
	logging = 1;

	while (logging) {
		char c;
		uint32_t bytes = 0;
		ret = service_receive_with_timeout(syslog, &c, 1, &bytes, 0);
		if (ret < 0 || (bytes != 1)) {
			printf("\n[connection interrupted]\n");
			fflush(stdout);
			break;
		}
		if(c != 0) {
			putchar(c);
		}
	}

	return NULL;
}

static int start_logging()
{
	idevice_error_t ret = idevice_new(&device, udid);
	if (ret != IDEVICE_E_SUCCESS) {
		fprintf(stderr, "Device with udid %s not found!?\n", udid);
		return -1;
	}

	/* start and connect to syslog_relay service */
	service_error_t serr = SERVICE_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, "com.apple.syslog_relay", (void**)&syslog, "idevicesyslog", NULL, &serr);
	if (serr != SERVICE_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not start service com.apple.syslog_relay.\n");
		idevice_free(device);
		device = NULL;
		return -1;
	}

	/* start worker thread */
	logging = 1;
#ifdef WIN32
	worker = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)syslog_worker, NULL, 0, NULL);
	if (worker == INVALID_HANDLE_VALUE) {
		logging = 0;
		return -1;
	}
#else
	if (pthread_create(&worker, NULL, syslog_worker, NULL) != 0) {
		logging = 0;
		return -1;
	}
#endif

	return 0;
}

static void stop_logging()
{
	if (logging) {
		/* notify thread to finish */
		logging = 0;
		if (syslog) {
			service_client_free(syslog);
			syslog = NULL;
		}

		/* wait for thread to complete */
#ifdef WIN32
		WaitForSingleObject(worker, INFINITE);
#else
		pthread_join(worker, NULL);
#endif
	}

	if (device) {
		idevice_free(device);
		device = NULL;
	}
}

static void device_event_cb(const idevice_event_t* event, void* userdata)
{
	if (event->event == IDEVICE_DEVICE_ADD) {
		if (!logging) {
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
		if (logging && (strcmp(udid, event->udid) == 0)) {
			stop_logging();
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

int main(int argc, char *argv[])
{
	int i;

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

	int num = 0;
	char **devices = NULL;
	idevice_get_device_list(&devices, &num);
	idevice_device_list_free(devices);
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
 
	if (udid) {
		free(udid);
	}

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

