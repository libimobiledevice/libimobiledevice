/*
 * idevicelocation.c
 * Simulate location on a device
 *
 * Copyright (C) 2017 Robbert van Ginkel <robbert@vanginkels.com>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/service.h>
#include "endianness.h"

void print_usage(int argc, char **argv);

int send_cmd(service_client_t sclient, int cmd)
{
	service_error_t res;
	int send_bytes = 0;
	res = service_send(sclient, (const char*)&cmd, 0x4, (uint32_t*)&send_bytes);
	if (res != SERVICE_E_SUCCESS){
		printf("ERROR: Could not send data, error code %d\n", res);
		return -1;
	} else if (send_bytes != 4) {
		printf("ERROR: Could not send all data, send %d bytes (expected %d)\n", send_bytes, 0x4);
		return -1;
	}
	return 0;
}

int send_string(service_client_t sclient, const char *string)
{
	service_error_t res;
	int send_bytes = 0;

	int len = strlen(string);
	int nlen = htobe32(len);
	
	res = service_send(sclient, (const char*)&nlen, 0x4, (uint32_t*)&send_bytes);
	if (res != SERVICE_E_SUCCESS){
		printf("ERROR: Could not send data, error code %d\n", res);
		return -1;
	} else if (send_bytes != 4) {
		printf("ERROR: Could not send all data, send %d bytes (expected %d)\n", send_bytes, 0x4);
		return -1;
	}
	
	send_bytes = 0;
	res = service_send(sclient, (const char*)string, len, (uint32_t*)&send_bytes);
	if (res != SERVICE_E_SUCCESS){
		printf("ERROR: Could not send data, error code %d\n", res);
		return -1;
	} else if (send_bytes != len) {
		printf("ERROR: Could not send all data, send %d bytes (expected %d)\n", send_bytes, len);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	lockdownd_client_t lckd = NULL;
	lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
	lockdownd_service_descriptor_t service = NULL;
	int result = -1;
	int i;
	const char *udid = NULL;
	const char *latitude = NULL;
	const char *longtitude = NULL;
	int stop = 0;
	int CMD_START = 0x0000000;
	int CMD_STOP = 0x1000000;

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
		else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--stop")) {
			stop = 1;
			continue;
		}
		else if (latitude == NULL) {
			latitude = argv[i];
			continue;
		}
		else if (longtitude == NULL) {
			longtitude = argv[i];
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
	if (!stop && (!latitude || !longtitude)) {
		print_usage(argc, argv);
		return -1;
	}
	
	if (IDEVICE_E_SUCCESS != idevice_new(&device, udid)) {
		if (udid) {
			printf("No device found with udid %s, is it plugged in?\n", udid);
		} else {
			printf("No device found, is it plugged in?\n");
		}
		return -1;
	}

	if (LOCKDOWN_E_SUCCESS != (ldret = lockdownd_client_new_with_handshake(device, &lckd, NULL))) {
		idevice_free(device);
		printf("ERROR: Could not connect to lockdownd, error code %d\n", ldret);
		return -1;
	}

	lockdownd_start_service(lckd, "com.apple.dt.simulatelocation", &service);
	lockdownd_client_free(lckd);

	if (service && service->port > 0) {
		service_client_t sclient = NULL;
		service_error_t rerr = service_client_new(device, service, &sclient);
		if (rerr != SERVICE_E_SUCCESS) {
			printf("Could not connect to DTSimulateLocation!\n");
		} else {
			if (stop) {
				result = send_cmd(sclient, CMD_STOP);
			} else {
				result = send_cmd(sclient, CMD_START);
				result = result - send_string(sclient, latitude);
				result = result - send_string(sclient, longtitude);
			}
		}
	} else {
		printf("Could not start DTSimulateLocation service! Remember that you have to mount the Developer disk image on your device if you want to use the DTSimulateLocation service.\n");
	}

	if (service)
		lockdownd_service_descriptor_free(service);

	idevice_free(device);

	return result;
}

void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] latitude longtitude\n", (name ? name + 1: argv[0]));
	printf("NOTE: A mounted developer disk image is required on the device, otherwise\n");
	printf("the DTSimulateLocation service is not available.\n\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
	printf("Homepage: <" PACKAGE_URL ">\n");
}
