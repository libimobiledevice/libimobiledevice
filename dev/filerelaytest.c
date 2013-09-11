/*
 * filerelaytest.c
 * Simple Test program showing the usage of the file_relay interface.
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
#include <stdlib.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/file_relay.h>

int main(int argc, char **argv)
{
	idevice_t dev = NULL;
	lockdownd_client_t client = NULL;
	lockdownd_service_descriptor_t service = NULL;
	file_relay_client_t frc = NULL;
	idevice_connection_t dump = NULL;
	const char **sources;
	const char *default_sources[] = {"AppleSupport", "Network", "VPN", "WiFi", "UserDatabases", "CrashReporter", "tmp", "SystemConfiguration", NULL};
	int i = 0;

	if (idevice_new(&dev, NULL) != IDEVICE_E_SUCCESS) {
		printf("no device connected?!\n");
		goto leave_cleanup;
	}

	printf("connecting...\n");
	if (lockdownd_client_new_with_handshake(dev, &client, NULL) != LOCKDOWN_E_SUCCESS) {
		printf("could not connect to lockdownd!\n");
		goto leave_cleanup;
	}

	if (lockdownd_start_service(client, FILE_RELAY_SERVICE_NAME, &service) != LOCKDOWN_E_SUCCESS) {
		printf("could not start file_relay service!\n");
		goto leave_cleanup;
	}

	if (client) {
		lockdownd_client_free(client);
		client = NULL;
	}

	if (file_relay_client_new(dev, service, &frc) != FILE_RELAY_E_SUCCESS) {
		printf("could not connect to file_relay service!\n");
		goto leave_cleanup;
	}

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

	if (argc > 1) {
		sources = calloc(1, argc * sizeof(char *));
		argc--;
		argv++;
		for (i = 0; i < argc; i++) {
			sources[i] = argv[i];
		}
	}
	else {
		sources = default_sources;
	}

	printf("Requesting");
	i = 0;
	while (sources[i]) {
		printf(" %s", sources[i]);
		i++;
	}
	printf("\n");

	if (file_relay_request_sources(frc, sources, &dump) != FILE_RELAY_E_SUCCESS) {
		printf("could not get sources\n");
		goto leave_cleanup;
	}

	if (!dump) {
		printf("did not get connection!\n");
		goto leave_cleanup;
	}

	uint32_t cnt = 0;
	uint32_t len = 0;
	char buf[4096];
	FILE *f = fopen("dump.cpio.gz", "wb");
	setbuf(stdout, NULL);
	printf("receiving ");
	while (idevice_connection_receive(dump, buf, 4096, &len) == IDEVICE_E_SUCCESS) {
		fwrite(buf, 1, len, f);
		cnt += len;
		printf(".");
		len = 0;
	}
	printf("\n");
	fclose(f);
	printf("total size received: %d\n", cnt);

leave_cleanup:
	if (frc) {
		file_relay_client_free(frc);
	}
	if (client) {
		lockdownd_client_free(client);
	}
	if (dev) {
		idevice_free(dev);
	}

	return 0;
}
