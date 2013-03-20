/*
 * afccheck.c
 * creates threads and check communication through AFC is done rigth
 *
 * Copyright (c) 2008 Jonathan Beck All Rights Reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>
#include "common/thread.h"

#define BUFFER_SIZE 20000
#define NB_THREADS 10


typedef struct {
	afc_client_t afc;
	int id;
} param;


static void* check_afc(void *data)
{
	//prepare a buffer
	unsigned int buffersize = BUFFER_SIZE * sizeof(unsigned int);
	int *buf = (int *) malloc(buffersize);
	int *buf2 = (int *) malloc(buffersize);
	unsigned int bytes = 0;
	uint64_t position = 0;
	
	//fill buffer
	int i = 0;
	for (i = 0; i < BUFFER_SIZE; i++) {
		buf[i] = ((param *) data)->id * i;
	}

	//now  writes buffer on device
	uint64_t file = 0;
	char path[50];
	sprintf(path, "/Buf%i", ((param *) data)->id);
	afc_file_open(((param *) data)->afc, path, AFC_FOPEN_RW, &file);
	afc_file_write(((param *) data)->afc, file, (char *) buf, buffersize, &bytes);
	afc_file_close(((param *) data)->afc, file);
	file = 0;
	if (bytes != buffersize)
		printf("Write operation failed\n");

	//now read it
	bytes = 0;
	afc_file_open(((param *) data)->afc, path, AFC_FOPEN_RDONLY, &file);
	afc_file_read(((param *) data)->afc, file, (char *) buf2, buffersize/2, &bytes);
	afc_file_read(((param *) data)->afc, file, (char *) buf2 + (buffersize/2), buffersize/2, &bytes);
	if(AFC_E_SUCCESS != afc_file_tell(((param *) data)->afc, file, &position))
		printf("Tell operation failed\n");
	afc_file_close(((param *) data)->afc, file);
	if (position != buffersize)
		printf("Read operation failed\n");

	//compare buffers
	for (i = 0; i < BUFFER_SIZE; i++) {
		if (buf[i] != buf2[i]) {
			printf("Buffers are differents, stream corrupted\n");
			break;
		}
	}

	//cleanup
	afc_remove_path(((param *) data)->afc, path);
	return NULL;
}

int main(int argc, char *argv[])
{
	lockdownd_client_t client = NULL;
	idevice_t phone = NULL;
	lockdownd_service_descriptor_t service = NULL;
	afc_client_t afc = NULL;

	if (argc > 1 && !strcasecmp(argv[1], "--debug")) {
		idevice_set_debug_level(1);
	} else {
		idevice_set_debug_level(0);
	}

	if (IDEVICE_E_SUCCESS != idevice_new(&phone, NULL)) {
		printf("No device found, is it plugged in?\n");
		return 1;
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(phone, &client, "afccheck")) {
		idevice_free(phone);
		return 1;
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_start_service(client, "com.apple.afc", &service) || !service || !service->port) {
		lockdownd_client_free(client);
		idevice_free(phone);
		fprintf(stderr, "Something went wrong when starting AFC.");
		return 1;
	}

	afc_client_new(phone, service, &afc);

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

	thread_t threads[NB_THREADS];
	param data[NB_THREADS];

	int i = 0;
	for (i = 0; i < NB_THREADS; i++) {
		data[i].afc = afc;
		data[i].id = i + 1;
		thread_create(&threads[i], check_afc, data + i);
	}

	for (i = 0; i < NB_THREADS; i++) {
		thread_join(threads[i]);
	}

	lockdownd_client_free(client);
	idevice_free(phone);

	return 0;
}
