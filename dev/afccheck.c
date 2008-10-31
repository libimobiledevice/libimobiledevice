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
#include <glib.h>

#include <libiphone/libiphone.h>

#define BUFFER_SIZE 20000
#define NB_THREADS 10


typedef struct {
	iphone_afc_client_t afc;
	int id;
} param;


void check_afc(gpointer data)
{
	//prepare a buffer
	int buffersize = BUFFER_SIZE * sizeof(int);
	int *buf = (int *) malloc(buffersize);
	int *buf2 = (int *) malloc(buffersize);
	int bytes = 0;
	//fill buffer
	int i = 0;
	for (i = 0; i < BUFFER_SIZE; i++) {
		buf[i] = ((param *) data)->id * i;
	}

	//now  writes buffer on iphone
	iphone_afc_file_t file = NULL;
	char path[50];
	sprintf(path, "/Buf%i", ((param *) data)->id);
	iphone_afc_open_file(((param *) data)->afc, path, IPHONE_AFC_FILE_WRITE, &file);
	iphone_afc_write_file(((param *) data)->afc, file, (char *) buf, buffersize, &bytes);
	iphone_afc_close_file(((param *) data)->afc, file);
	file = NULL;
	if (bytes != buffersize)
		printf("Write operation failed\n");

	//now read it
	bytes = 0;
	iphone_afc_open_file(((param *) data)->afc, path, IPHONE_AFC_FILE_READ, &file);
	iphone_afc_read_file(((param *) data)->afc, file, (char *) buf2, buffersize, &bytes);
	iphone_afc_close_file(((param *) data)->afc, file);
	if (bytes != buffersize)
		printf("Read operation failed\n");

	//compare buffers
	for (i = 0; i < BUFFER_SIZE; i++) {
		if (buf[i] != buf2[i]) {
			printf("Buffers are differents, stream corrupted\n");
			break;
		}
	}

	//cleanup
	iphone_afc_delete_file(((param *) data)->afc, path);
	g_thread_exit(0);
}

int main(int argc, char *argv[])
{
	iphone_lckd_client_t control = NULL;
	iphone_device_t phone = NULL;
	GError *err;
	int port = 0;
	iphone_afc_client_t afc = NULL;

	if (IPHONE_E_SUCCESS != iphone_get_device(&phone)) {
		printf("No iPhone found, is it plugged in?\n");
		return 1;
	}

	if (IPHONE_E_SUCCESS != iphone_lckd_new_client(phone, &control)) {
		iphone_free_device(phone);
		return 1;
	}

	if (IPHONE_E_SUCCESS == iphone_lckd_start_service(control, "com.apple.afc", &port) && !port) {
		iphone_lckd_free_client(control);
		iphone_free_device(phone);
		fprintf(stderr, "Something went wrong when starting AFC.");
		return 1;
	}

	iphone_afc_new_client(phone, 3432, port, &afc);

	//makes sure thread environment is available
	if (!g_thread_supported())
		g_thread_init(NULL);

	GThread *threads[NB_THREADS];
	param data[NB_THREADS];

	int i = 0;
	for (i = 0; i < NB_THREADS; i++) {
		data[i].afc = afc;
		data[i].id = i + 1;
		threads[i] = g_thread_create((GThreadFunc) check_afc, data + i, TRUE, &err);
	}

	for (i = 0; i < NB_THREADS; i++) {
		g_thread_join(threads[i]);
	}


	iphone_lckd_free_client(control);
	iphone_free_device(phone);

	return 0;
}
