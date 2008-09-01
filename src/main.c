/*
 * main.c
 * Rudimentary interface to the iPhone
 *
 * Copyright (c) 2008 Zach C. All Rights Reserved.
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
#include <usb.h>

#include "usbmux.h"
#include "iphone.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <libiphone/libiphone.h>

int debug = 1;

int main(int argc, char *argv[])
{
	int bytes = 0, port = 0, i = 0;
	iphone_lckd_client_t control = NULL;
	iphone_device_t phone = NULL;

	if (argc > 1 && !strcasecmp(argv[1], "--debug")) {
		debug = 1;
	} else {
		debug = 0;
	}

	if (IPHONE_E_SUCCESS != iphone_get_device(&phone)) {
		printf("No iPhone found, is it plugged in?\n");
		return -1;
	}

	if (IPHONE_E_SUCCESS != iphone_lckd_new_client(phone, &control)) {
		iphone_free_device(phone);
		return -1;
	}

	char *uid = NULL;
	if (IPHONE_E_SUCCESS == lockdownd_get_device_uid(control, &uid)) {
		printf("DeviceUniqueID : %s\n", uid);
		free(uid);
	}

	iphone_lckd_start_service(control, "com.apple.afc", &port);

	if (port) {
		iphone_afc_client_t afc = NULL;
		iphone_afc_new_client(phone, 3432, port, &afc);
		if (afc) {
			char **dirs = NULL;
			iphone_afc_get_dir_list(afc, "/eafaedf", &dirs);
			if (!dirs)
				iphone_afc_get_dir_list(afc, "/", &dirs);
			printf("Directory time.\n");
			for (i = 0; dirs[i]; i++) {
				printf("/%s\n", dirs[i]);
			}

			g_strfreev(dirs);
			iphone_afc_get_devinfo(afc, &dirs);
			if (dirs) {
				for (i = 0; dirs[i]; i += 2) {
					printf("%s: %s\n", dirs[i], dirs[i + 1]);
				}
			}
			g_strfreev(dirs);

			iphone_afc_file_t my_file = NULL;
			struct stat stbuf;
			iphone_afc_get_file_attr(afc, "/iTunesOnTheGoPlaylist.plist", &stbuf);
			if (IPHONE_E_SUCCESS ==
				iphone_afc_open_file(afc, "/iTunesOnTheGoPlaylist.plist", IPHONE_AFC_FILE_READ, &my_file) && my_file) {
				printf("A file size: %i\n", stbuf.st_size);
				char *file_data = (char *) malloc(sizeof(char) * stbuf.st_size);
				iphone_afc_read_file(afc, my_file, file_data, stbuf.st_size, &bytes);
				if (bytes >= 0) {
					printf("The file's data:\n");
					fwrite(file_data, 1, bytes, stdout);
				}
				printf("\nClosing my file.\n");
				iphone_afc_close_file(afc, my_file);
				free(file_data);
			} else
				printf("couldn't open a file\n");

			iphone_afc_open_file(afc, "/readme.libiphone.fx", IPHONE_AFC_FILE_WRITE, &my_file);
			if (my_file) {
				char *outdatafile = strdup("this is a bitchin text file\n");
				iphone_afc_write_file(afc, my_file, outdatafile, strlen(outdatafile), &bytes);
				free(outdatafile);
				if (bytes > 0)
					printf("Wrote a surprise. ;)\n");
				else
					printf("I wanted to write a surprise, but... :(\n");
				iphone_afc_close_file(afc, my_file);
			}
			printf("Deleting a file...\n");
			bytes = iphone_afc_delete_file(afc, "/delme");
			if (bytes)
				printf("Success.\n");
			else
				printf("Failure. (expected unless you have a /delme file on your phone)\n");

			printf("Renaming a file...\n");
			bytes = iphone_afc_rename_file(afc, "/renme", "/renme2");
			if (bytes > 0)
				printf("Success.\n");
			else
				printf("Failure. (expected unless you have a /renme file on your phone)\n");

			printf("Seek & read\n");
			iphone_afc_open_file(afc, "/readme.libiphone.fx", IPHONE_AFC_FILE_READ, &my_file);
			if (IPHONE_E_SUCCESS != iphone_afc_seek_file(afc, my_file, 5))
				printf("WARN: SEEK DID NOT WORK\n");
			char *threeletterword = (char *) malloc(sizeof(char) * 5);
			iphone_afc_read_file(afc, my_file, threeletterword, 3, &bytes);
			threeletterword[3] = '\0';
			if (bytes > 0)
				printf("Result: %s\n", threeletterword);
			else
				printf("Couldn't read!\n");
			free(threeletterword);
			iphone_afc_close_file(afc, my_file);

		}
		iphone_afc_free_client(afc);
	} else {
		printf("Start service failure.\n");
	}

	printf("All done.\n");

	iphone_lckd_free_client(control);
	iphone_free_device(phone);

	return 0;
}
