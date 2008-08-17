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
#include "plist.h"
#include "lockdown.h"
#include "AFC.h"
#include "userpref.h"

int debug = 1;

int main(int argc, char *argv[]) {
	int bytes = 0, port = 0, i = 0;
	lockdownd_client *control = NULL;
	iPhone *phone = get_iPhone();
	
	if (argc > 1 && !strcasecmp(argv[1], "--debug")){
		debug = 1;
	} else {
		debug = 0;
	}
	
	if (!phone) {
		printf("No iPhone found, is it plugged in?\n");
		return -1;
       	}

	if (!lockdownd_init(phone, &control)){
		free_iPhone(phone);
		return -1;
	}

	port = lockdownd_start_service(control, "com.apple.afc");
	
	if (port) {
		AFClient *afc = afc_connect(phone, 3432, port);
		if (afc) {
			char **dirs;
			dirs = afc_get_dir_list(afc, "/eafaedf");
			if (!dirs) dirs = afc_get_dir_list(afc, "/");
			printf("Directory time.\n");
			for (i = 0; dirs[i]; i++) {
				printf("/%s\n", dirs[i]);
			}
			
			g_strfreev(dirs);
			dirs = afc_get_devinfo(afc);
			if (dirs) {
				for (i = 0; dirs[i]; i+=2) {
					printf("%s: %s\n", dirs[i], dirs[i+1]);
				}
			}
			g_strfreev(dirs);
			
			AFCFile *my_file = afc_open_file(afc, "/iTunesOnTheGoPlaylist.plist", AFC_FILE_READ);
			if (my_file) {
				printf("A file size: %i\n", my_file->size);
				char *file_data = (char*)malloc(sizeof(char) * my_file->size);
				bytes = afc_read_file(afc, my_file, file_data, my_file->size);
				if (bytes >= 0) {
					printf("The file's data:\n");
					fwrite(file_data, 1, bytes, stdout);
				}
				printf("\nClosing my file.\n");
				afc_close_file(afc, my_file);
				free(my_file);
				free(file_data);
			} else printf("couldn't open a file\n");
			
			my_file = afc_open_file(afc, "/readme.libiphone.fx", AFC_FILE_WRITE);
			if (my_file) {
				char *outdatafile = strdup("this is a bitchin text file\n");
				bytes = afc_write_file(afc, my_file, outdatafile, strlen(outdatafile));
				free(outdatafile);
				if (bytes > 0) printf("Wrote a surprise. ;)\n");
				else printf("I wanted to write a surprise, but... :(\n");
				afc_close_file(afc, my_file);
				free(my_file);
			}
			printf("Deleting a file...\n");
			bytes = afc_delete_file(afc, "/delme");
			if (bytes) printf("Success.\n");
			else printf("Failure. (expected unless you have a /delme file on your phone)\n");
			
			printf("Renaming a file...\n");
			bytes = afc_rename_file(afc, "/renme", "/renme2");
			if (bytes > 0) printf("Success.\n");
			else printf("Failure. (expected unless you have a /renme file on your phone)\n");
			
			printf("Seek & read\n");
			my_file = afc_open_file(afc, "/readme.libiphone.fx", AFC_FILE_READ);
			bytes = afc_seek_file(afc, my_file, 5);
			if (bytes) printf("WARN: SEEK DID NOT WORK\n");
			char *threeletterword = (char*)malloc(sizeof(char) * 5);
			bytes = afc_read_file(afc, my_file, threeletterword, 3);
			threeletterword[3] = '\0';
			if (bytes > 0) printf("Result: %s\n", threeletterword);
			else printf("Couldn't read!\n");
			free(threeletterword);
			afc_close_file(afc, my_file);
			free(my_file);
			
		}
		afc_disconnect(afc);
	} else {
		printf("Start service failure.\n");
	}
	
	printf("All done.\n");

	lockdownd_close(control);
	free_iPhone(phone);
	
	return 0;
}

