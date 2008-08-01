/*
 * main.c
 * Rudimentary interface to the iPhone
 *
 * Copyright (c) 2008 Zack C. All Rights Reserved.
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
	char* host_id = NULL;
	iPhone *phone = get_iPhone();
	if (argc > 1 && !strcasecmp(argv[1], "--debug")) debug = 1;
	else debug = 0;
	char *response = (char*)malloc(sizeof(char) * 2048);
	int bytes = 0, port = 0, i = 0;
	if (phone) printf("I got a phone.\n");
	else { printf("oops\n"); return -1; }
	
	lockdownd_client *control = new_lockdownd_client(phone);
	if (!lockdownd_hello(control)) {
		printf("Something went wrong in the lockdownd client, go take a look.\n");
	} else {
		printf("We said hello. :)\n");
	}
		
	printf("Now starting SSL.\n");
	host_id = get_host_id();
	if (host_id && !lockdownd_start_SSL_session(control, host_id)) {
		printf("Error happened in GnuTLS...\n");
	} else { 
		free(host_id);
		host_id = NULL;
		printf("... we're in SSL with the phone... !?\n");
		port = lockdownd_start_service(control, "com.apple.afc");
	}
	if (port) {
		printf("Start Service successful -- connect on port %i\n", port);
		AFClient *afc = afc_connect(phone, 3432, port);
		if (afc) {
			char **dirs;
			dirs = afc_get_dir_list(afc, "/eafaedf");
			if (!dirs) dirs = afc_get_dir_list(afc, "/");
			printf("Directory time.\n");
			for (i = 0; strcmp(dirs[i], ""); i++) {
				printf("/%s\n", dirs[i]);
			}
			
			free_dictionary(dirs);
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
			else printf("Failure.\n");
			
			printf("Renaming a file...\n");
			bytes = afc_rename_file(afc, "/renme", "/renme2");
			if (bytes > 0) printf("Success.\n");
			else printf("Failure.\n");
		}
		afc_disconnect(afc);
	} else {
		printf("Start service failure.\n");
	}
	
	printf("All done.\n");
	
	free_iPhone(phone);
	
	return 0;
}

