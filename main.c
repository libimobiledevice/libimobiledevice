/*
 * libiphone main.c written by FxChiP
 * With much help from Daniel Brownlees
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

int debug = 1;

int main(int argc, char *argv[]) {
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
	if (!lockdownd_start_SSL_session(control, "29942970-207913891623273984")) {
		printf("Error happened in GnuTLS...\n");
	} else { 
		printf("... we're in SSL with the phone... !?\n");
	}
	port = lockdownd_start_service(control, "com.apple.afc");
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
		}
		afc_disconnect(afc);
	} else {
		printf("Start service failure.\n");
	}
	
	printf("All done.\n");
	
	free_iPhone(phone);
	
	return 0;
}

