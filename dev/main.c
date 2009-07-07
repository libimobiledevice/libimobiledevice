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

#include <libiphone/libiphone.h>
#include "../src/utils.h"

void notifier(const char *notification)
{
	printf("---------------------------------------------------------\n");
	printf("------> Notification received: %s\n", notification);
	printf("---------------------------------------------------------\n");
}

void perform_notification(iphone_device_t phone, iphone_lckd_client_t control, const char *notification)
{
	int nport = 0;
	iphone_np_client_t np;

	iphone_lckd_start_service(control, "com.apple.mobile.notification_proxy", &nport);
	if (nport) {
		printf("::::::::::::::: np was started ::::::::::::\n");
		iphone_np_new_client(phone, nport, &np);
		if (np) {
			printf("::::::::: PostNotification %s\n", notification);
			iphone_np_post_notification(np, notification);
			iphone_np_free_client(np);
		}
	} else {
		printf("::::::::::::::: np was NOT started ::::::::::::\n");
	}
}

int main(int argc, char *argv[])
{
	int bytes = 0, port = 0, i = 0;
	int npp;
	iphone_lckd_client_t control = NULL;
	iphone_device_t phone = NULL;
	uint64_t lockfile = 0;
	iphone_np_client_t gnp = NULL;

	if (argc > 1 && !strcasecmp(argv[1], "--debug")) {
		iphone_set_debug(1);
		iphone_set_debug_mask(DBGMASK_ALL);
	} else {
		iphone_set_debug(0);
		iphone_set_debug_mask(DBGMASK_NONE);
	}

	if (IPHONE_E_SUCCESS != iphone_get_device(&phone)) {
		printf("No iPhone found, is it plugged in?\n");
		return -1;
	}

	if (IPHONE_E_SUCCESS != iphone_lckd_new_client(phone, &control)) {
		iphone_free_device(phone);
		printf("Exiting.\n");
		return -1;
	}

	char *uid = NULL;
	if (IPHONE_E_SUCCESS == lockdownd_get_device_uid(control, &uid)) {
		printf("DeviceUniqueID : %s\n", uid);
		free(uid);
	}


	char *nnn = NULL;
	if (IPHONE_E_SUCCESS == lockdownd_get_device_name(control, &nnn)) {
		printf("DeviceName : %s\n", nnn);
		free(nnn);
	}

	iphone_lckd_start_service(control, "com.apple.afc", &port);

	if (port) {
		iphone_afc_client_t afc = NULL;
		iphone_afc_new_client(phone, port, &afc);
		if (afc) {
			iphone_lckd_start_service(control, "com.apple.mobile.notification_proxy", &npp);
			if (npp) {
				printf("Notification Proxy started.\n");
				iphone_np_new_client(phone, npp, &gnp);
			} else {
				printf("ERROR: Notification proxy could not be started.\n");
			}
			if (gnp) {
				const char *nspec[4] = {
					NP_SYNC_CANCEL_REQUEST,
					NP_SYNC_SUSPEND_REQUEST,
					NP_SYNC_RESUME_REQUEST,
					NULL
				};
				iphone_np_observe_notifications(gnp, nspec);
				iphone_np_set_notify_callback(gnp, notifier);
			}

			perform_notification(phone, control, NP_SYNC_WILL_START);

			iphone_afc_open_file(afc, "/com.apple.itunes.lock_sync", AFC_FOPEN_RW, &lockfile);
			if (lockfile) {
				printf("locking file\n");
				iphone_afc_lock_file(afc, lockfile, 2 | 4);

				perform_notification(phone, control, NP_SYNC_DID_START);
			}

			char **dirs = NULL;
			iphone_afc_get_dir_list(afc, "/eafaedf", &dirs);
			if (!dirs)
				iphone_afc_get_dir_list(afc, "/", &dirs);
			printf("Directory time.\n");
			for (i = 0; dirs[i]; i++) {
				printf("/%s\n", dirs[i]);
			}

			g_strfreev(dirs);

			dirs = NULL;
			iphone_afc_get_devinfo(afc, &dirs);
			if (dirs) {
				for (i = 0; dirs[i]; i += 2) {
					printf("%s: %s\n", dirs[i], dirs[i + 1]);
				}
			}
			g_strfreev(dirs);

			uint64_t my_file = 0;
			char **info = NULL;
			uint64_t fsize = 0;
			if (IPHONE_E_SUCCESS == iphone_afc_get_file_info(afc, "/readme.libiphone.fx", &info) && info) {
				for (i = 0; info[i]; i += 2) {
					printf("%s: %s\n", info[i], info[i+1]);
					if (!strcmp(info[i], "st_size")) {
						fsize = atoll(info[i+1]);
					}
				}
			}

			if (IPHONE_E_SUCCESS ==
				iphone_afc_open_file(afc, "/readme.libiphone.fx", AFC_FOPEN_RDONLY, &my_file) && my_file) {
				printf("A file size: %i\n", fsize);
				char *file_data = (char *) malloc(sizeof(char) * fsize);
				iphone_afc_read_file(afc, my_file, file_data, fsize, &bytes);
				if (bytes >= 0) {
					printf("The file's data:\n");
					fwrite(file_data, 1, bytes, stdout);
				}
				printf("\nClosing my file.\n");
				iphone_afc_close_file(afc, my_file);
				free(file_data);
			} else
				printf("couldn't open a file\n");

			iphone_afc_open_file(afc, "/readme.libiphone.fx", AFC_FOPEN_WR, &my_file);
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
			iphone_afc_open_file(afc, "/readme.libiphone.fx", AFC_FOPEN_RDONLY, &my_file);
			if (IPHONE_E_SUCCESS != iphone_afc_seek_file(afc, my_file, 5, SEEK_CUR))
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

		if (gnp && lockfile) {
			char *noti;

			/*
			noti = NULL;
			iphone_np_get_notification(gnp, &noti);
			if (noti) {
				printf("------> received notification '%s'\n", noti);
				free(noti);
			}*/

			printf("XXX sleeping\n");
			/*for (i = 0; i < 5; i++) {
				noti = NULL;
				printf("--- getting notification\n");
				iphone_np_get_notification(gnp, &noti);
				if (noti) {
					printf("------> received notification '%s'\n", noti);
					free(noti);
				} else {
					printf("---- no notification\n");
				}
				sleep(1);
			}
			*/
			sleep(5);

			//perform_notification(phone, control, NP_SYNC_DID_FINISH);

			printf("XXX unlocking file\n");
			iphone_afc_lock_file(afc, lockfile, 8 | 4);

			printf("XXX closing file\n");
			iphone_afc_close_file(afc, lockfile);
		}

		if (gnp) {
			iphone_np_free_client(gnp);
			gnp = NULL;
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
