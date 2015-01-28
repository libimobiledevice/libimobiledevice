/*
 * idevicenotificationproxy.c
 * Simple client for the notification_proxy service
 *
 * Copyright (c) 2009-2015 Martin Szulecki All Rights Reserved.
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

#ifdef WIN32
#include <windows.h>
#define sleep(x) Sleep(x*1000)
#else
#include <unistd.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/notification_proxy.h>

enum cmd_mode {
	CMD_NONE = 0,
	CMD_OBSERVE,
	CMD_POST
};

static int quit_flag = 0;

/**
 * signal handler function for cleaning up properly
 */
static void clean_exit(int sig)
{
	fprintf(stderr, "Exiting...\n");
	quit_flag++;
}

static void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
	printf("Post or observe notifications on a device.\n\n");
	printf(" Where COMMAND is one of:\n");
	printf("  post ID [...]\t\tpost notification IDs to device and exit\n");
	printf("  observe ID [...]\tobserve notification IDs in the foreground until CTRL+C or signal is received\n");
	printf("\n");
	printf(" The following OPTIONS are accepted:\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
	printf("Homepage: <http://libimobiledevice.org>\n");
}

static void notify_cb(const char *notification, void *user_data)
{
	printf("> %s\n", notification);
}

int main(int argc, char *argv[])
{
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	lockdownd_service_descriptor_t service = NULL;
	lockdownd_client_t client = NULL;
	idevice_t device = NULL;
	np_client_t gnp = NULL;

	int result = -1;
	int i;
	const char* udid = NULL;
	int cmd = CMD_NONE;
	char* cmd_arg = NULL;

	int count = 0;
	char **nspec = NULL;
	char **nspectmp = NULL;

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
				result = 0;
				goto cleanup;
			}
			udid = argv[i];
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			result = 0;
			goto cleanup;
		}
		else if (!strcmp(argv[i], "post") || !strcmp(argv[i], "observe")) {
			cmd = CMD_POST;
			if (!strcmp(argv[i], "observe")) {
				cmd = CMD_OBSERVE;
			}

			i++;

			if (!argv[i] || argv[i] == NULL || (!strncmp(argv[i], "-", 1))) {
				printf("Please supply a valid notification identifier.\n");
				print_usage(argc, argv);
				goto cleanup;
			}

			count = 0;
			nspec = malloc(sizeof(char*) * (count+1));

			while(1) {
				if (argv[i] && (strlen(argv[i]) >= 2) && (strncmp(argv[i], "-", 1) != 0)) {
					nspectmp = realloc(nspec, sizeof(char*) * (count+1));
					nspectmp[count] = strdup(argv[i]);
					nspec = nspectmp;
					count = count+1;
					i++;
				} else {
					i--;
					break;
				}
			}

			nspectmp = realloc(nspec, sizeof(char*) * (count+1));
			nspectmp[count] = NULL;
			nspec = nspectmp;
			continue;
		}
		else {
			print_usage(argc, argv);
			return 0;
		}
	}

	/* verify options */
	if (cmd == CMD_NONE) {
		print_usage(argc, argv);
		goto cleanup;
	}

	if (IDEVICE_E_SUCCESS != idevice_new(&device, udid)) {
		if (udid) {
			printf("No device found with udid %s, is it plugged in?\n", udid);
		} else {
			printf("No device found, is it plugged in?\n");
		}
		goto cleanup;
	}

	if (LOCKDOWN_E_SUCCESS != (ret = lockdownd_client_new_with_handshake(device, &client, "idevicenotificationproxy"))) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd, error code %d\n", ret);
		goto cleanup;
	}

	ret = lockdownd_start_service(client, NP_SERVICE_NAME, &service);

	lockdownd_client_free(client);

	if ((ret == LOCKDOWN_E_SUCCESS) && (service->port > 0)) {
		if (np_client_new(device, service, &gnp) != NP_E_SUCCESS) {
			printf("Could not connect to notification_proxy!\n");
			result = -1;
		} else {
			np_set_notify_callback(gnp, notify_cb, NULL);

			switch (cmd) {
				case CMD_POST:
					i = 0;
					while(nspec[i] != NULL && i < (count+1)) {
						printf("< posting \"%s\"\n", nspec[i]);
						np_post_notification(gnp, nspec[i]);
						i++;
					}
					break;
				case CMD_OBSERVE:
				default:
					i = 0;
					while(nspec[i] != NULL && i < (count+1)) {
						printf("! observing \"%s\"\n", nspec[i]);
						np_observe_notification(gnp, nspec[i]);
						i++;
					}

					/* just sleep and wait for notifications */
					while (!quit_flag) {
						sleep(1);
					}

					break;
			}

			result = EXIT_SUCCESS;

			if (gnp) {
				np_client_free(gnp);
				gnp = NULL;
			}
		}
	} else {
		printf("Could not start notification_proxy service on device.\n");
	}

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

cleanup:
	if (nspec) {
		i = 0;
		while(nspec[i] != NULL && i < (count+1)) {
			free(nspec[i]);
			i++;
		}
		free(nspec);
	}

	if (cmd_arg) {
		free(cmd_arg);
	}

	if (device)
		idevice_free(device);

	return result;
}
