/*
 * idevicenotificationproxy.c
 * Simple client for the notification_proxy service
 *
 * Copyright (c) 2018-2024 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2009-2015 Martin Szulecki, All Rights Reserved.
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

#define TOOL_NAME "idevicenotificationproxy"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#ifdef _WIN32
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

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Post or observe notifications on a device.\n"
		"\n"
		"Where COMMAND is one of:\n"
		"  post ID [...]         post notification IDs to device and exit\n"
		"  observe ID [...]      observe notification IDs in foreground until CTRL+C\n"
                "                        or signal is received\n"
		"\n"
		"The following OPTIONS are accepted:\n"
		"  -u, --udid UDID       target specific device by UDID\n"
		"  -i, --insecure        use insecure notification proxy (non-paired device)\n"
		"  -n, --network         connect to network device\n"
		"  -d, --debug           enable communication debugging\n"
		"  -h, --help            prints usage information\n"
		"  -v, --version         prints version information\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
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
	int i = 0;
	const char* udid = NULL;
	int use_network = 0;
	int insecure = 0;
	int cmd = CMD_NONE;
	char* cmd_arg = NULL;

	int count = 0;
	char **nspec = NULL;
	char **nspectmp = NULL;

	int c = 0;
	const struct option longopts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "udid", required_argument, NULL, 'u' },
		{ "insecure", no_argument, NULL, 'i' },
		{ "network", no_argument, NULL, 'n' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0}
	};

	signal(SIGINT, clean_exit);
	signal(SIGTERM, clean_exit);
#ifndef _WIN32
	signal(SIGQUIT, clean_exit);
	signal(SIGPIPE, SIG_IGN);
#endif

	/* parse cmdline args */
	while ((c = getopt_long(argc, argv, "dhu:inv", longopts, NULL)) != -1) {
		switch (c) {
		case 'd':
			idevice_set_debug_level(1);
			break;
		case 'u':
			if (!*optarg) {
				fprintf(stderr, "ERROR: UDID argument must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			}
			udid = optarg;
			break;
		case 'n':
			use_network = 1;
			break;
		case 'i':
			insecure = 1;
			break;
		case 'h':
			print_usage(argc, argv, 0);
			return 0;
		case 'v':
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			return 0;
		default:
			print_usage(argc, argv, 1);
			return 2;
		}
	}
	argc -= optind;
	argv += optind;

	if (!argv[i]) {
		fprintf(stderr, "ERROR: Missing command\n");
		print_usage(argc+optind, argv-optind, 1);
		return 2;
	}

	if (!strcmp(argv[i], "post")) {
		cmd = CMD_POST;
	} else if (!strcmp(argv[i], "observe")) {
		cmd = CMD_OBSERVE;
	}

	if (cmd == CMD_POST || cmd == CMD_OBSERVE) {
		i++;
		if (!argv[i]) {
			fprintf(stderr, "ERROR: Please supply a valid notification identifier.\n");
			print_usage(argc+optind, argv-optind, 1);
			return 2;
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
	}

	/* verify options */
	if (cmd == CMD_NONE) {
		fprintf(stderr, "ERROR: Unsupported command '%s'\n", argv[0]);
		print_usage(argc+optind, argv-optind, 1);
		return 2;
	}

	if (IDEVICE_E_SUCCESS != idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX)) {
		if (udid) {
			printf("No device found with udid %s.\n", udid);
		} else {
			printf("No device found.\n");
		}
		goto cleanup;
	}

	if (insecure) {
		ret = lockdownd_client_new(device, &client, TOOL_NAME);
	} else {
		ret = lockdownd_client_new_with_handshake(device, &client, TOOL_NAME);
	}
	if (LOCKDOWN_E_SUCCESS != ret) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd: %s (%d)\n", lockdownd_strerror(ret), ret);
		goto cleanup;
	}

	ret = lockdownd_start_service(client, (insecure) ? "com.apple.mobile.insecure_notification_proxy" : NP_SERVICE_NAME, &service);

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
		printf("ERROR: Could not start service %s: %s\n", NP_SERVICE_NAME, lockdownd_strerror(ret));
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
