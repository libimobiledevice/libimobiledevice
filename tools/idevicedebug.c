/*
 * idevicedebug.c
 * Interact with the debugserver service of a device.
 *
 * Copyright (c) 2014-2015 Martin Szulecki All Rights Reserved.
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

#define TOOL_NAME "idevicedebug"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>

#ifdef _WIN32
#include <windows.h>
#define sleep(x) Sleep(x*1000)
#endif

#include <libimobiledevice/installation_proxy.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/debugserver.h>
#include <plist/plist.h>
#include "common/debug.h"

static int debug_level = 0;

#define log_debug(...) if (debug_level > 0) { printf(__VA_ARGS__); fputc('\n', stdout); }

enum cmd_mode {
	CMD_NONE = 0,
	CMD_RUN,
	CMD_KILL
};

static int quit_flag = 0;

static void on_signal(int sig)
{
	fprintf(stderr, "Exiting...\n");
	quit_flag++;
}

static int cancel_receive()
{
	return quit_flag;
}

static instproxy_error_t instproxy_client_get_object_by_key_from_info_dictionary_for_bundle_identifier(instproxy_client_t client, const char* appid, const char* key, plist_t* node)
{
	if (!client || !appid || !key)
		return INSTPROXY_E_INVALID_ARG;

	plist_t apps = NULL;

	// create client options for any application types
	plist_t client_opts = instproxy_client_options_new();
	instproxy_client_options_add(client_opts, "ApplicationType", "Any", NULL);

	// only return attributes we need
	instproxy_client_options_set_return_attributes(client_opts, "CFBundleIdentifier", "CFBundleExecutable", key, NULL);

	// only query for specific appid
	const char* appids[] = {appid, NULL};

	// query device for list of apps
	instproxy_error_t ierr = instproxy_lookup(client, appids, client_opts, &apps);

	instproxy_client_options_free(client_opts);

	if (ierr != INSTPROXY_E_SUCCESS) {
		return ierr;
	}

	plist_t app_found = plist_access_path(apps, 1, appid);
	if (!app_found) {
		if (apps)
			plist_free(apps);
		*node = NULL;
		return INSTPROXY_E_OP_FAILED;
	}

	plist_t object = plist_dict_get_item(app_found, key);
	if (object) {
		*node = plist_copy(object);
	} else {
		log_debug("key %s not found", key);
		return INSTPROXY_E_OP_FAILED;
	}

	plist_free(apps);

	return INSTPROXY_E_SUCCESS;
}

static debugserver_error_t debugserver_client_handle_response(debugserver_client_t client, char** response, int* exit_status)
{
	debugserver_error_t dres = DEBUGSERVER_E_SUCCESS;
	char* o = NULL;
	char* r = *response;

	/* Documentation of response codes can be found here:
	   https://github.com/llvm/llvm-project/blob/4fe839ef3a51e0ea2e72ea2f8e209790489407a2/lldb/docs/lldb-gdb-remote.txt#L1269
	*/
        
	if (r[0] == 'O') {
		/* stdout/stderr */
		debugserver_decode_string(r + 1, strlen(r) - 1, &o);
		printf("%s", o);
		fflush(stdout);
	} else if (r[0] == 'T') {
		/* thread stopped information */
		log_debug("Thread stopped. Details:\n%s", r + 1);
		if (exit_status != NULL) {
			/* "Thread stopped" seems to happen when assert() fails.
			   Use bash convention where signals cause an exit
			   status of 128 + signal
			*/
			*exit_status = 128 + SIGABRT;
		}
		/* Break out of the loop. */
		dres = DEBUGSERVER_E_UNKNOWN_ERROR;
	} else if (r[0] == 'E') {
		printf("ERROR: %s\n", r + 1);
	} else if (r[0] == 'W' || r[0] == 'X') {
		/* process exited */
		debugserver_decode_string(r + 1, strlen(r) - 1, &o);
		if (o != NULL) {
			printf("Exit %s: %u\n", (r[0] == 'W' ? "status" : "due to signal"), o[0]);
			if (exit_status != NULL) {
				/* Use bash convention where signals cause an
				   exit status of 128 + signal
				*/
				*exit_status = o[0] + (r[0] == 'W' ? 0 : 128);
			}
		} else {
			log_debug("Unable to decode exit status from %s", r);
			dres = DEBUGSERVER_E_UNKNOWN_ERROR;
                }
	} else if (r && strlen(r) == 0) {
		log_debug("empty response");
	} else {
		log_debug("ERROR: unhandled response '%s'", r);
	}

	if (o != NULL) {
		free(o);
		o = NULL;
	}

	free(*response);
	*response = NULL;
	return dres;
}

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Interact with the debugserver service of a device.\n"
		"\n"
		"Where COMMAND is one of:\n"
		"  run BUNDLEID [ARGS...]  run app with BUNDLEID and optional ARGS on device.\n"
		"  kill BUNDLEID           kill app with BUNDLEID\n"
		"\n"
		"The following OPTIONS are accepted:\n"
		"  -u, --udid UDID       target specific device by UDID\n"
		"  -n, --network         connect to network device\n"
		"      --detach          detach from app after launch, keeping it running\n"
		"  -e, --env NAME=VALUE  set environment variable NAME to VALUE\n"
		"  -d, --debug           enable communication debugging\n"
		"  -h, --help            prints usage information\n"
		"  -v, --version         prints version information\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

int main(int argc, char *argv[])
{
	int res = -1;
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	instproxy_client_t instproxy_client = NULL;
	debugserver_client_t debugserver_client = NULL;
	int i;
	int cmd = CMD_NONE;
	const char* udid = NULL;
	int use_network = 0;
	int detach_after_start = 0;
	const char* bundle_identifier = NULL;
	char* path = NULL;
	char* working_directory = NULL;
	char **newlist = NULL;
	char** environment = NULL;
	int environment_index = 0;
	int environment_count = 0;
	char* response = NULL;
	debugserver_command_t command = NULL;
	debugserver_error_t dres = DEBUGSERVER_E_UNKNOWN_ERROR;

	int c = 0;
	const struct option longopts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "udid", required_argument, NULL, 'u' },
		{ "network", no_argument, NULL, 'n' },
		{ "detach", no_argument, NULL, 1 },
		{ "env", required_argument, NULL, 'e' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	/* map signals */
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
#ifndef _WIN32
	signal(SIGQUIT, on_signal);
	signal(SIGPIPE, SIG_IGN);
#endif

	while ((c = getopt_long(argc, argv, "dhu:ne:v", longopts, NULL)) != -1) {
		switch (c) {
		case 'd':
			debug_level++;
			if (debug_level > 1) {
				idevice_set_debug_level(debug_level-1);
			}
			break;
		case 'u':
			if (!*optarg) {
				fprintf(stderr, "ERROR: UDID must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			}
			udid = optarg;
			break;
		case 'n':
			use_network = 1;
			break;
		case 1:
			detach_after_start = 1;
			break;
		case 'e':
			if (!*optarg || strchr(optarg, '=') == NULL) {
				fprintf(stderr, "ERROR: environment variables need to be specified as -e KEY=VALUE\n");
				print_usage(argc, argv, 1);
				res = 2;
				goto cleanup;
			}
			/* add environment variable */
			if (!newlist)
				newlist = malloc((environment_count + 1) * sizeof(char*));
			else
				newlist = realloc(environment, (environment_count + 1) * sizeof(char*));
			newlist[environment_count++] = strdup(optarg);
			environment = newlist;
			break;
		case 'h':
			print_usage(argc, argv, 0);
			res = 0;
			goto cleanup;
			break;
		case 'v':
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			res = 0;
			goto cleanup;
			break;
		default:
			print_usage(argc, argv, 1);
			res = 2;
			goto cleanup;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		fprintf(stderr, "ERROR: Missing command.\n");
		print_usage(argc+optind, argv-optind, 1);
		return 2;
	}

	if (!strcmp(argv[0], "run")) {
		cmd = CMD_RUN;
		if (argc < 2) {
			/* make sure at least the bundle identifier was provided */
			fprintf(stderr, "ERROR: Please supply the bundle identifier of the app to run.\n");
			print_usage(argc+optind, argv-optind, 1);
			res = 2;
			goto cleanup;
		}
		/*  read bundle identifier */
		bundle_identifier = argv[1];
		i = 1;
	} else if (!strcmp(argv[0], "kill")) {
		cmd = CMD_KILL;
		if (argc < 2) {
			/* make sure at least the bundle identifier was provided */
			fprintf(stderr, "ERROR: Please supply the bundle identifier of the app to run.\n");
			print_usage(argc+optind, argv-optind, 1);
			res = 2;
			goto cleanup;
		}
		/*  read bundle identifier */
		bundle_identifier = argv[1];
		i = 1;
	}

	/* verify options */
	if (cmd == CMD_NONE) {
		fprintf(stderr, "ERROR: Unsupported command specified.\n");
		print_usage(argc+optind, argv-optind, 1);
		res = 2;
		goto cleanup;
	}

	if (environment) {
		newlist = realloc(environment, (environment_count + 1) * sizeof(char*));
		newlist[environment_count] = NULL;
		environment = newlist;
	}

	/* connect to the device */
	ret = idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX);
	if (ret != IDEVICE_E_SUCCESS) {
		if (udid) {
			printf("No device found with udid %s.\n", udid);
		} else {
			printf("No device found.\n");
		}
		goto cleanup;
	}

	/* get the path to the app and it's working directory */
	if (instproxy_client_start_service(device, &instproxy_client, TOOL_NAME) != INSTPROXY_E_SUCCESS) {
		fprintf(stderr, "Could not start installation proxy service.\n");
		goto cleanup;
	}

	instproxy_client_get_path_for_bundle_identifier(instproxy_client, bundle_identifier, &path);
	if (!path) {
		fprintf(stderr, "Invalid bundle identifier: %s\n", bundle_identifier);
		goto cleanup;
	}

	plist_t container = NULL;
	instproxy_client_get_object_by_key_from_info_dictionary_for_bundle_identifier(instproxy_client, bundle_identifier, "Container", &container);
	instproxy_client_free(instproxy_client);
	instproxy_client = NULL;

	if (container && (plist_get_node_type(container) == PLIST_STRING)) {
		plist_get_string_val(container, &working_directory);
		log_debug("working_directory: %s\n", working_directory);
		plist_free(container);
	} else {
		plist_free(container);
		fprintf(stderr, "Could not determine container path for bundle identifier %s.\n", bundle_identifier);
		goto cleanup;
	}

	/* start and connect to debugserver */
	if (debugserver_client_start_service(device, &debugserver_client, TOOL_NAME) != DEBUGSERVER_E_SUCCESS) {
		fprintf(stderr,
			"Could not start com.apple.debugserver!\n"
			"Please make sure to mount the developer disk image first:\n"
			"  1) Get the iOS version from `ideviceinfo -k ProductVersion`.\n"
			"  2) Find the matching iPhoneOS DeveloperDiskImage.dmg files.\n"
			"  3) Run `ideviceimagemounter` with the above path.\n");
		goto cleanup;
	}

	/* set receive params */
	if (debugserver_client_set_receive_params(debugserver_client, cancel_receive, 250) != DEBUGSERVER_E_SUCCESS) {
		fprintf(stderr, "Error in debugserver_client_set_receive_params\n");
		goto cleanup;
	}

	/* enable logging for the session in debug mode */
	if (debug_level) {
		log_debug("Setting logging bitmask...");
		debugserver_command_new("QSetLogging:bitmask=LOG_ALL|LOG_RNB_REMOTE|LOG_RNB_PACKETS;", 0, NULL, &command);
		dres = debugserver_client_send_command(debugserver_client, command, &response, NULL);
		debugserver_command_free(command);
		command = NULL;
		if (response) {
			if (strncmp(response, "OK", 2) != 0) {
				debugserver_client_handle_response(debugserver_client, &response, NULL);
				goto cleanup;
			}
			free(response);
			response = NULL;
		}
	}

	/* set maximum packet size */
	log_debug("Setting maximum packet size...");
	char* packet_size[2] = { (char*)"1024", NULL};
	debugserver_command_new("QSetMaxPacketSize:", 1, packet_size, &command);
	dres = debugserver_client_send_command(debugserver_client, command, &response, NULL);
	debugserver_command_free(command);
	command = NULL;
	if (response) {
		if (strncmp(response, "OK", 2) != 0) {
			debugserver_client_handle_response(debugserver_client, &response, NULL);
			goto cleanup;
		}
		free(response);
		response = NULL;
	}

	/* set working directory */
	log_debug("Setting working directory...");
	char* working_dir[2] = {working_directory, NULL};
	debugserver_command_new("QSetWorkingDir:", 1, working_dir, &command);
	dres = debugserver_client_send_command(debugserver_client, command, &response, NULL);
	debugserver_command_free(command);
	command = NULL;
	if (response) {
		if (strncmp(response, "OK", 2) != 0) {
			debugserver_client_handle_response(debugserver_client, &response, NULL);
			goto cleanup;
		}
		free(response);
		response = NULL;
	}

	/* set environment */
	if (environment) {
		log_debug("Setting environment...");
		for (environment_index = 0; environment_index < environment_count; environment_index++) {
			log_debug("setting environment variable: %s", environment[environment_index]);
			debugserver_client_set_environment_hex_encoded(debugserver_client, environment[environment_index], NULL);
		}
	}

	/* set arguments and run app */
	log_debug("Setting argv...");
	i++; /* i is the offset of the bundle identifier, thus skip it */
	int app_argc = (argc - i + 2);
	char **app_argv = (char**)malloc(sizeof(char*) * app_argc);
	app_argv[0] = path;
	log_debug("app_argv[%d] = %s", 0, app_argv[0]);
	app_argc = 1;
	while (i < argc && argv && argv[i]) {
		log_debug("app_argv[%d] = %s", app_argc, argv[i]);
		app_argv[app_argc++] = argv[i];
		i++;
	}
	app_argv[app_argc] = NULL;
	debugserver_client_set_argv(debugserver_client, app_argc, app_argv, NULL);
	free(app_argv);

	/* check if launch succeeded */
	log_debug("Checking if launch succeeded...");
	debugserver_command_new("qLaunchSuccess", 0, NULL, &command);
	dres = debugserver_client_send_command(debugserver_client, command, &response, NULL);
	debugserver_command_free(command);
	command = NULL;
	if (response) {
		if (strncmp(response, "OK", 2) != 0) {
			debugserver_client_handle_response(debugserver_client, &response, NULL);
			goto cleanup;
		}
		free(response);
		response = NULL;
	}

	if (cmd == CMD_KILL) {
		debugserver_command_new("k", 0, NULL, &command);
		dres = debugserver_client_send_command(debugserver_client, command, &response, NULL);
		debugserver_command_free(command);
		command = NULL;
		goto cleanup;
	} else
	if (cmd == CMD_RUN) {
		if (detach_after_start) {
			log_debug("Detaching from app");
			debugserver_command_new("D", 0, NULL, &command);
			dres = debugserver_client_send_command(debugserver_client, command, &response, NULL);
			debugserver_command_free(command);
			command = NULL;

			res = (dres == DEBUGSERVER_E_SUCCESS) ? 0: -1;
			goto cleanup;
		}

		/* set thread */
		log_debug("Setting thread...");
		debugserver_command_new("Hc0", 0, NULL, &command);
		dres = debugserver_client_send_command(debugserver_client, command, &response, NULL);
		debugserver_command_free(command);
		command = NULL;
		if (response) {
			if (strncmp(response, "OK", 2) != 0) {
				debugserver_client_handle_response(debugserver_client, &response, NULL);
				goto cleanup;
			}
			free(response);
			response = NULL;
		}

		/* continue running process */
		log_debug("Continue running process...");
		debugserver_command_new("c", 0, NULL, &command);
		dres = debugserver_client_send_command(debugserver_client, command, &response, NULL);
		debugserver_command_free(command);
		command = NULL;
		log_debug("Continue response: %s", response);

		/* main loop which is parsing/handling packets during the run */
		log_debug("Entering run loop...");
		while (!quit_flag) {
			if (dres != DEBUGSERVER_E_SUCCESS) {
				log_debug("failed to receive response; error %d", dres);
				break;
			}

			if (response) {
				log_debug("response: %s", response);
				if (strncmp(response, "OK", 2) != 0) {
					dres = debugserver_client_handle_response(debugserver_client, &response, &res);
					if (dres != DEBUGSERVER_E_SUCCESS) {
						log_debug("failed to process response; error %d; %s", dres, response);
						break;
					}
				}
			}
			if (res >= 0) {
				goto cleanup;
			}

			dres = debugserver_client_receive_response(debugserver_client, &response, NULL);
		}

		/* ignore quit_flag after this point */
		if (debugserver_client_set_receive_params(debugserver_client, NULL, 5000) != DEBUGSERVER_E_SUCCESS) {
			fprintf(stderr, "Error in debugserver_client_set_receive_params\n");
			goto cleanup;
		}

		/* interrupt execution */
		debugserver_command_new("\x03", 0, NULL, &command);
		dres = debugserver_client_send_command(debugserver_client, command, &response, NULL);
		debugserver_command_free(command);
		command = NULL;
		if (response) {
			if (strncmp(response, "OK", 2) != 0) {
				debugserver_client_handle_response(debugserver_client, &response, NULL);
			}
			free(response);
			response = NULL;
		}

		/* kill process after we finished */
		log_debug("Killing process...");
		debugserver_command_new("k", 0, NULL, &command);
		dres = debugserver_client_send_command(debugserver_client, command, &response, NULL);
		debugserver_command_free(command);
		command = NULL;
		if (response) {
			if (strncmp(response, "OK", 2) != 0) {
				debugserver_client_handle_response(debugserver_client, &response, NULL);
			}
			free(response);
			response = NULL;
		}

		if (res < 0) {
			res = (dres == DEBUGSERVER_E_SUCCESS) ? 0: -1;
		}
	}

cleanup:
	/* cleanup the house */
	if (environment) {
		for (environment_index = 0; environment_index < environment_count; environment_index++) {
			free(environment[environment_index]);
		}
		free(environment);
	}

	if (working_directory)
		free(working_directory);

	if (path)
		free(path);

	if (response)
		free(response);

	if (debugserver_client)
		debugserver_client_free(debugserver_client);

	if (device)
		idevice_free(device);

	return res;
}
