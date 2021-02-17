/*
 * idevicedebugserverproxy.c
 * Proxy a debugserver connection from device for remote debugging
 *
 * Copyright (c) 2021 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2012 Martin Szulecki All Rights Reserved.
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

#define TOOL_NAME "idevicedebugserverproxy"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/select.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/debugserver.h>

#include "common/socket.h"
#include "common/thread.h"

#define info(...) fprintf(stdout, __VA_ARGS__); fflush(stdout)
#define debug(...) if(debug_mode) fprintf(stdout, __VA_ARGS__)

static int debug_mode = 0;
static int quit_flag = 0;

typedef struct {
	int client_fd;
	idevice_t device;
	debugserver_client_t debugserver_client;
} socket_info_t;

struct thread_info {
	THREAD_T th;
	int client_fd;
	struct thread_info *next;
};

typedef struct thread_info thread_info_t;


static void clean_exit(int sig)
{
	fprintf(stderr, "Exiting...\n");
	quit_flag++;
}

static void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] <PORT>\n", (name ? name + 1: argv[0]));
	printf("\n");
	printf("Proxy debugserver connection from device to a local socket at PORT.\n");
	printf("\n");
	printf("OPTIONS:\n");
	printf("  -u, --udid UDID\ttarget specific device by UDID\n");
	printf("  -n, --network\t\tconnect to network device\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("  -v, --version\t\tprints version information\n");
	printf("\n");
	printf("Homepage:    <" PACKAGE_URL ">\n");
	printf("Bug Reports: <" PACKAGE_BUGREPORT ">\n");
}

static void* connection_handler(void* data)
{
	debugserver_error_t derr = DEBUGSERVER_E_SUCCESS;
	socket_info_t* socket_info = (socket_info_t*)data;
	const int bufsize = 65536;
	char* buf;

	int client_fd = socket_info->client_fd;

	debug("%s: client_fd = %d\n", __func__, client_fd);

	derr = debugserver_client_start_service(socket_info->device, &socket_info->debugserver_client, TOOL_NAME);
	if (derr != DEBUGSERVER_E_SUCCESS) {
		fprintf(stderr, "Could not start debugserver on device!\nPlease make sure to mount a developer disk image first.\n");
		return NULL;
	}

	buf = malloc(bufsize);
	if (!buf) {
		fprintf(stderr, "Failed to allocate buffer\n");
		return NULL;
	}

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(client_fd, &fds);

	int dtimeout = 1;

	while (!quit_flag) {
		ssize_t n = socket_receive_timeout(client_fd, buf, bufsize, 0, 1);
		if (n != -ETIMEDOUT) {
			if (n < 0) {
				fprintf(stderr, "Failed to read from client fd: %s\n", strerror(-n));
				break;
			} else if (n == 0) {
				fprintf(stderr, "connection closed\n");
				break;
			}

			uint32_t sent = 0;
			debugserver_client_send(socket_info->debugserver_client, buf, n, &sent);
		}
		do {
			uint32_t r = 0;
			derr = debugserver_client_receive_with_timeout(socket_info->debugserver_client, buf, bufsize, &r, dtimeout);
			if (r > 0) {
				socket_send(client_fd, buf, r);
				dtimeout = 1;
			} else if (derr == DEBUGSERVER_E_TIMEOUT) {
				dtimeout = 5;
				break;
			} else {
				fprintf(stderr, "debugserver connection closed\n");
				break;
			}
		} while (derr == DEBUGSERVER_E_SUCCESS);
		if (derr != DEBUGSERVER_E_TIMEOUT && derr != DEBUGSERVER_E_SUCCESS) {
			break;
		}
	}
	free(buf);

	debug("%s: shutting down...\n", __func__);

	debugserver_client_free(socket_info->debugserver_client);
	socket_info->debugserver_client = NULL;

	/* shutdown client socket */
	socket_shutdown(socket_info->client_fd, SHUT_RDWR);
	socket_close(socket_info->client_fd);

	return NULL;
}

int main(int argc, char *argv[])
{
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	idevice_t device = NULL;
	thread_info_t *thread_list = NULL;
	const char* udid = NULL;
	int use_network = 0;
	uint16_t local_port = 0;
	int server_fd;
	int result = EXIT_SUCCESS;
	int i;

#ifndef WIN32
	struct sigaction sa;
	struct sigaction si;
	memset(&sa, '\0', sizeof(struct sigaction));
	memset(&si, '\0', sizeof(struct sigaction));

	sa.sa_handler = clean_exit;
	sigemptyset(&sa.sa_mask);

	si.sa_handler = SIG_IGN;
	sigemptyset(&si.sa_mask);

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGPIPE, &si, NULL);
#else
	/* bind signals */
	signal(SIGINT, clean_exit);
	signal(SIGTERM, clean_exit);
#endif

	/* parse cmdline arguments */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			debug_mode = 1;
			idevice_set_debug_level(1);
			socket_set_verbose(3);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udid")) {
			i++;
			if (!argv[i] || !*argv[i]) {
				print_usage(argc, argv);
				return 0;
			}
			udid = argv[i];
			continue;
		}
		else if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--network")) {
			use_network = 1;
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return EXIT_SUCCESS;
		}
		else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			return EXIT_SUCCESS;
		}
		else if (atoi(argv[i]) > 0) {
			local_port = atoi(argv[i]);
			continue;
		}
		else {
			print_usage(argc, argv);
			return EXIT_SUCCESS;
		}
	}

	/* a PORT is mandatory */
	if (!local_port) {
		fprintf(stderr, "Please specify a PORT.\n");
		print_usage(argc, argv);
		goto leave_cleanup;
	}

	/* start services and connect to device */
	ret = idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX);
	if (ret != IDEVICE_E_SUCCESS) {
		if (udid) {
			fprintf(stderr, "No device found with udid %s.\n", udid);
		} else {
			fprintf(stderr, "No device found.\n");
		}
		result = EXIT_FAILURE;
		goto leave_cleanup;
	}

	/* create local socket */
	server_fd = socket_create("127.0.0.1", local_port);
	if (server_fd < 0) {
		fprintf(stderr, "Could not create socket\n");
		result = EXIT_FAILURE;
		goto leave_cleanup;
	}

	while (!quit_flag) {
		debug("%s: Waiting for connection on local port %d\n", __func__, local_port);

		/* wait for client */
		int client_fd = socket_accept(server_fd, local_port);
		if (client_fd < 0) {
			continue;
		}

		debug("%s: Handling new client connection...\n", __func__);

		thread_info_t *el = (thread_info_t*)malloc(sizeof(thread_info_t));
		if (!el) {
			fprintf(stderr, "Out of memory\n");
			exit(EXIT_FAILURE);
		}
		el->client_fd = client_fd;
		el->next = NULL;

		if (thread_list) {
			thread_list->next = el;
		} else {
			thread_list = el;
		}

		socket_info_t *sinfo = (socket_info_t*)malloc(sizeof(socket_info_t));
		if (!sinfo) {
			fprintf(stderr, "Out of memory\n");
			exit(EXIT_FAILURE);
		}
		sinfo->client_fd = client_fd;
		sinfo->device = device;

		if (thread_new(&(el->th), connection_handler, (void*)sinfo) != 0) {
			fprintf(stderr, "Could not start connection handler.\n");
			socket_shutdown(server_fd, SHUT_RDWR);
			socket_close(server_fd);
			break;
		}
	}

	debug("%s: Shutting down debugserver proxy...\n", __func__);

	/* join and clean up threads */
	while (thread_list) {
		thread_info_t *el = thread_list;
		socket_shutdown(el->client_fd, SHUT_RDWR);
		socket_close(el->client_fd);
		thread_join(el->th);
		thread_free(el->th);
		thread_list = el->next;
		free(el);
	}

leave_cleanup:
	if (device) {
		idevice_free(device);
	}

	return result;
}
