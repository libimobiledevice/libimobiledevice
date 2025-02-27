/*
 * idevicedate.c
 * Simple utility to get and set the clock on a device
 *
 * Copyright (c) 2011 Martin Szulecki All Rights Reserved.
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

#define TOOL_NAME "idevicedate"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#if HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif
#ifndef _WIN32
#include <signal.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#ifdef _DATE_FMT
#define DATE_FMT_LANGINFO nl_langinfo (_DATE_FMT)
#else
#ifdef _WIN32
#define DATE_FMT_LANGINFO "%a %b %#d %H:%M:%S %Z %Y"
#else
#define DATE_FMT_LANGINFO "%a %b %e %H:%M:%S %Z %Y"
#endif
#endif

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS]\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Display the current date or set it on a device.\n"
		"\n"
		"NOTE: Setting the time on iOS 6 and later is only supported\n"
		"      in the setup wizard screens before device activation.\n"
		"\n"
		"OPTIONS:\n"
		"  -u, --udid UDID       target specific device by UDID\n"
		"  -n, --network         connect to network device\n"
		"  -s, --set TIMESTAMP   set UTC time described by TIMESTAMP\n"
		"  -c, --sync            set time of device to current system time\n"
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
	lockdownd_client_t client = NULL;
	lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	const char* udid = NULL;
	int use_network = 0;
	time_t setdate = 0;
	plist_t node = NULL;
	int node_type = -1;
	uint64_t datetime = 0;
	time_t rawtime;
	struct tm * tmp;
	char buffer[80];
	int result = 0;

	int c = 0;
	const struct option longopts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "udid", required_argument, NULL, 'u' },
		{ "network", no_argument, NULL, 'n' },
		{ "version", no_argument, NULL, 'v' },
		{ "set", required_argument, NULL, 's' },
		{ "sync", no_argument, NULL, 'c' },
		{ NULL, 0, NULL, 0}
	};

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	/* parse cmdline args */
	while ((c = getopt_long(argc, argv, "dhu:nvs:c", longopts, NULL)) != -1) {
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
		case 'h':
			print_usage(argc, argv, 0);
			return 0;
		case 'v':
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			return 0;
		case 's':
			if (!*optarg) {
				fprintf(stderr, "ERROR: set argument must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			}
			setdate = atoi(optarg);
			if (setdate == 0) {
				fprintf(stderr, "ERROR: Invalid timestamp value.\n");
				print_usage(argc, argv, 1);
				return 0;
			}
			break;
		case 'c':
			/* get current time */
			setdate = time(NULL);
			/* convert it to local time which sets timezone/daylight variables */
			tmp = localtime(&setdate);
			/* recalculate to make it UTC */
			setdate = mktime(tmp);
			break;
		default:
			print_usage(argc, argv, 1);
			return 2;
		}
	}
	argc -= optind;
	argv += optind;

	ret = idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX);
	if (ret != IDEVICE_E_SUCCESS) {
		if (udid) {
			printf("No device found with udid %s.\n", udid);
		} else {
			printf("No device found.\n");
		}
		return -1;
	}

	if (LOCKDOWN_E_SUCCESS != (ldret = lockdownd_client_new_with_handshake(device, &client, TOOL_NAME))) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd, error code %d\n", ldret);
		result = -1;
		goto cleanup;
	}

	if(lockdownd_get_value(client, NULL, "TimeIntervalSince1970", &node) != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "ERROR: Unable to retrieve 'TimeIntervalSince1970' node from device.\n");
		result = -1;
		goto cleanup;
	}

	if (node == NULL) {
		fprintf(stderr, "ERROR: Empty node for 'TimeIntervalSince1970' received.\n");
		result = -1;
		goto cleanup;
	}

	node_type = plist_get_node_type(node);

	/* get or set? */
	if (setdate == 0) {
		/* get time value from device */
		switch (node_type) {
			case PLIST_UINT:
				plist_get_uint_val(node, &datetime);
				break;
			case PLIST_REAL:
				{
					double rv = 0;
					plist_get_real_val(node, &rv);
					datetime = rv;
				}
				break;
			default:
				fprintf(stderr, "ERROR: Unexpected node type for 'TimeIntervalSince1970'\n");
				break;
		}
		plist_free(node);
		node = NULL;

		/* date/time calculations */
		rawtime = (time_t)datetime;
		tmp = localtime(&rawtime);

		/* finally we format and print the current date */
		strftime(buffer, 80, DATE_FMT_LANGINFO, tmp);
		puts(buffer);
	} else {
		datetime = setdate;

		plist_free(node);
		node = NULL;

		switch (node_type) {
			case PLIST_UINT:
				node = plist_new_uint(datetime);
				break;
			case PLIST_REAL:
				node = plist_new_real((double)datetime);
				break;
			default:
				fprintf(stderr, "ERROR: Unexpected node type for 'TimeIntervalSince1970'\n");
				break;
		}

		if(lockdownd_set_value(client, NULL, "TimeIntervalSince1970", node) == LOCKDOWN_E_SUCCESS) {
			tmp = localtime(&setdate);
			strftime(buffer, 80, DATE_FMT_LANGINFO, tmp);
			puts(buffer);
		} else {
			printf("ERROR: Failed to set date on device.\n");
		}
		node = NULL;
	}

cleanup:
	if (client)
		lockdownd_client_free(client);

	if (device)
		idevice_free(device);

	return result;
}
