/*
 * idevicecrashreport.c
 * Simple utility to move crash reports from a device to a local directory.
 *
 * Copyright (c) 2014 Martin Szulecki. All Rights Reserved.
 * Copyright (c) 2014 Nikias Bassen. All Rights Reserved.
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

#define TOOL_NAME "idevicecrashreport"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <signal.h>
#endif
#include <libimobiledevice-glue/utils.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/service.h>
#include <libimobiledevice/afc.h>
#include <plist/plist.h>

#ifdef _WIN32
#include <windows.h>
#define S_IFLNK S_IFREG
#define S_IFSOCK S_IFREG
#endif

#define CRASH_REPORT_MOVER_SERVICE "com.apple.crashreportmover"
#define CRASH_REPORT_COPY_MOBILE_SERVICE "com.apple.crashreportcopymobile"

const char* target_directory = NULL;
static int extract_raw_crash_reports = 0;
static int keep_crash_reports = 0;
static int remove_all = 0;

static int file_exists(const char* path)
{
	struct stat tst;
#ifdef _WIN32
	return (stat(path, &tst) == 0);
#else
	return (lstat(path, &tst) == 0);
#endif
}

static int extract_raw_crash_report(const char* filename)
{
	int res = 0;
	plist_t report = NULL;
	char* raw = NULL;
	char* raw_filename = strdup(filename);

	/* create filename with '.crash' extension */
	char* p = strrchr(raw_filename, '.');
	if ((p == NULL) || (strcmp(p, ".plist") != 0)) {
		free(raw_filename);
		return res;
	}
	strcpy(p, ".crash");

	/* read plist crash report */
	if (plist_read_from_file(filename, &report, NULL)) {
		plist_t description_node = plist_dict_get_item(report, "description");
		if (description_node && plist_get_node_type(description_node) == PLIST_STRING) {
			plist_get_string_val(description_node, &raw);

			if (raw != NULL) {
				/* write file */
				buffer_write_to_filename(raw_filename, raw, strlen(raw));
				free(raw);
				res = 1;
			}
		}
	}

	if (report)
		plist_free(report);

	if (raw_filename)
		free(raw_filename);

	return res;
}

static int afc_client_copy_and_remove_crash_reports(afc_client_t afc, const char* device_directory, const char* host_directory, const char* filename_filter)
{
	afc_error_t afc_error;
	int k;
	int res = -1;
	int crash_report_count = 0;
	uint64_t handle;
	char source_filename[512];
	char target_filename[512];

	if (!afc)
		return res;

	char** list = NULL;
	afc_error = afc_read_directory(afc, device_directory, &list);
	if (afc_error != AFC_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not read device directory '%s'\n", device_directory);
		return res;
	}

	/* ensure we have a trailing slash */
	strcpy(source_filename, device_directory);
	if (source_filename[strlen(source_filename)-1] != '/') {
		strcat(source_filename, "/");
	}
	int device_directory_length = strlen(source_filename);

	/* ensure we have a trailing slash */
	strcpy(target_filename, host_directory);
	if (target_filename[strlen(target_filename)-1] != '/') {
		strcat(target_filename, "/");
	}
	int host_directory_length = strlen(target_filename);

	/* loop over file entries */
	for (k = 0; list[k]; k++) {
		if (!strcmp(list[k], ".") || !strcmp(list[k], "..")) {
			continue;
		}

		char **fileinfo = NULL;
		struct stat stbuf;
		memset(&stbuf, '\0', sizeof(struct stat));

		/* assemble absolute source filename */
		strcpy(((char*)source_filename) + device_directory_length, list[k]);

		/* assemble absolute target filename */
#ifdef _WIN32
		/* replace every ':' with '-' since ':' is an illegal character for file names in windows */
		char* current_pos = strchr(list[k], ':');
		while (current_pos) {
			*current_pos = '-';
			current_pos = strchr(current_pos, ':');
		}
#endif
		char* p = strrchr(list[k], '.');
		if (p != NULL && !strncmp(p, ".synced", 7)) {
			/* make sure to strip ".synced" extension as seen on iOS 5 */
			size_t newlen = p - list[k];
			strncpy(((char*)target_filename) + host_directory_length, list[k], newlen);
			target_filename[host_directory_length + newlen] = '\0';
		} else {
			strcpy(((char*)target_filename) + host_directory_length, list[k]);
		}

		/* get file information */
		afc_get_file_info(afc, source_filename, &fileinfo);
		if (!fileinfo) {
			printf("Failed to read information for '%s'. Skipping...\n", source_filename);
			continue;
		}

		/* parse file information */
		int i;
		for (i = 0; fileinfo[i]; i+=2) {
			if (!strcmp(fileinfo[i], "st_size")) {
				stbuf.st_size = atoll(fileinfo[i+1]);
			} else if (!strcmp(fileinfo[i], "st_ifmt")) {
				if (!strcmp(fileinfo[i+1], "S_IFREG")) {
					stbuf.st_mode = S_IFREG;
				} else if (!strcmp(fileinfo[i+1], "S_IFDIR")) {
					stbuf.st_mode = S_IFDIR;
				} else if (!strcmp(fileinfo[i+1], "S_IFLNK")) {
					stbuf.st_mode = S_IFLNK;
				} else if (!strcmp(fileinfo[i+1], "S_IFBLK")) {
					stbuf.st_mode = S_IFBLK;
				} else if (!strcmp(fileinfo[i+1], "S_IFCHR")) {
					stbuf.st_mode = S_IFCHR;
				} else if (!strcmp(fileinfo[i+1], "S_IFIFO")) {
					stbuf.st_mode = S_IFIFO;
				} else if (!strcmp(fileinfo[i+1], "S_IFSOCK")) {
					stbuf.st_mode = S_IFSOCK;
				}
			} else if (!strcmp(fileinfo[i], "st_nlink")) {
				stbuf.st_nlink = atoi(fileinfo[i+1]);
			} else if (!strcmp(fileinfo[i], "st_mtime")) {
				stbuf.st_mtime = (time_t)(atoll(fileinfo[i+1]) / 1000000000);
			} else if (!strcmp(fileinfo[i], "LinkTarget") && !remove_all) {
				/* report latest crash report filename */
				printf("Link: %s\n", (char*)target_filename + strlen(target_directory));

				/* remove any previous symlink */
				if (file_exists(target_filename)) {
					remove(target_filename);
				}

#ifndef _WIN32
				/* use relative filename */
				char* b = strrchr(fileinfo[i+1], '/');
				if (b == NULL) {
					b = fileinfo[i+1];
				} else {
					b++;
				}

				/* create a symlink pointing to latest log */
				if (symlink(b, target_filename) < 0) {
					fprintf(stderr, "Can't create symlink to %s\n", b);
				}
#endif

				if (!keep_crash_reports)
					afc_remove_path(afc, source_filename);

				res = 0;
			}
		}

		/* free file information */
		afc_dictionary_free(fileinfo);

		/* recurse into child directories */
		if (S_ISDIR(stbuf.st_mode)) {
			if (!remove_all) {
#ifdef _WIN32
				mkdir(target_filename);
#else
				mkdir(target_filename, 0755);
#endif
			}
			res = afc_client_copy_and_remove_crash_reports(afc, source_filename, target_filename, filename_filter);

			/* remove directory from device */
			if (!remove_all && !keep_crash_reports)
				afc_remove_path(afc, source_filename);
		} else if (S_ISREG(stbuf.st_mode)) {
			if (filename_filter != NULL && strstr(source_filename, filename_filter) == NULL) {
				continue;
			}

			if (remove_all) {
				printf("Remove: %s\n", source_filename);
				afc_remove_path(afc, source_filename);
				continue;
			}

			/* copy file to host */
			afc_error = afc_file_open(afc, source_filename, AFC_FOPEN_RDONLY, &handle);
			if(afc_error != AFC_E_SUCCESS) {
				if (afc_error == AFC_E_OBJECT_NOT_FOUND) {
					continue;
				}
				fprintf(stderr, "Unable to open device file '%s' (%d). Skipping...\n", source_filename, afc_error);
				continue;
			}

			FILE* output = fopen(target_filename, "wb");
			if(output == NULL) {
				fprintf(stderr, "Unable to open local file '%s'. Skipping...\n", target_filename);
				afc_file_close(afc, handle);
				continue;
			}

			printf("%s: %s\n", (keep_crash_reports ? "Copy": "Move") , (char*)target_filename + strlen(target_directory));

			uint32_t bytes_read = 0;
			uint32_t bytes_total = 0;
			unsigned char data[0x1000];

			afc_error = afc_file_read(afc, handle, (char*)data, 0x1000, &bytes_read);
			while(afc_error == AFC_E_SUCCESS && bytes_read > 0) {
				fwrite(data, 1, bytes_read, output);
				bytes_total += bytes_read;
				afc_error = afc_file_read(afc, handle, (char*)data, 0x1000, &bytes_read);
			}
			afc_file_close(afc, handle);
			fclose(output);

			if ((uint32_t)stbuf.st_size != bytes_total) {
				fprintf(stderr, "File size mismatch. Skipping...\n");
				continue;
			}

			/* remove file from device */
			if (!keep_crash_reports) {
				afc_remove_path(afc, source_filename);
			}

			/* extract raw crash information into separate '.crash' file */
			if (extract_raw_crash_reports) {
				extract_raw_crash_report(target_filename);
			}

			crash_report_count++;

			res = 0;
		}
	}
	afc_dictionary_free(list);

	/* no reports, no error */
	if (crash_report_count == 0)
		res = 0;

	return res;
}

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] DIRECTORY\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Move crash reports from device to a local DIRECTORY.\n"
		"\n"
		"OPTIONS:\n"
		"  -u, --udid UDID       target specific device by UDID\n"
		"  -n, --network         connect to network device\n"
		"  -e, --extract         extract raw crash report into separate '.crash' file\n"
		"  -k, --keep            copy but do not remove crash reports from device\n"
		"  -d, --debug           enable communication debugging\n"
		"  -f, --filter NAME     filter crash reports by NAME (case sensitive)\n"
		"  -h, --help            prints usage information\n"
		"  -v, --version         prints version information\n"
		"  --remove-all          remove all crash logs found\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

int main(int argc, char* argv[])
{
	idevice_t device = NULL;
	lockdownd_client_t lockdownd = NULL;
	afc_client_t afc = NULL;

	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdownd_error = LOCKDOWN_E_SUCCESS;
	afc_error_t afc_error = AFC_E_SUCCESS;

	const char* udid = NULL;
	int use_network = 0;
	const char* filename_filter = NULL;

	int c = 0;
	const struct option longopts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "udid", required_argument, NULL, 'u' },
		{ "network", no_argument, NULL, 'n' },
		{ "version", no_argument, NULL, 'v' },
		{ "filter", required_argument, NULL, 'f' },
		{ "extract", no_argument, NULL, 'e' },
		{ "keep", no_argument, NULL, 'k' },
		{ "remove-all", no_argument, NULL, 1 },
		{ NULL, 0, NULL, 0}
	};

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	/* parse cmdline args */
	while ((c = getopt_long(argc, argv, "dhu:nvf:ek", longopts, NULL)) != -1) {
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
		case 'f':
			if (!*optarg) {
				fprintf(stderr, "ERROR: filter argument must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			}
			filename_filter = optarg;
			break;
		case 'e':
			extract_raw_crash_reports = 1;
			break;
		case 'k':
			keep_crash_reports = 1;
			break;
		case 1:
			remove_all = 1;
			break;
		default:
			print_usage(argc, argv, 1);
			return 2;
		}
	}
	argc -= optind;
	argv += optind;

	/* ensure a target directory was supplied */
	if (!remove_all) {
		if (!argv[0]) {
			fprintf(stderr, "ERROR: missing target directory.\n");
			print_usage(argc+optind, argv-optind, 1);
			return 2;
		}
		target_directory = argv[0];
	} else {
		target_directory = ".";
	}

	/* check if target directory exists */
	if (!file_exists(target_directory)) {
		fprintf(stderr, "ERROR: Directory '%s' does not exist.\n", target_directory);
		return 1;
	}

	device_error = idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX);
	if (device_error != IDEVICE_E_SUCCESS) {
		if (udid) {
			printf("No device found with udid %s.\n", udid);
		} else {
			printf("No device found.\n");
		}
		return -1;
	}

	lockdownd_error = lockdownd_client_new_with_handshake(device, &lockdownd, TOOL_NAME);
	if (lockdownd_error != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd, error code %d\n", lockdownd_error);
		idevice_free(device);
		return -1;
	}

	/* start crash log mover service */
	lockdownd_service_descriptor_t service = NULL;
	lockdownd_error = lockdownd_start_service(lockdownd, CRASH_REPORT_MOVER_SERVICE, &service);
	if (lockdownd_error != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not start service %s: %s\n", CRASH_REPORT_MOVER_SERVICE, lockdownd_strerror(lockdownd_error));
		lockdownd_client_free(lockdownd);
		idevice_free(device);
		return -1;
	}

	/* trigger move operation on device */
	service_client_t svcmove = NULL;
	service_error_t service_error = service_client_new(device, service, &svcmove);
	lockdownd_service_descriptor_free(service);
	service = NULL;
	if (service_error != SERVICE_E_SUCCESS) {
		lockdownd_client_free(lockdownd);
		idevice_free(device);
		return -1;
	}

	/* read "ping" message which indicates the crash logs have been moved to a safe harbor */
	char *ping = malloc(4);
	memset(ping, '\0', 4);
	int attempts = 0;
	while ((strncmp(ping, "ping", 4) != 0) && (attempts < 10)) {
		uint32_t bytes = 0;
		service_error = service_receive_with_timeout(svcmove, ping, 4, &bytes, 2000);
		if (service_error == SERVICE_E_SUCCESS || service_error == SERVICE_E_TIMEOUT) {
			attempts++;
			continue;
		}

		fprintf(stderr, "ERROR: Crash logs could not be moved. Connection interrupted (%d).\n", service_error);
		break;
	}
	service_client_free(svcmove);
	free(ping);

	if (device_error != IDEVICE_E_SUCCESS || attempts > 10) {
		fprintf(stderr, "ERROR: Failed to receive ping message from crash report mover.\n");
		lockdownd_client_free(lockdownd);
		idevice_free(device);
		return -1;
	}

	lockdownd_error = lockdownd_start_service(lockdownd, CRASH_REPORT_COPY_MOBILE_SERVICE, &service);
	if (lockdownd_error != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not start service %s: %s\n", CRASH_REPORT_COPY_MOBILE_SERVICE, lockdownd_strerror(lockdownd_error));
		lockdownd_client_free(lockdownd);
		idevice_free(device);
		return -1;
	}
	lockdownd_client_free(lockdownd);

	afc = NULL;
	afc_error = afc_client_new(device, service, &afc);
	if(afc_error != AFC_E_SUCCESS) {
		lockdownd_client_free(lockdownd);
		idevice_free(device);
		return -1;
	}

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

	/* recursively copy crash reports from the device to a local directory */
	if (afc_client_copy_and_remove_crash_reports(afc, ".", target_directory, filename_filter) < 0) {
		fprintf(stderr, "ERROR: Failed to get crash reports from device.\n");
		afc_client_free(afc);
		idevice_free(device);
		return -1;
	}

	printf("Done.\n");

	afc_client_free(afc);
	idevice_free(device);

	return 0;
}
