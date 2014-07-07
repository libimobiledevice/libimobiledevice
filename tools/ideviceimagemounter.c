/*
 * ideviceimagemounter.c
 * Mount developer/debug disk images on the device
 *
 * Copyright (C) 2010 Nikias Bassen <nikias@gmx.li>
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

#include <stdlib.h>
#define _GNU_SOURCE 1
#define __USE_GNU 1
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/mobile_image_mounter.h>
#include <asprintf.h>
#include "common/utils.h"

static int list_mode = 0;
static int xml_mode = 0;
static char *udid = NULL;
static char *imagetype = NULL;

static const char PKG_PATH[] = "PublicStaging";
static const char PATH_PREFIX[] = "/private/var/mobile/Media";

typedef enum {
	DISK_IMAGE_UPLOAD_TYPE_AFC,
	DISK_IMAGE_UPLOAD_TYPE_UPLOAD_IMAGE
} disk_image_upload_type_t;

static void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] IMAGE_FILE IMAGE_SIGNATURE_FILE\n\n", (name ? name + 1: argv[0]));
	printf("Mounts the specified disk image on the device.\n\n");
	printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
	printf("  -l, --list\t\tList mount information\n");
	printf("  -t, --imagetype\tImage type to use, default is 'Developer'\n");
	printf("  -x, --xml\t\tUse XML output\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
}

static void parse_opts(int argc, char **argv)
{
	static struct option longopts[] = {
		{"help", 0, NULL, 'h'},
		{"udid", 0, NULL, 'u'},
		{"list", 0, NULL, 'l'},
		{"imagetype", 0, NULL, 't'},
		{"xml", 0, NULL, 'x'},
		{"debug", 0, NULL, 'd'},
		{NULL, 0, NULL, 0}
	};
	int c;

	while (1) {
		c = getopt_long(argc, argv, "hu:lt:xd", longopts,
						(int *) 0);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_usage(argc, argv);
			exit(0);
		case 'u':
			if (strlen(optarg) != 40) {
				printf("%s: invalid UDID specified (length != 40)\n",
					   argv[0]);
				print_usage(argc, argv);
				exit(2);
			}
			udid = strdup(optarg);
			break;
		case 'l':
			list_mode = 1;
			break;
		case 't':
			imagetype = strdup(optarg);
			break;
		case 'x':
			xml_mode = 1;
			break;
		case 'd':
			idevice_set_debug_level(1);
			break;
		default:
			print_usage(argc, argv);
			exit(2);
		}
	}
}

static void print_xml(plist_t node)
{
	char *xml = NULL;
	uint32_t len = 0;
	plist_to_xml(node, &xml, &len);
	if (xml)
		puts(xml);
}

static ssize_t mim_upload_cb(void* buf, size_t size, void* userdata)
{
	return fread(buf, 1, size, (FILE*)userdata);
}

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	lockdownd_client_t lckd = NULL;
	mobile_image_mounter_client_t mim = NULL;
	afc_client_t afc = NULL;
	lockdownd_service_descriptor_t service = NULL;
	int res = -1;
	char *image_path = NULL;
	size_t image_size = 0;
	char *image_sig_path = NULL;

	parse_opts(argc, argv);

	argc -= optind;
	argv += optind;

	if (!list_mode) {
		if (argc < 1) {
			printf("ERROR: No IMAGE_FILE has been given!\n");
			return -1;
		}
		image_path = strdup(argv[0]);
		if (argc >= 2) {
			image_sig_path = strdup(argv[1]);
		} else {
			if (asprintf(&image_sig_path, "%s.signature", image_path) < 0) {
				printf("Out of memory?!\n");
				return -1;
			}
		}
	}

	if (IDEVICE_E_SUCCESS != idevice_new(&device, udid)) {
		printf("No device found, is it plugged in?\n");
		return -1;
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(device, &lckd, "ideviceimagemounter")) {
		printf("ERROR: could not connect to lockdown. Exiting.\n");
		goto leave;
	}

	plist_t pver = NULL;
	char *product_version = NULL;
	lockdownd_get_value(lckd, NULL, "ProductVersion", &pver);
	if (pver && plist_get_node_type(pver) == PLIST_STRING) {
		plist_get_string_val(pver, &product_version);
	}
	disk_image_upload_type_t disk_image_upload_type = DISK_IMAGE_UPLOAD_TYPE_AFC;
	int product_version_major = 0;
	int product_version_minor = 0;
	if (product_version) {
		if (sscanf(product_version, "%d.%d.%*d", &product_version_major, &product_version_minor) == 2) {
			if (product_version_major >= 7)
				disk_image_upload_type = DISK_IMAGE_UPLOAD_TYPE_UPLOAD_IMAGE;
		}
	}

	lockdownd_start_service(lckd, "com.apple.mobile.mobile_image_mounter", &service);

	if (!service || service->port == 0) {
		printf("ERROR: Could not start mobile_image_mounter service!\n");
		goto leave;
	}

	if (mobile_image_mounter_new(device, service, &mim) != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		printf("ERROR: Could not connect to mobile_image_mounter!\n");
		goto leave;
	}	

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

	if (!list_mode) {
		struct stat fst;
		if (disk_image_upload_type == DISK_IMAGE_UPLOAD_TYPE_AFC) {
			if ((lockdownd_start_service(lckd, "com.apple.afc", &service) !=
				 LOCKDOWN_E_SUCCESS) || !service || !service->port) {
				fprintf(stderr, "Could not start com.apple.afc!\n");
				goto leave;
			}
			if (afc_client_new(device, service, &afc) != AFC_E_SUCCESS) {
				fprintf(stderr, "Could not connect to AFC!\n");
				goto leave;
			}
			if (service) {
				lockdownd_service_descriptor_free(service);
				service = NULL;
			}
		}
		if (stat(image_path, &fst) != 0) {
			fprintf(stderr, "ERROR: stat: %s: %s\n", image_path, strerror(errno));
			goto leave;
		}
		image_size = fst.st_size;
		if (stat(image_sig_path, &fst) != 0) {
			fprintf(stderr, "ERROR: stat: %s: %s\n", image_sig_path, strerror(errno));
			goto leave;
		}
	}

	lockdownd_client_free(lckd);
	lckd = NULL;

	mobile_image_mounter_error_t err;
	plist_t result = NULL;

	if (list_mode) {
		/* list mounts mode */
		if (!imagetype) {
			imagetype = strdup("Developer");
		}
		err = mobile_image_mounter_lookup_image(mim, imagetype, &result);
		free(imagetype);
		if (err == MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
			res = 0;
			if (xml_mode) {
				print_xml(result);
			} else {
				plist_print_to_stream(result, stdout);
			}
		} else {
			printf("Error: lookup_image returned %d\n", err);
		}
	} else {
		char sig[8192];
		size_t sig_length = 0;
		FILE *f = fopen(image_sig_path, "rb");
		if (!f) {
			fprintf(stderr, "Error opening signature file '%s': %s\n", image_sig_path, strerror(errno));
			goto leave;
		}
		sig_length = fread(sig, 1, sizeof(sig), f);
		fclose(f);
		if (sig_length == 0) {
			fprintf(stderr, "Could not read signature from file '%s'\n", image_sig_path);
			goto leave;
		}

		f = fopen(image_path, "rb");
		if (!f) {
			fprintf(stderr, "Error opening image file '%s': %s\n", image_path, strerror(errno));
			goto leave;
		}

		char *targetname = NULL;
		if (asprintf(&targetname, "%s/%s", PKG_PATH, "staging.dimage") < 0) {
			fprintf(stderr, "Out of memory!?\n");
			goto leave;
		}
		char *mountname = NULL;
		if (asprintf(&mountname, "%s/%s", PATH_PREFIX, targetname) < 0) {
			fprintf(stderr, "Out of memory!?\n");
			goto leave;
		}


		if (!imagetype) {
			imagetype = strdup("Developer");
		}

		switch(disk_image_upload_type) {
			case DISK_IMAGE_UPLOAD_TYPE_UPLOAD_IMAGE:
				printf("Uploading %s\n", image_path);
				err = mobile_image_mounter_upload_image(mim, imagetype, image_size, sig, sig_length, mim_upload_cb, f);
				break;
			case DISK_IMAGE_UPLOAD_TYPE_AFC:
			default:
				printf("Uploading %s --> afc:///%s\n", image_path, targetname);
				char **strs = NULL;
				if (afc_get_file_info(afc, PKG_PATH, &strs) != AFC_E_SUCCESS) {
					if (afc_make_directory(afc, PKG_PATH) != AFC_E_SUCCESS) {
						fprintf(stderr, "WARNING: Could not create directory '%s' on device!\n", PKG_PATH);
					}
				}
				if (strs) {
					int i = 0;
					while (strs[i]) {
						free(strs[i]);
						i++;
					}
					free(strs);
				}

				uint64_t af = 0;
				if ((afc_file_open(afc, targetname, AFC_FOPEN_WRONLY, &af) !=
					 AFC_E_SUCCESS) || !af) {
					fclose(f);
					fprintf(stderr, "afc_file_open on '%s' failed!\n", targetname);
					goto leave;
				}

				char buf[8192];
				size_t amount = 0;
				do {
					amount = fread(buf, 1, sizeof(buf), f);
					if (amount > 0) {
						uint32_t written, total = 0;
						while (total < amount) {
							written = 0;
							if (afc_file_write(afc, af, buf, amount, &written) !=
								AFC_E_SUCCESS) {
								fprintf(stderr, "AFC Write error!\n");
								break;
							}
							total += written;
						}
						if (total != amount) {
							fprintf(stderr, "Error: wrote only %d of %d\n", total,
									(unsigned int)amount);
							afc_file_close(afc, af);
							fclose(f);
							goto leave;
						}
					}
				}
				while (amount > 0);

				afc_file_close(afc, af);
				break;
		}

		fclose(f);

		printf("done.\n");

		printf("Mounting...\n");
		err = mobile_image_mounter_mount_image(mim, mountname, sig, sig_length, imagetype, &result);
		free(imagetype);
		if (err == MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
			if (result) {
				plist_t node = plist_dict_get_item(result, "Status");
				if (node) {
					char *status = NULL;
					plist_get_string_val(node, &status);
					if (status) {
						if (!strcmp(status, "Complete")) {
							printf("Done.\n");
							res = 0;
						} else {
							printf("unexpected status value:\n");
							if (xml_mode) {
								print_xml(result);
							} else {
								plist_print_to_stream(result, stdout);
							}
						}
						free(status);
					} else {
						printf("unexpected result:\n");
						if (xml_mode) {
							print_xml(result);
						} else {
							plist_print_to_stream(result, stdout);
						}
					}
				}
				node = plist_dict_get_item(result, "Error");
				if (node) {
					char *error = NULL;
					plist_get_string_val(node, &error);
					if (error) {
						printf("Error: %s\n", error);
						free(error);
					} else {
						printf("unexpected result:\n");
						if (xml_mode) {
							print_xml(result);
						} else {
							plist_print_to_stream(result, stdout);
						}
					}

				} else {
					if (xml_mode) {
						print_xml(result);
					} else {
						plist_print_to_stream(result, stdout);
					}
				}
			}
		} else {
			printf("Error: mount_image returned %d\n", err);

		}
	}

	if (result) {
		plist_free(result);
	}

	/* perform hangup command */
	mobile_image_mounter_hangup(mim);
	/* free client */
	mobile_image_mounter_free(mim);

leave:
	if (afc) {
		afc_client_free(afc);
	}
	if (lckd) {
		lockdownd_client_free(lckd);
	}
	idevice_free(device);

	if (image_path)
			free(image_path);
	if (image_sig_path)
		free(image_sig_path);

	return res;
}
