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

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/mobile_image_mounter.h>
#include <asprintf.h>

static int indent_level = 0;

static int list_mode = 0;
static int xml_mode = 0;
static char *udid = NULL;
static char *imagetype = NULL;

static const char PKG_PATH[] = "PublicStaging";
static const char PATH_PREFIX[] = "/private/var/mobile/Media";

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

static void plist_node_to_string(plist_t node);

static void plist_array_to_string(plist_t node)
{
	/* iterate over items */
	int i, count;
	plist_t subnode = NULL;

	count = plist_array_get_size(node);

	for (i = 0; i < count; i++) {
		subnode = plist_array_get_item(node, i);
		printf("%*s", indent_level, "");
		printf("%d: ", i);
		plist_node_to_string(subnode);
	}
}

static void plist_dict_to_string(plist_t node)
{
	/* iterate over key/value pairs */
	plist_dict_iter it = NULL;

	char* key = NULL;
	plist_t subnode = NULL;
	plist_dict_new_iter(node, &it);
	plist_dict_next_item(node, it, &key, &subnode);
	while (subnode)
	{
		printf("%*s", indent_level, "");
		printf("%s", key);
		if (plist_get_node_type(subnode) == PLIST_ARRAY)
			printf("[%d]: ", plist_array_get_size(subnode));
		else
			printf(": ");
		free(key);
		key = NULL;
		plist_node_to_string(subnode);
		plist_dict_next_item(node, it, &key, &subnode);
	}
	free(it);
}

static void plist_node_to_string(plist_t node)
{
	char *s = NULL;
	char *data = NULL;
	double d;
	uint8_t b;
	uint64_t u = 0;
	struct timeval tv = { 0, 0 };

	plist_type t;

	if (!node)
		return;

	t = plist_get_node_type(node);

	switch (t) {
	case PLIST_BOOLEAN:
		plist_get_bool_val(node, &b);
		printf("%s\n", (b ? "true" : "false"));
		break;

	case PLIST_UINT:
		plist_get_uint_val(node, &u);
		printf("%llu\n", (long long)u);
		break;

	case PLIST_REAL:
		plist_get_real_val(node, &d);
		printf("%f\n", d);
		break;

	case PLIST_STRING:
		plist_get_string_val(node, &s);
		printf("%s\n", s);
		free(s);
		break;

	case PLIST_KEY:
		plist_get_key_val(node, &s);
		printf("%s: ", s);
		free(s);
		break;

	case PLIST_DATA:
		plist_get_data_val(node, &data, &u);
		uint64_t i;
		for (i = 0; i < u; i++) {
			printf("%02x", (unsigned char)data[i]);
		}
		free(data);
		printf("\n");
		break;

	case PLIST_DATE:
		plist_get_date_val(node, (int32_t*)&tv.tv_sec, (int32_t*)&tv.tv_usec);
		{
			time_t ti = (time_t)tv.tv_sec;
			struct tm *btime = localtime(&ti);
			if (btime) {
				s = (char*)malloc(24);
 				memset(s, 0, 24);
				if (strftime(s, 24, "%Y-%m-%dT%H:%M:%SZ", btime) <= 0) {
					free (s);
					s = NULL;
				}
			}
		}
		if (s) {
			puts(s);
			free(s);
		}
		puts("\n");
		break;

	case PLIST_ARRAY:
		printf("\n");
		indent_level++;
		plist_array_to_string(node);
		indent_level--;
		break;

	case PLIST_DICT:
		printf("\n");
		indent_level++;
		plist_dict_to_string(node);
		indent_level--;
		break;

	default:
		break;
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

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	lockdownd_client_t lckd = NULL;
	mobile_image_mounter_client_t mim = NULL;
	afc_client_t afc = NULL;
	lockdownd_service_descriptor_t service = NULL;
	int res = -1;
	char *image_path = NULL;
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
		if (stat(image_path, &fst) != 0) {
			fprintf(stderr, "ERROR: stat: %s: %s\n", image_path, strerror(errno));
			goto leave;
		}
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
				plist_dict_to_string(result);
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

		printf("Copying '%s' --> '%s'\n", image_path, targetname);

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
		fclose(f);

		printf("done.\n");

		printf("Mounting...\n");
		if (!imagetype) {
			imagetype = strdup("Developer");
		}
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
								plist_dict_to_string(result);
							}
						}
						free(status);
					} else {
						printf("unexpected result:\n");
						if (xml_mode) {
							print_xml(result);
						} else {
							plist_dict_to_string(result);
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
							plist_dict_to_string(result);
						}
					}

				} else {
					if (xml_mode) {
						print_xml(result);
					} else {
						plist_dict_to_string(result);
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
