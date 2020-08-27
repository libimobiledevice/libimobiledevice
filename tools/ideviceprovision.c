/*
 * ideviceprovision.c
 * Simple utility to install, get, or remove provisioning profiles
 *   to/from idevices
 *
 * Copyright (c) 2012-2016 Nikias Bassen, All Rights Reserved.
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

#define TOOL_NAME "ideviceprovision"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#ifndef WIN32
#include <signal.h>
#endif

#ifdef WIN32
#include <windows.h>
#else
#include <arpa/inet.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/misagent.h>
#include "common/utils.h"

static void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
	printf("\n");
	printf("Manage provisioning profiles on a device.\n");
	printf("\n");
	printf("Where COMMAND is one of:\n");
	printf("  install FILE\tInstalls the provisioning profile specified by FILE.\n");
	printf("              \tA valid .mobileprovision file is expected.\n");
	printf("  list\t\tGet a list of all provisioning profiles on the device.\n");
	printf("  copy PATH\tRetrieves all provisioning profiles from the device and\n");
	printf("           \tstores them into the existing directory specified by PATH.\n");
	printf("           \tThe files will be stored as UUID.mobileprovision\n");
	printf("  copy UUID PATH  Retrieves the provisioning profile identified by UUID\n");
	printf("           \tfrom the device and stores it into the existing directory\n");
	printf("           \tspecified by PATH. The file will be stored as UUID.mobileprovision.\n");
	printf("  remove UUID\tRemoves the provisioning profile identified by UUID.\n");
	printf("  remove-all\tRemoves all installed provisioning profiles.\n");
	printf("  dump FILE\tPrints detailed information about the provisioning profile\n");
	printf("           \tspecified by FILE.\n");
	printf("\n");
	printf("The following OPTIONS are accepted:\n");
	printf("  -u, --udid UDID  target specific device by UDID\n");
	printf("  -n, --network    connect to network device\n");
	printf("  -x, --xml        print XML output when using the 'dump' command\n");
	printf("  -d, --debug      enable communication debugging\n");
	printf("  -h, --help       prints usage information\n");
	printf("  -v, --version    prints version information\n");
	printf("\n");
	printf("Homepage:    <" PACKAGE_URL ">\n");
	printf("Bug Reports: <" PACKAGE_BUGREPORT ">\n");
}

enum {
	OP_INSTALL,
	OP_LIST,
	OP_COPY,
	OP_REMOVE,
	OP_DUMP,
	NUM_OPS
};

#define ASN1_SEQUENCE 0x30
#define ASN1_CONTAINER 0xA0
#define ASN1_OBJECT_IDENTIFIER 0x06
#define ASN1_OCTET_STRING 0x04

static void asn1_next_item(unsigned char** p)
{
	char bsize = *(*p+1);
	if (bsize & 0x80) {
		*p += 2 + (bsize & 0xF);
	} else {
		*p += 3;
	}
}

static size_t asn1_item_get_size(unsigned char* p)
{
	size_t res = 0;
	char bsize = *(p+1);
	if (bsize & 0x80) {
		uint16_t ws = 0;
		uint32_t ds = 0;
		switch (bsize & 0xF) {
		case 2:
			ws = *(uint16_t*)(p+2);
			res = ntohs(ws);
			break;
		case 3:
			ds = *(uint32_t*)(p+2);
			res = ntohl(ds) >> 8;
			break;
		case 4:
			ds = *(uint32_t*)(p+2);
			res = ntohl(ds);
			break;
		default:
			fprintf(stderr, "ERROR: Invalid or unimplemented byte size %d\n", bsize & 0xF);
			break;
		}
	} else {
		res = (int)bsize;
	}
	return res;
}

static void asn1_skip_item(unsigned char** p)
{
	size_t sz = asn1_item_get_size(*p);
	*p += 2;
	*p += sz;
}

static plist_t profile_get_embedded_plist(plist_t profile)
{
	if (plist_get_node_type(profile) != PLIST_DATA) {
		fprintf(stderr, "%s: unexpected plist node type for profile (PLIST_DATA expected)\n", __func__);
		return NULL;
	}
	char* bbuf = NULL;
	uint64_t blen = 0;
	plist_get_data_val(profile, &bbuf, &blen);
	if (!bbuf) {
		fprintf(stderr, "%s: could not get data value from plist node\n", __func__);
		return NULL;
	}

	unsigned char* pp = (unsigned char*)bbuf;

	if (*pp != ASN1_SEQUENCE) {
		free(bbuf);
		fprintf(stderr, "%s: unexpected profile data (0)\n", __func__);
		return NULL;
	}
	size_t slen = asn1_item_get_size(pp);
	char bsize = *(pp+1);
	if (bsize & 0x80) {
		slen += 2 + (bsize & 0xF);
	} else {
		slen += 3;
	}
	if (slen != blen) {
		free(bbuf);
		fprintf(stderr, "%s: unexpected profile data (1)\n", __func__);
		return NULL;
	}
	asn1_next_item(&pp);

	if (*pp != ASN1_OBJECT_IDENTIFIER) {
		free(bbuf);
		fprintf(stderr, "%s: unexpected profile data (2)\n", __func__);
		return NULL;
	}
	asn1_skip_item(&pp);

	if (*pp != ASN1_CONTAINER) {
		free(bbuf);
		fprintf(stderr, "%s: unexpected profile data (3)\n", __func__);
		return NULL;
	}
	asn1_next_item(&pp);

	if (*pp != ASN1_SEQUENCE) {
		free(bbuf);
		fprintf(stderr, "%s: unexpected profile data (4)\n", __func__);
		return NULL;
	}
	asn1_next_item(&pp);

	int k = 0;
	// go to the 3rd element (skip 2)
	while (k < 2) {
		asn1_skip_item(&pp);
		k++;
	}
	if (*pp != ASN1_SEQUENCE) {
		free(bbuf);
		fprintf(stderr, "%s: unexpected profile data (5)\n", __func__);
		return NULL;
	}
	asn1_next_item(&pp);

	if (*pp != ASN1_OBJECT_IDENTIFIER) {
		free(bbuf);
		fprintf(stderr, "%s: unexpected profile data (6)\n", __func__);
		return NULL;
	}
	asn1_skip_item(&pp);

	if (*pp != ASN1_CONTAINER) {
		free(bbuf);
		fprintf(stderr, "%s: unexpected profile data (7)\n", __func__);
		return NULL;
	}
	asn1_next_item(&pp);

	if (*pp != ASN1_OCTET_STRING) {
		free(bbuf);
		fprintf(stderr, "%s: unexpected profile data (8)\n", __func__);
		return NULL;
	}
	slen = asn1_item_get_size(pp);
	asn1_next_item(&pp);

	plist_t pl = NULL;
	plist_from_xml((char*)pp, slen, &pl);
	free(bbuf);

	return pl;
}

static int profile_read_from_file(const char* path, unsigned char **profile_data, unsigned int *profile_size)
{
	FILE* f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "Could not open file '%s'\n", path);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	long int size = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (size >= 0x1000000) {
		fprintf(stderr, "The file '%s' is too large for processing.\n", path);
		fclose(f);
		return -1;
	}

	unsigned char* buf = malloc(size);
	if (!buf) {
		fprintf(stderr, "Could not allocate memory...\n");
		fclose(f);
		return -1;
	}

	long int cur = 0;
	while (cur < size) {
		ssize_t r = fread(buf+cur, 1, 512, f);
		if (r <= 0) {
			break;
		}
		cur += r;
	}
	fclose(f);

	if (cur != size) {
		free(buf);
		fprintf(stderr, "Could not read in file '%s' (size %ld read %ld)\n", path, size, cur);
		return -1;
	}

	*profile_data = buf;
	*profile_size = (unsigned int)size;

	return 0;
}

int main(int argc, char *argv[])
{
	lockdownd_client_t client = NULL;
	lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
	lockdownd_service_descriptor_t service = NULL;
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	int res = 0;
	int i;
	int op = -1;
	int output_xml = 0;
	const char* udid = NULL;
	const char* param = NULL;
	const char* param2 = NULL;
	int use_network = 0;

#ifndef WIN32
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
		else if (!strcmp(argv[i], "install")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) < 1)) {
				print_usage(argc, argv);
				return 0;
			}
			param = argv[i];
			op = OP_INSTALL;
			continue;
		}
		else if (!strcmp(argv[i], "list")) {
			op = OP_LIST;
		}
		else if (!strcmp(argv[i], "copy")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) < 1)) {
				print_usage(argc, argv);
				return 0;
			}
			param = argv[i];
			op = OP_COPY;
			i++;
			if (argv[i] && (strlen(argv[i]) > 0)) {
				param2 = argv[i];
			}
			continue;
		}
		else if (!strcmp(argv[i], "remove")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) < 1)) {
				print_usage(argc, argv);
				return 0;
			}
			param = argv[i];
			op = OP_REMOVE;
			continue;
		}
		else if (!strcmp(argv[i], "remove-all")) {
			i++;
			op = OP_REMOVE;
			continue;
		}
		else if (!strcmp(argv[i], "dump")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) < 1)) {
				print_usage(argc, argv);
				return 0;
			}
			param = argv[i];
			op = OP_DUMP;
			continue;
		}
		else if (!strcmp(argv[i], "-x") || !strcmp(argv[i], "--xml")) {
			output_xml = 1;
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
		else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			return 0;
		}
		else {
			print_usage(argc, argv);
			return 0;
		}
	}

	if ((op == -1) || (op >= NUM_OPS)) {
		print_usage(argc, argv);
		return 0;
	}

	if (op == OP_DUMP) {
		unsigned char* profile_data = NULL;
		unsigned int profile_size = 0;
		if (profile_read_from_file(param, &profile_data, &profile_size) != 0) {
			return -1;
		}
		plist_t pdata = plist_new_data((char*)profile_data, profile_size);
		plist_t pl = profile_get_embedded_plist(pdata);
		plist_free(pdata);
		free(profile_data);

		if (pl) {
			if (output_xml) {
				char* xml = NULL;
				uint32_t xlen = 0;
				plist_to_xml(pl, &xml, &xlen);
				if (xml) {
					printf("%s\n", xml);
					free(xml);
				}
			} else {
				if (pl && (plist_get_node_type(pl) == PLIST_DICT)) {
					plist_print_to_stream(pl, stdout);
				} else {
					fprintf(stderr, "ERROR: unexpected node type in profile plist (not PLIST_DICT)\n");
					res = -1;
				}
			}
		} else {
			fprintf(stderr, "ERROR: could not extract embedded plist from profile!\n");
		}
		plist_free(pl);

		return res;
	} else if (op == OP_COPY) {
		struct stat st;
		const char *checkdir = (param2) ? param2 : param;
		if ((stat(checkdir, &st) < 0) || !S_ISDIR(st.st_mode)) {
			fprintf(stderr, "ERROR: %s does not exist or is not a directory!\n", checkdir);
			return -1;
		}
	}

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
		idevice_free(device);
		return -1;
	}

	plist_t pver = NULL;
	char *pver_s = NULL;
	lockdownd_get_value(client, NULL, "ProductVersion", &pver);
	if (pver && plist_get_node_type(pver) == PLIST_STRING) {
		plist_get_string_val(pver, &pver_s);
	}
	plist_free(pver);
	int product_version_major = 0;
	int product_version_minor = 0;
	int product_version_patch = 0;
	if (pver_s) {
		sscanf(pver_s, "%d.%d.%d", &product_version_major, &product_version_minor, &product_version_patch);
		free(pver_s);
	}
	if (product_version_major == 0) {
		fprintf(stderr, "ERROR: Could not determine the device's ProductVersion\n");
		lockdownd_client_free(client);
		idevice_free(device);
		return -1;
	}
	int product_version = ((product_version_major & 0xFF) << 16) | ((product_version_minor & 0xFF) << 8) | (product_version_patch & 0xFF);

	if (LOCKDOWN_E_SUCCESS != lockdownd_start_service(client, "com.apple.misagent", &service)) {
		fprintf(stderr, "Could not start service \"com.apple.misagent\"\n");
		lockdownd_client_free(client);
		idevice_free(device);
		return -1;
	}
	lockdownd_client_free(client);
	client = NULL;

	misagent_client_t mis = NULL;
	if (misagent_client_new(device, service, &mis) != MISAGENT_E_SUCCESS) {
		fprintf(stderr, "Could not connect to \"com.apple.misagent\" on device\n");
		if (service)
			lockdownd_service_descriptor_free(service);
		lockdownd_client_free(client);
		idevice_free(device);
		return -1;
	}

	if (service)
		lockdownd_service_descriptor_free(service);

	switch (op) {
		case OP_INSTALL:
		{
			unsigned char* profile_data = NULL;
			unsigned int profile_size = 0;
			if (profile_read_from_file(param, &profile_data, &profile_size) != 0) {
				break;
			}

			uint64_t psize = profile_size;
			plist_t pdata = plist_new_data((const char*)profile_data, psize);
			free(profile_data);

			if (misagent_install(mis, pdata) == MISAGENT_E_SUCCESS) {
				printf("Profile '%s' installed successfully.\n", param);
			} else {
				int sc = misagent_get_status_code(mis);
				fprintf(stderr, "Could not install profile '%s', status code: 0x%x\n", param, sc);
			}
		}
			break;
		case OP_LIST:
		case OP_COPY:
		{
			plist_t profiles = NULL;
			misagent_error_t merr;
			if (product_version < 0x090300) {
				merr = misagent_copy(mis, &profiles);
			} else {
				merr = misagent_copy_all(mis, &profiles);
			}
			if (merr == MISAGENT_E_SUCCESS) {
				int found_match = 0;
				uint32_t num_profiles = plist_array_get_size(profiles);
				if (op == OP_LIST || !param2) {
					printf("Device has %d provisioning %s installed:\n", num_profiles, (num_profiles == 1) ? "profile" : "profiles");
				}
				uint32_t j;
				for (j = 0; !found_match && j < num_profiles; j++) {
					char* p_name = NULL;
					char* p_uuid = NULL;
					plist_t profile = plist_array_get_item(profiles, j);
					plist_t pl = profile_get_embedded_plist(profile);
					if (pl && (plist_get_node_type(pl) == PLIST_DICT)) {
						plist_t node;
						node = plist_dict_get_item(pl, "Name");
						if (node && (plist_get_node_type(node) == PLIST_STRING)) {
							plist_get_string_val(node, &p_name);
						}
						node = plist_dict_get_item(pl, "UUID");
						if (node && (plist_get_node_type(node) == PLIST_STRING)) {
							plist_get_string_val(node, &p_uuid);
						}
					}
					if (param2) {
						if (p_uuid && !strcmp(p_uuid, param)) {
							found_match = 1;
						} else {
							free(p_uuid);
							free(p_name);
							continue;
						}
					}
					printf("%s - %s\n", (p_uuid) ? p_uuid : "(unknown id)", (p_name) ? p_name : "(no name)");
					if (op == OP_COPY) {
						char pfname[512];
						if (p_uuid) {
							sprintf(pfname, "%s/%s.mobileprovision", (param2) ? param2 : param, p_uuid);
						} else {
							sprintf(pfname, "%s/profile%d.mobileprovision", (param2) ? param2 : param, j);
						}
						FILE* f = fopen(pfname, "wb");
						if (f) {
							char* dt = NULL;
							uint64_t ds = 0;
							plist_get_data_val(profile, &dt, &ds);
							fwrite(dt, 1, ds, f);
							fclose(f);
							printf(" => %s\n", pfname);
						} else {
							fprintf(stderr, "Could not open '%s' for writing: %s\n", pfname, strerror(errno));
						}
					}
					free(p_uuid);
					free(p_name);
				}
				if (param2 && !found_match) {
					fprintf(stderr, "Profile '%s' was not found on the device.\n", param);
					res = -1;
				}
			} else {
				int sc = misagent_get_status_code(mis);
				fprintf(stderr, "Could not get installed profiles from device, status code: 0x%x\n", sc);
				res = -1;
			}
			plist_free(profiles);
		}
			break;
		case OP_REMOVE:
			if (param) {
				/* remove specified provisioning profile */
				if (misagent_remove(mis, param) == MISAGENT_E_SUCCESS) {
					printf("Profile '%s' removed.\n", param);
				} else {
					int sc = misagent_get_status_code(mis);
					fprintf(stderr, "Could not remove profile '%s', status code 0x%x\n", param, sc);
				}
			} else {
				/* remove all provisioning profiles */
				plist_t profiles = NULL;
				misagent_error_t merr;
				if (product_version < 0x090300) {
					merr = misagent_copy(mis, &profiles);
				} else {
					merr = misagent_copy_all(mis, &profiles);
				}
				if (merr == MISAGENT_E_SUCCESS) {
					uint32_t j;
					uint32_t num_removed = 0;
					for (j = 0; j < plist_array_get_size(profiles); j++) {
						char* p_name = NULL;
						char* p_uuid = NULL;
						plist_t profile = plist_array_get_item(profiles, j);
						plist_t pl = profile_get_embedded_plist(profile);
						if (pl && (plist_get_node_type(pl) == PLIST_DICT)) {
							plist_t node;
							node = plist_dict_get_item(pl, "Name");
							if (node && (plist_get_node_type(node) == PLIST_STRING)) {
								plist_get_string_val(node, &p_name);
							}
							node = plist_dict_get_item(pl, "UUID");
							if (node && (plist_get_node_type(node) == PLIST_STRING)) {
								plist_get_string_val(node, &p_uuid);
							}
						}
						if (p_uuid) {
							if (misagent_remove(mis, p_uuid) == MISAGENT_E_SUCCESS) {
								printf("OK profile removed: %s - %s\n", p_uuid, (p_name) ? p_name : "(no name)");
								num_removed++;
							} else {
								int sc = misagent_get_status_code(mis);
								printf("FAIL profile not removed: %s - %s (status code 0x%x)\n", p_uuid, (p_name) ? p_name : "(no name)", sc);
							}
						}
						free(p_name);
						free(p_uuid);
					}
					printf("%d profiles removed.\n", num_removed);
				} else {
					int sc = misagent_get_status_code(mis);
					fprintf(stderr, "Could not get installed profiles from device, status code: 0x%x\n", sc);
					res = -1;
				}
				plist_free(profiles);
			}
			break;
		default:
			break;
	}

	misagent_client_free(mis);

	idevice_free(device);

	return res;
}

