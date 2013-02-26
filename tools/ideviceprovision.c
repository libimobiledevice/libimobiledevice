/*
 * ideviceprovision.c
 * Simple utility to install, get, or remove provisioning profiles
 *   to/from idevices
 *
 * Copyright (c) 2012 Nikias Bassen, All Rights Reserved.
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
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <windows.h>
#else
#include <arpa/inet.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/misagent.h>

static void print_usage(int argc, char **argv)
{
	char *name = NULL;
	
	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
	printf("Manage provisioning profiles on a device.\n\n");
	printf(" Where COMMAND is one of:\n");
	printf("  install FILE\tInstalls the provisioning profile specified by FILE.\n");
	printf("              \tA valid .mobileprovision file is expected.\n");
	printf("  list\t\tGet a list of all provisioning profiles on the device.\n");
	printf("  copy PATH\tRetrieves all provisioning profiles from the device and\n");
	printf("           \tstores them into the existing directory specified by PATH.\n");
	printf("           \tThe files will be stored as UUID.mobileprovision\n");
	printf("  remove UUID\tRemoves the provisioning profile identified by UUID.\n\n");
	printf(" The following OPTIONS are accepted:\n");
	printf("  -d, --debug      enable communication debugging\n");
	printf("  -u, --udid UDID  target specific device by its 40-digit device UDID\n");
	printf("  -h, --help       prints usage information\n");
	printf("\n");
}

enum {
	OP_INSTALL,
	OP_LIST,
	OP_COPY,
	OP_REMOVE,
	NUM_OPS
};

#define ASN1_SEQUENCE 0x30
#define ASN1_CONTAINER 0xA0
#define ASN1_OBJECT_IDENTIFIER 0x06
#define ASN1_OCTET_STRING 0x04

static void asn1_next_item(unsigned char** p)
{
	if (*(*p+1) & 0x80) {
		*p += 4;
	} else {
		*p += 3;
	}
}

static int asn1_item_get_size(unsigned char* p)
{
	int res = 0;
	if (*(p+1) & 0x80) {
		uint16_t ws = 0;
		memcpy(&ws, p+2, 2);
		ws = ntohs(ws);
		res = ws;
	} else {
		res = (int) *(p+1);
	}
	return res;
}

static void asn1_skip_item(unsigned char** p)
{
	int sz = asn1_item_get_size(*p);
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
	uint16_t slen = asn1_item_get_size(pp);
	if (slen+4 != (uint16_t)blen) {
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

int main(int argc, char *argv[])
{
	lockdownd_client_t client = NULL;
	lockdownd_service_descriptor_t service = NULL;
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	int i;
	int op = -1;
	const char* udid = NULL;
	const char* param = NULL;

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
				return 0;
			}
			udid = argv[i];
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
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
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

	ret = idevice_new(&device, udid);
	if (ret != IDEVICE_E_SUCCESS) {
		if (udid) {
			printf("No device found with udid %s, is it plugged in?\n", udid);
		} else {
			printf("No device found, is it plugged in?\n");
		}
		return -1;
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(device, &client, "ideviceprovision")) {
		idevice_free(device);
		return -1;
	}

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
			FILE* f = fopen(param, "rb");
			if (!f) {
				fprintf(stderr, "Could not open file '%s'\n", param);
				break;
			}
			fseek(f, 0, SEEK_END);
			long int size = ftell(f);
			fseek(f, 0, SEEK_SET);

			if (size >= 0x1000000) {
				fprintf(stderr, "The file '%s' is too large for processing.\n", param);
				fclose(f);
				break;
			}

			char* buf = malloc(size);
			if (!buf) {
				fprintf(stderr, "Could not allocate memory...\n");
				fclose(f);
				break;
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
				fprintf(stderr, "Could not read in file '%s' (size %ld read %ld)\n", param, size, cur);
				break;
			}

			uint64_t psize = size;
			plist_t pdata = plist_new_data(buf, psize);

			if (misagent_install(mis, pdata) == MISAGENT_E_SUCCESS) {
				printf("Profile '%s' installed successfully.\n", param);
			} else {
				int sc = misagent_get_status_code(mis);
				fprintf(stderr, "Could not install profile '%s', status code: 0x%x\n", param, sc);
			}
			free(buf);
		}
			break;
		case OP_LIST:
		case OP_COPY:
		{
			plist_t profiles = NULL;
			if (misagent_copy(mis, &profiles) == MISAGENT_E_SUCCESS) {
				uint32_t num_profiles = plist_array_get_size(profiles);
				printf("Device has %d provisioning %s installed:\n", num_profiles, (num_profiles == 1) ? "profile" : "profiles");
				uint32_t j;
				for (j = 0; j < num_profiles; j++) {
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
					printf("%s - %s\n", (p_uuid) ? p_uuid : "(unknown id)", (p_name) ? p_name : "(no name)");
					if (op == OP_COPY) {
						char pfname[512];
						if (p_uuid) {
							sprintf(pfname, "%s/%s.mobileprovision", param, p_uuid);
						} else {
							sprintf(pfname, "%s/profile%d.mobileprovision", param, j);
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
							fprintf(stderr, "Could not open '%s' for writing\n", pfname);
						}
					}
					if (p_uuid) {
						free(p_uuid);
					}
					if (p_name) {
						free(p_name);
					}
				}
			} else {
				int sc = misagent_get_status_code(mis);
				fprintf(stderr, "Could not get installed profiles from device, status code: 0x%x\n", sc);
			}
		}
			break;
		case OP_REMOVE:
			if (misagent_remove(mis, param) == MISAGENT_E_SUCCESS) {
				printf("Profile '%s' removed.\n", param);
			} else {
				int sc = misagent_get_status_code(mis);
				fprintf(stderr, "Could not remove profile '%s', status code 0x%x\n", param, sc);
			}
			break;
		default:
			break;
	}

	misagent_client_free(mis);

	idevice_free(device);

	return 0;
}

