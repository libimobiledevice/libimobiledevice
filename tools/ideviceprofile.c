/*
 * ideviceprofile.c
 * Simple utility to install, get, or remove provisioning profiles
 *   to/from idevices
 *
 * Copyright (c) 2020 Ethan Carlson, All Rights Reserved.
 * Uses base code from ideviceprovision.c Copyright Nikias Bassen
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

#define TOOL_NAME "ideviceprofile"

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
#include <libimobiledevice/mcinstall.h>
#include "common/utils.h"

static void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
	printf("\n");
	printf("Manage configuration profiles on a device.\n");
	printf("\n");
	printf("Where COMMAND is one of:\n");
	printf("  install FILE\t\tInstalls the mobileconfig profile specified by FILE.\n");
	printf("              \t\t\tA valid .mobileconfig file is expected.\n");
	printf("  list\t\t\tGet a list of all mobileconfig profiles on the device.\n");
    printf("  remove ID\t\tRemove configuration profile specified by ID.\n");
    printf("           \t\t\tWhere ID is the profile ID of the profile to be removed\n");
    printf("           \t\t\t(Use list option to get the ID of the profile.)\n");
	printf("  installDEP FILE\tInstalls DEP Configuration specified by FILE.\n");
	printf("           \t\t\tA valid .plist file is expected.\n");
	printf("  dumpDEP\t\tPrints the DEP Configuration present on the device.\n");
    printf("  download\t\tDownloads DEP Enrollment profile to device.\n");
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
    OP_REMOVE,
    OP_SET_CLOUD_CONFIG,
    OP_GET_CLOUD_CONFIG,
    OP_DOWNLOAD,
	NUM_OPS
};



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
        else if (!strcmp(argv[i], "download")) {
			op = OP_DOWNLOAD;
		}
        else if (!strcmp(argv[i], "remove")) {
            i++;
			if (!argv[i] || (strlen(argv[i]) < 1)) {
				print_usage(argc, argv);
				return 0;
			}
			param = argv[i];
			op = OP_REMOVE;
		}
        else if (!strcmp(argv[i], "installDEP")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) < 1)) {
				print_usage(argc, argv);
				return 0;
			}
			param = argv[i];
			op = OP_SET_CLOUD_CONFIG;
			continue;
		}
        else if (!strcmp(argv[i], "dumpDEP")) {
			op = OP_GET_CLOUD_CONFIG;
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
    
	mcinstall_client_t mis = NULL;
	if (LOCKDOWN_E_SUCCESS != lockdownd_start_service(client, "com.apple.mobile.MCInstall", &service)) {
            fprintf(stderr, "Could not start service \"com.apple.mobile.MCInstall\"\n");
            lockdownd_client_free(client);
            idevice_free(device);
            return -1;
    }

    lockdownd_client_free(client);
    client = NULL;


    if (mcinstall_client_new(device, service, &mis) != MCINSTALL_E_SUCCESS) {
            fprintf(stderr, "Could not connect to \"com.apple.mobile.MCInstall\" on device\n");
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

				if (mcinstall_install(mis, pdata) == MCINSTALL_E_SUCCESS) {
						printf("Profile '%s' installed successfully.\n", param);
				} else {
						int sc = mcinstall_get_status_code(mis);
						fprintf(stderr, "Could not install profile '%s', status code: 0x%x\n", param, sc);
				}
                plist_free(pdata);
		}
				break;
        case OP_SET_CLOUD_CONFIG:
		{
				unsigned char* profile_data = NULL;
				unsigned int profile_size = 0;
				if (profile_read_from_file(param, &profile_data, &profile_size) != 0) {
						break;
				}

				uint64_t psize = profile_size;
                plist_t pdata;
				
                plist_from_memory((const char*)profile_data, psize, &pdata);
				free(profile_data);
                if (pdata && (plist_get_node_type(pdata) == PLIST_DICT)) {
                    if (mcinstall_install_cloud_config(mis, pdata) == MCINSTALL_E_SUCCESS) {
						printf("DEP Cloud Config '%s' installed successfully.\n", param);
				    } else {
						int sc = mcinstall_get_status_code(mis);
						fprintf(stderr, "Could not install DEP Cloud Config '%s', status code: 0x%x\n", param, sc);
				    }
				} else {
					fprintf(stderr, "ERROR: unexpected node type in cloudconfig plist (not PLIST_DICT)\n");
					res = -1;
				}
                plist_free(pdata);


				
		}
				break;
        case OP_REMOVE:
		case OP_LIST:
			{
				plist_t profiles = NULL;
				mcinstall_error_t merr;
				merr = mcinstall_copy(mis, &profiles);
				if (merr == MCINSTALL_E_SUCCESS) {

					int found_match = 0;
					plist_t profileIdentifiers = plist_dict_get_item(profiles, "OrderedIdentifiers");
                    plist_t profileMetadata = plist_dict_get_item(profiles, "ProfileMetadata");
					uint32_t num_profiles = plist_array_get_size(profileIdentifiers);
					if (op == OP_LIST) {
						printf("Device has %d configuration %s installed:\n", num_profiles, (num_profiles == 1) ? "profile" : "profiles");
                        uint32_t j;
                        for (j = 0; !found_match && j < num_profiles; j++) {
                            char* p_name = NULL;
                            plist_t profileName = plist_array_get_item(profileIdentifiers, j);
                            plist_get_string_val(profileName, &p_name);
                            printf("%s\n", (p_name) ? p_name : "(no name)");
                            free(p_name);
                            plist_free(profileName);
                        }
					} else {
                        plist_t profile = plist_dict_get_item(profileMetadata, param);
                        
                        if (profile){
                            merr = mcinstall_remove(mis, profile, param);
                            if (merr == MCINSTALL_E_SUCCESS) {
                                fprintf(stdout, "Profile %s removed from device.\n", param);
                            } else {
                                int sc = mcinstall_get_status_code(mis);
					            fprintf(stderr, "Could not get remove profile from device, status code: 0x%x\n", sc);
					            res = -1;
                            }
                        } else {
                            fprintf(stderr, "Profile %s not found on device.\n", param);
                        }
                    }
					plist_free(profileMetadata);
					plist_free(profileIdentifiers);
				} else {
					int sc = mcinstall_get_status_code(mis);
					fprintf(stderr, "Could not get installed profiles from device, status code: 0x%x\n", sc);
					res = -1;
				}
				plist_free(profiles);
			}
		break;

        case OP_GET_CLOUD_CONFIG:
			{
				plist_t profiles = NULL;
				mcinstall_error_t merr;
				merr = mcinstall_get_cloud_config(mis, &profiles);
				if (merr == MCINSTALL_E_SUCCESS) {
                    if (output_xml) {
				        char* xml = NULL;
                        uint32_t xlen = 0;
                        plist_to_xml(profiles, &xml, &xlen);
                        if (xml) {
                            printf("%s\n", xml);
                            free(xml);
                        }
                    } else {
                        if (profiles) {
                            plist_print_to_stream(profiles, stdout);
                        } else {
                            fprintf(stderr, "ERROR: DEP Cloud Config was empty.\n");
                            res = -1;
                        }
                    }
				} else {
					int sc = mcinstall_get_status_code(mis);
					fprintf(stderr, "Could not get CloudConfig from device, status code: 0x%x\n", sc);
					res = -1;
				}
				plist_free(profiles);
			}
		break;

        case OP_DOWNLOAD:
			{
				plist_t profiles = NULL;
				mcinstall_error_t merr;
				merr = mcinstall_download_cloud_config(mis, &profiles);
				if (merr == MCINSTALL_E_SUCCESS) {
                    if (output_xml) {
				        char* xml = NULL;
                        uint32_t xlen = 0;
                        plist_to_xml(profiles, &xml, &xlen);
                        if (xml) {
                            printf("%s\n", xml);
                            free(xml);
                        }
                    } else {
                        if (profiles) {
                            plist_print_to_stream(profiles, stdout);
                        } else {
                            fprintf(stderr, "ERROR: DEP Cloud Config was empty.\n");
                            res = -1;
                        }
                    }
				} else {
					int sc = mcinstall_get_status_code(mis);
					fprintf(stderr, "Could not get CloudConfig from device, status code: 0x%x\n", sc);
					res = -1;
				}
				plist_free(profiles);
			}
		break;
		
		default:
			break;
	}

	mcinstall_client_free(mis);

	idevice_free(device);

	return res;
}
