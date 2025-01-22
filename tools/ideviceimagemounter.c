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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define TOOL_NAME "ideviceimagemounter"

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
#include <sys/stat.h>
#ifndef _WIN32
#include <signal.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/mobile_image_mounter.h>
#include <libimobiledevice-glue/sha.h>
#include <libimobiledevice-glue/utils.h>
#include <asprintf.h>
#include <plist/plist.h>
#include <libtatsu/tss.h>

static int list_mode = 0;
static int use_network = 0;
static int xml_mode = 0;
static const char *udid = NULL;
static const char *imagetype = NULL;

static const char PKG_PATH[] = "PublicStaging";
static const char PATH_PREFIX[] = "/private/var/mobile/Media";

typedef enum {
	DISK_IMAGE_UPLOAD_TYPE_AFC,
	DISK_IMAGE_UPLOAD_TYPE_UPLOAD_IMAGE
} disk_image_upload_type_t;

enum cmd_mode {
	CMD_NONE = 0,
	CMD_MOUNT,
	CMD_UNMOUNT,
	CMD_LIST,
	CMD_DEVMODESTATUS
};

int cmd = CMD_NONE;

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] COMMAND [COMMAND OPTIONS...]\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Mount, list, or unmount a disk image on the device.\n"
		"\n"
		"COMMANDS:\n"
		"  mount PATH     Mount the developer disk image at PATH.\n"
		"                 For iOS 17+, PATH is a directory containing a .dmg image,\n"
		"                 a BuildManifest.plist, and a Firmware sub-directory;\n"
		"                 for older versions PATH is a .dmg filename with a\n"
		"                 .dmg.signature in the same directory, or with another\n"
		"                 parameter pointing to a file elsewhere.\n"
		"  list           List mounted disk images.\n"
		"  unmount PATH   Unmount the image mounted at PATH.\n"
		"  devmodestatus  Query the developer mode status (iOS 16+)\n"
		"\n"
		"OPTIONS:\n"
		"  -u, --udid UDID       target specific device by UDID\n"
		"  -n, --network         connect to network device\n"
		"  -t, --imagetype TYPE  Image type to use, default is 'Developer'\n"
		"  -x, --xml             Use XML output\n"
		"  -d, --debug           enable communication debugging\n"
		"  -h, --help            prints usage information\n"
		"  -v, --version         prints version information\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

static void parse_opts(int argc, char **argv)
{
	int debug_level = 0;
	static struct option longopts[] = {
		{ "help",      no_argument,       NULL, 'h' },
		{ "udid",      required_argument, NULL, 'u' },
		{ "network",   no_argument,       NULL, 'n' },
		{ "imagetype", required_argument, NULL, 't' },
		{ "xml",       no_argument,       NULL, 'x' },
		{ "debug",     no_argument,       NULL, 'd' },
		{ "version",   no_argument,       NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	int c;

	while (1) {
		c = getopt_long(argc, argv, "hu:t:xdnv", longopts, NULL);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_usage(argc, argv, 0);
			exit(0);
		case 'u':
			if (!*optarg) {
				fprintf(stderr, "ERROR: UDID must not be empty!\n");
				print_usage(argc, argv, 1);
				exit(2);
			}
			udid = optarg;
			break;
		case 'n':
			use_network = 1;
			break;
		case 't':
			imagetype = optarg;
			break;
		case 'x':
			xml_mode = 1;
			break;
		case 'd':
			debug_level++;
			break;
		case 'v':
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			exit(0);
		default:
			print_usage(argc, argv, 1);
			exit(2);
		}
	}
	idevice_set_debug_level(debug_level);
	tss_set_debug_level(debug_level);
}

static ssize_t mim_upload_cb(void* buf, size_t size, void* userdata)
{
	return fread(buf, 1, size, (FILE*)userdata);
}

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	lockdownd_client_t lckd = NULL;
	lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
	mobile_image_mounter_client_t mim = NULL;
	afc_client_t afc = NULL;
	lockdownd_service_descriptor_t service = NULL;
	int res = -1;
	char *image_path = NULL;
	size_t image_size = 0;
	char *image_sig_path = NULL;

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	parse_opts(argc, argv);

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		fprintf(stderr, "ERROR: Missing command.\n\n");
		print_usage(argc+optind, argv-optind, 1);
		return 2;
	}

	char* cmdstr = argv[0];

	int optind2 = 0;
	if (!strcmp(cmdstr, "mount")) {
		cmd = CMD_MOUNT;
		optind2++;
	} else if (!strcmp(cmdstr, "list")) {
		cmd = CMD_LIST;
		optind2++;
	} else if (!strcmp(cmdstr, "umount") || !strcmp(cmdstr, "unmount")) {
		cmd = CMD_UNMOUNT;
		optind2++;
	} else if (!strcmp(cmdstr, "devmodestatus")) {
		cmd = CMD_DEVMODESTATUS;
		optind2++;
	} else {
		// assume mount command, unless -l / --list was specified
		if (list_mode) {
			cmd = CMD_LIST;
		} else {
			cmd = CMD_MOUNT;
		}
	}

	argc -= optind2;
	argv += optind2;
	optind += optind2;

	switch (cmd) {
		case CMD_MOUNT:
			if (argc < 1) {
				fprintf(stderr, "ERROR: Missing IMAGE_FILE for mount command\n");
				print_usage(argc+optind, argv-optind, 1);
				return 2;
			}
			image_path = strdup(argv[0]);
			if (argc >= 2) {
				image_sig_path = strdup(argv[1]);
			} else {
				if (asprintf(&image_sig_path, "%s.signature", image_path) < 0) {
					printf("Out of memory?!\n");
					return 1;
				}
			}
			break;
		case CMD_UNMOUNT:
			if (argc != 1) {
				fprintf(stderr, "ERROR: Missing mount path (argc = %d)\n", argc);
				print_usage(argc+optind, argv-optind, 1);
				return 2;
			}
			break;
		default:
			break;
	}

	if (IDEVICE_E_SUCCESS != idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX)) {
		if (udid) {
			printf("No device found with udid %s.\n", udid);
		} else {
			printf("No device found.\n");
		}
		return 1;
	}

	if (LOCKDOWN_E_SUCCESS != (ldret = lockdownd_client_new_with_handshake(device, &lckd, TOOL_NAME))) {
		printf("ERROR: Could not connect to lockdown, error code %d.\n", ldret);
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

	if (product_version_major >= 16) {
		uint8_t dev_mode_status = 0;
		plist_t val = NULL;
		ldret = lockdownd_get_value(lckd, "com.apple.security.mac.amfi", "DeveloperModeStatus", &val);
		if (ldret == LOCKDOWN_E_SUCCESS) {
			plist_get_bool_val(val, &dev_mode_status);
			plist_free(val);
		}
		if (!dev_mode_status) {
			printf("ERROR: You have to enable Developer Mode on the given device in order to allowing mounting a developer disk image.\n");
			goto leave;
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

	if (cmd == CMD_MOUNT) {
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
		if (product_version_major < 17 && stat(image_sig_path, &fst) != 0) {
			fprintf(stderr, "ERROR: stat: %s: %s\n", image_sig_path, strerror(errno));
			goto leave;
		}
	}

	lockdownd_client_free(lckd);
	lckd = NULL;

	mobile_image_mounter_error_t err = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
	plist_t result = NULL;

	if (cmd == CMD_LIST) {
		/* list mounts mode */
		if (!imagetype) {
			if (product_version_major < 17) {
				imagetype = "Developer";
			} else {
				imagetype = "Personalized";
			}
		}
		err = mobile_image_mounter_lookup_image(mim, imagetype, &result);
		if (err == MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
			res = 0;
			plist_write_to_stream(result, stdout, (xml_mode) ? PLIST_FORMAT_XML : PLIST_FORMAT_LIMD, 0);
		} else {
			printf("Error: lookup_image returned %d\n", err);
		}
	} else if (cmd == CMD_MOUNT) {
		unsigned char *sig = NULL;
		size_t sig_length = 0;
		FILE *f;
		struct stat fst;
		plist_t mount_options = NULL;

		if (product_version_major < 17) {
			f = fopen(image_sig_path, "rb");
			if (!f) {
				fprintf(stderr, "Error opening signature file '%s': %s\n", image_sig_path, strerror(errno));
				goto leave;
			}
			if (fstat(fileno(f), &fst) != 0) {
				fprintf(stderr, "Error: fstat: %s\n", strerror(errno));
				goto leave;
			}
			sig = malloc(fst.st_size);
			sig_length = fread(sig, 1, fst.st_size, f);
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
		} else {
			if (stat(image_path, &fst) != 0) {
				fprintf(stderr, "Error: stat: '%s': %s\n", image_path, strerror(errno));
				goto leave;
			}
			if (!S_ISDIR(fst.st_mode)) {
				fprintf(stderr, "Error: Personalized Disk Image mount expects a directory as image path.\n");
				goto leave;
			}
			char* build_manifest_path = string_build_path(image_path, "BuildManifest.plist", NULL);
			plist_t build_manifest = NULL;
			if (plist_read_from_file(build_manifest_path, &build_manifest, NULL) != 0) {
				free(build_manifest_path);
				build_manifest_path = string_build_path(image_path, "Restore", "BuildManifest.plist", NULL);
				if (plist_read_from_file(build_manifest_path, &build_manifest, NULL) == 0) {
					char* image_path_new = string_build_path(image_path, "Restore", NULL);
					free(image_path);
					image_path = image_path_new;
				}
			}
			if (!build_manifest) {
				fprintf(stderr, "Error: Could not locate BuildManifest.plist inside given disk image path!\n");
				goto leave;
			}

			plist_t identifiers = NULL;
			mobile_image_mounter_error_t merr = mobile_image_mounter_query_personalization_identifiers(mim, NULL, &identifiers);
			if (merr != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
				fprintf(stderr, "Failed to query personalization identifiers: %d\n", merr);
				goto error_out;
			}

			unsigned int board_id = plist_dict_get_uint(identifiers, "BoardId");
			unsigned int chip_id = plist_dict_get_uint(identifiers, "ChipID");

			plist_t build_identities = plist_dict_get_item(build_manifest, "BuildIdentities");
			plist_array_iter iter;
			plist_array_new_iter(build_identities, &iter);
			plist_t item = NULL;
			plist_t build_identity = NULL;
			do {
				plist_array_next_item(build_identities, iter, &item);
				if (!item) {
					break;
				}
				unsigned int bi_board_id = (unsigned int)plist_dict_get_uint(item, "ApBoardID");
				unsigned int bi_chip_id = (unsigned int)plist_dict_get_uint(item, "ApChipID");
				if (bi_chip_id == chip_id && bi_board_id == board_id) {
					build_identity = item;
					break;
				}
			} while (item);
			plist_mem_free(iter);
			if (!build_identity) {
				fprintf(stderr, "Error: The given disk image is not compatible with the current device.\n");
				goto leave;
			}
			plist_t p_tc_path = plist_access_path(build_identity, 4, "Manifest", "LoadableTrustCache", "Info", "Path");
			if (!p_tc_path) {
				fprintf(stderr, "Error: Could not determine path for trust cache!\n");
				goto leave;
			}
			plist_t p_dmg_path = plist_access_path(build_identity, 4, "Manifest", "PersonalizedDMG", "Info", "Path");
			if (!p_dmg_path) {
				fprintf(stderr, "Error: Could not determine path for disk image!\n");
				goto leave;
			}
			char *tc_path = string_build_path(image_path, plist_get_string_ptr(p_tc_path, NULL), NULL);
			unsigned char* trust_cache = NULL;
			uint64_t trust_cache_size = 0;
			if (!buffer_read_from_filename(tc_path, (char**)&trust_cache, &trust_cache_size)) {
				fprintf(stderr, "Error: Trust cache does not exist at '%s'!\n", tc_path);
				goto leave;
			}
			mount_options = plist_new_dict();
			plist_dict_set_item(mount_options, "ImageTrustCache", plist_new_data((char*)trust_cache, trust_cache_size));
			free(trust_cache);
			char *dmg_path = string_build_path(image_path, plist_get_string_ptr(p_dmg_path, NULL), NULL);
			free(image_path);
			image_path = dmg_path;
			f = fopen(image_path, "rb");
			if (!f) {
				fprintf(stderr, "Error opening image file '%s': %s\n", image_path, strerror(errno));
				goto leave;
			}

			unsigned char buf[8192];
			unsigned char sha384_digest[48];
			sha384_context ctx;
			sha384_init(&ctx);
			fstat(fileno(f), &fst);
			image_size = fst.st_size;
			while (!feof(f)) {
				ssize_t fr = fread(buf, 1, sizeof(buf), f);
				if (fr <= 0) {
					break;
				}
				sha384_update(&ctx, buf, fr);
			}
			rewind(f);
			sha384_final(&ctx, sha384_digest);
			unsigned char* manifest = NULL;
			unsigned int manifest_size = 0;
			/* check if the device already has a personalization manifest for this image */
			if (mobile_image_mounter_query_personalization_manifest(mim, "DeveloperDiskImage", sha384_digest, sizeof(sha384_digest), &manifest, &manifest_size) == MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
				printf("Using existing personalization manifest from device.\n");
			} else {
				/* we need to re-connect in this case */
				mobile_image_mounter_free(mim);
				mim = NULL;
				if (mobile_image_mounter_start_service(device, &mim, TOOL_NAME) != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
					goto error_out;
				}
				printf("No personalization manifest, requesting from TSS...\n");
				unsigned char* nonce = NULL;
				unsigned int nonce_size = 0;

				/* create new TSS request and fill parameters */
				plist_t request = tss_request_new(NULL);
				plist_t params = plist_new_dict();
				tss_parameters_add_from_manifest(params, build_identity, 1);

				/* copy all `Ap,*` items from identifiers */
				plist_dict_iter di = NULL;
				plist_dict_new_iter(identifiers, &di);
				plist_t node = NULL;
				do {
					char* key = NULL;
					plist_dict_next_item(identifiers, di, &key, &node);
					if (node) {
						if (!strncmp(key, "Ap,", 3)) {
							plist_dict_set_item(request, key, plist_copy(node));
						}
					}
					free(key);
				} while (node);
				plist_mem_free(di);

				plist_dict_copy_uint(params, identifiers, "ApECID", "UniqueChipID");
				plist_dict_set_item(params, "ApProductionMode", plist_new_bool(1));
				plist_dict_set_item(params, "ApSecurityMode", plist_new_bool(1));
				plist_dict_set_item(params, "ApSupportsImg4", plist_new_bool(1));

				/* query nonce from image mounter service */
				merr = mobile_image_mounter_query_nonce(mim, "DeveloperDiskImage", &nonce, &nonce_size);
				if (merr == MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
					plist_dict_set_item(params, "ApNonce", plist_new_data((char*)nonce, nonce_size));
				} else {
					fprintf(stderr, "ERROR: Failed to query nonce for developer disk image: %d\n", merr);
					goto error_out;
				}
				mobile_image_mounter_free(mim);
				mim = NULL;

				plist_dict_set_item(params, "ApSepNonce", plist_new_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 20));
				plist_dict_set_item(params, "UID_MODE", plist_new_bool(0));
				tss_request_add_ap_tags(request, params, NULL);
				tss_request_add_common_tags(request, params, NULL);
				tss_request_add_ap_img4_tags(request, params);
				plist_free(params);

				/* request IM4M from TSS */
				plist_t response = tss_request_send(request, NULL);
				plist_free(request);

				plist_t p_manifest = plist_dict_get_item(response, "ApImg4Ticket");
				if (!PLIST_IS_DATA(p_manifest)) {
					fprintf(stderr, "Failed to get Img4Ticket\n");
					goto error_out;
				}

				uint64_t m4m_len = 0;
				plist_get_data_val(p_manifest, (char**)&manifest, &m4m_len);
				manifest_size = m4m_len;
				plist_free(response);
				printf("Done.\n");
			}
			sig = manifest;
			sig_length = manifest_size;

			imagetype = "Personalized";
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
			imagetype = "Developer";
		}

		if (!mim) {
			if (mobile_image_mounter_start_service(device, &mim, TOOL_NAME) != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
				goto error_out;
			}
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
							if (afc_file_write(afc, af, buf + total, amount - total, &written) !=
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

		if (err != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
			if (err == MOBILE_IMAGE_MOUNTER_E_DEVICE_LOCKED) {
				printf("ERROR: Device is locked, can't mount. Unlock device and try again.\n");
			} else {
				printf("ERROR: Unknown error occurred, can't mount.\n");
			}
			goto error_out;
		}
		printf("done.\n");

		printf("Mounting...\n");
		err = mobile_image_mounter_mount_image_with_options(mim, mountname, sig, sig_length, imagetype, mount_options, &result);
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
							plist_write_to_stream(result, stdout, (xml_mode) ? PLIST_FORMAT_XML : PLIST_FORMAT_LIMD, 0);
						}
						free(status);
					} else {
						printf("unexpected result:\n");
						plist_write_to_stream(result, stdout, (xml_mode) ? PLIST_FORMAT_XML : PLIST_FORMAT_LIMD, 0);
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
						plist_write_to_stream(result, stdout, (xml_mode) ? PLIST_FORMAT_XML : PLIST_FORMAT_LIMD, 0);
					}
					node = plist_dict_get_item(result, "DetailedError");
					if (node) {
						printf("DetailedError: %s\n", plist_get_string_ptr(node, NULL));
					}
				} else {
					plist_write_to_stream(result, stdout, (xml_mode) ? PLIST_FORMAT_XML : PLIST_FORMAT_LIMD, 0);
				}
			}
		} else {
			printf("Error: mount_image returned %d\n", err);

		}
	} else if (cmd == CMD_UNMOUNT) {
		err = mobile_image_mounter_unmount_image(mim, argv[0]);
		switch (err) {
			case MOBILE_IMAGE_MOUNTER_E_SUCCESS:
				printf("Success\n");
				res = 0;
				break;
			case MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED:
				printf("Error: '%s' is not mounted\n", argv[0]);
				res = 1;
				break;
			case MOBILE_IMAGE_MOUNTER_E_NOT_SUPPORTED:
				printf("Error: 'unmount' is not supported on this device\n");
				res = 1;
				break;
			case MOBILE_IMAGE_MOUNTER_E_DEVICE_LOCKED:
				printf("Error: device is locked\n");
				res = 1;
				break;
			default:
				printf("Error: unmount returned %d\n", err);
				break;
		}
	} else if (cmd == CMD_DEVMODESTATUS) {
		err = mobile_image_mounter_query_developer_mode_status(mim, &result);
		if (err == MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
			res = 0;
			plist_write_to_stream(result, stdout, (xml_mode) ? PLIST_FORMAT_XML : PLIST_FORMAT_LIMD, 0);
		} else {
			printf("Error: query_developer_mode_status returned %d\n", err);
		}
	}

	if (result) {
		plist_free(result);
	}

error_out:
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
