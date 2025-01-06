/*
 * idevicebackup2.c
 * Command line interface to use the device's backup and restore service
 *
 * Copyright (c) 2010-2022 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2009-2010 Martin Szulecki, All Rights Reserved.
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

#define TOOL_NAME "idevicebackup2"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/mobilebackup2.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/afc.h>
#include <libimobiledevice/installation_proxy.h>
#include <libimobiledevice/sbservices.h>
#include <libimobiledevice/diagnostics_relay.h>
#include <libimobiledevice-glue/utils.h>
#include <plist/plist.h>

#include <endianness.h>

#define LOCK_ATTEMPTS 50
#define LOCK_WAIT 200000

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#define sleep(x) Sleep(x*1000)
#ifndef ELOOP
#define ELOOP 114
#endif
#else
#include <termios.h>
#include <sys/statvfs.h>
#endif
#include <sys/stat.h>

#define CODE_SUCCESS 0x00
#define CODE_ERROR_LOCAL 0x06
#define CODE_ERROR_REMOTE 0x0b
#define CODE_FILE_DATA 0x0c

static int verbose = 1;
static int quit_flag = 0;
static int passcode_requested = 0;

#define PRINT_VERBOSE(min_level, ...) if (verbose >= min_level) { printf(__VA_ARGS__); };

enum cmd_mode {
	CMD_BACKUP,
	CMD_RESTORE,
	CMD_INFO,
	CMD_LIST,
	CMD_UNBACK,
	CMD_CHANGEPW,
	CMD_LEAVE,
	CMD_CLOUD
};

enum cmd_flags {
	CMD_FLAG_RESTORE_SYSTEM_FILES       = (1 << 1),
	CMD_FLAG_RESTORE_NO_REBOOT          = (1 << 2),
	CMD_FLAG_RESTORE_COPY_BACKUP        = (1 << 3),
	CMD_FLAG_RESTORE_SETTINGS           = (1 << 4),
	CMD_FLAG_RESTORE_REMOVE_ITEMS       = (1 << 5),
	CMD_FLAG_ENCRYPTION_ENABLE          = (1 << 6),
	CMD_FLAG_ENCRYPTION_DISABLE         = (1 << 7),
	CMD_FLAG_ENCRYPTION_CHANGEPW        = (1 << 8),
	CMD_FLAG_FORCE_FULL_BACKUP          = (1 << 9),
	CMD_FLAG_CLOUD_ENABLE               = (1 << 10),
	CMD_FLAG_CLOUD_DISABLE              = (1 << 11),
	CMD_FLAG_RESTORE_SKIP_APPS          = (1 << 12)
};

static int backup_domain_changed = 0;

static void notify_cb(const char *notification, void *userdata)
{
	if (strlen(notification) == 0) {
		return;
	}
	if (!strcmp(notification, NP_SYNC_CANCEL_REQUEST)) {
		PRINT_VERBOSE(1, "User has cancelled the backup process on the device.\n");
		quit_flag++;
	} else if (!strcmp(notification, NP_BACKUP_DOMAIN_CHANGED)) {
		backup_domain_changed = 1;
	} else if (!strcmp(notification, "com.apple.LocalAuthentication.ui.presented")) {
		passcode_requested = 1;
	} else if (!strcmp(notification, "com.apple.LocalAuthentication.ui.dismissed")) {
		passcode_requested = 0;
	} else {
		PRINT_VERBOSE(1, "Unhandled notification '%s' (TODO: implement)\n", notification);
	}
}

static void mobilebackup_afc_get_file_contents(afc_client_t afc, const char *filename, char **data, uint64_t *size)
{
	if (!afc || !data || !size) {
		return;
	}

	char **fileinfo = NULL;
	uint32_t fsize = 0;

	afc_get_file_info(afc, filename, &fileinfo);
	if (!fileinfo) {
		return;
	}
	int i;
	for (i = 0; fileinfo[i]; i+=2) {
		if (!strcmp(fileinfo[i], "st_size")) {
			fsize = atol(fileinfo[i+1]);
			break;
		}
	}
	afc_dictionary_free(fileinfo);

	if (fsize == 0) {
		return;
	}

	uint64_t f = 0;
	afc_file_open(afc, filename, AFC_FOPEN_RDONLY, &f);
	if (!f) {
		return;
	}
	char *buf = (char*)malloc((uint32_t)fsize);
	uint32_t done = 0;
	while (done < fsize) {
		uint32_t bread = 0;
		afc_file_read(afc, f, buf+done, 65536, &bread);
		if (bread > 0) {
			done += bread;
		} else {
			break;
		}
	}
	if (done == fsize) {
		*size = fsize;
		*data = buf;
	} else {
		free(buf);
	}
	afc_file_close(afc, f);
}

static int __mkdir(const char* path, int mode)
{
#ifdef _WIN32
	return mkdir(path);
#else
	return mkdir(path, mode);
#endif
}

static int mkdir_with_parents(const char *dir, int mode)
{
	if (!dir) return -1;
	if (__mkdir(dir, mode) == 0) {
		return 0;
	}
	if (errno == EEXIST) return 0;
	int res;
	char *parent = strdup(dir);
	char *parentdir = dirname(parent);
	if (parentdir) {
		res = mkdir_with_parents(parentdir, mode);
	} else {
		res = -1;
	}
	free(parent);
	if (res == 0) {
		mkdir_with_parents(dir, mode);
	}
	return res;
}

#ifdef _WIN32
static int win32err_to_errno(int err_value)
{
	switch (err_value) {
		case ERROR_FILE_NOT_FOUND:
			return ENOENT;
		case ERROR_ALREADY_EXISTS:
			return EEXIST;
		default:
			return EFAULT;
	}
}
#endif

static int remove_file(const char* path)
{
	int e = 0;
#ifdef _WIN32
	if (!DeleteFile(path)) {
		e = win32err_to_errno(GetLastError());
	}
#else
	if (remove(path) < 0) {
		e = errno;
	}
#endif
	return e;
}

static int remove_directory(const char* path)
{
	int e = 0;
#ifdef _WIN32
	if (!RemoveDirectory(path)) {
		e = win32err_to_errno(GetLastError());
	}
#else
	if (remove(path) < 0) {
		e = errno;
	}
#endif
	return e;
}

struct entry {
	char *name;
	struct entry *next;
};

static void scan_directory(const char *path, struct entry **files, struct entry **directories)
{
	DIR* cur_dir = opendir(path);
	if (cur_dir) {
		struct dirent* ep;
		while ((ep = readdir(cur_dir))) {
			if ((strcmp(ep->d_name, ".") == 0) || (strcmp(ep->d_name, "..") == 0)) {
				continue;
			}
			char *fpath = string_build_path(path, ep->d_name, NULL);
			if (fpath) {
#ifdef HAVE_DIRENT_D_TYPE
				if (ep->d_type & DT_DIR) {
#else
				struct stat st;
				if (stat(fpath, &st) != 0) return;
				if (S_ISDIR(st.st_mode)) {
#endif
					struct entry *ent = malloc(sizeof(struct entry));
					if (!ent) return;
					ent->name = fpath;
					ent->next = *directories;
					*directories = ent;
					scan_directory(fpath, files, directories);
					fpath = NULL;
				} else {
					struct entry *ent = malloc(sizeof(struct entry));
					if (!ent) return;
					ent->name = fpath;
					ent->next = *files;
					*files = ent;
					fpath = NULL;
				}
			}
		}
		closedir(cur_dir);
	}
}

static int rmdir_recursive(const char* path)
{
	int res = 0;
	struct entry *files = NULL;
	struct entry *directories = NULL;
	struct entry *ent;

	ent = malloc(sizeof(struct entry));
	if (!ent) return ENOMEM;
	ent->name = strdup(path);
	ent->next = NULL;
	directories = ent;

	scan_directory(path, &files, &directories);

	ent = files;
	while (ent) {
		struct entry *del = ent;
		res = remove_file(ent->name);
		free(ent->name);
		ent = ent->next;
		free(del);
	}
	ent = directories;
	while (ent) {
		struct entry *del = ent;
		res = remove_directory(ent->name);
		free(ent->name);
		ent = ent->next;
		free(del);
	}

	return res;
}

static char* get_uuid()
{
	const char *chars = "ABCDEF0123456789";
	int i = 0;
	char *uuid = (char*)malloc(sizeof(char) * 33);

	srand(time(NULL));

	for (i = 0; i < 32; i++) {
		uuid[i] = chars[rand() % 16];
	}

	uuid[32] = '\0';

	return uuid;
}

static plist_t mobilebackup_factory_info_plist_new(const char* udid, idevice_t device, afc_client_t afc)
{
	/* gather data from lockdown */
	plist_t value_node = NULL;
	plist_t root_node = NULL;
	plist_t itunes_settings = NULL;
	plist_t min_itunes_version = NULL;
	char *udid_uppercase = NULL;

	lockdownd_client_t lockdown = NULL;
	if (lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME) != LOCKDOWN_E_SUCCESS) {
		return NULL;
	}

	plist_t ret = plist_new_dict();

	/* get basic device information in one go */
	lockdownd_get_value(lockdown, NULL, NULL, &root_node);

	/* get iTunes settings */
	lockdownd_get_value(lockdown, "com.apple.iTunes", NULL, &itunes_settings);

	/* get minimum iTunes version */
	lockdownd_get_value(lockdown, "com.apple.mobile.iTunes", "MinITunesVersion", &min_itunes_version);

	lockdownd_client_free(lockdown);

	/* get a list of installed user applications */
	plist_t app_dict = plist_new_dict();
	plist_t installed_apps = plist_new_array();
	instproxy_client_t ip = NULL;
	if (instproxy_client_start_service(device, &ip, TOOL_NAME) == INSTPROXY_E_SUCCESS) {
		plist_t client_opts = instproxy_client_options_new();
		instproxy_client_options_add(client_opts, "ApplicationType", "User", NULL);
		instproxy_client_options_set_return_attributes(client_opts, "CFBundleIdentifier", "ApplicationSINF", "iTunesMetadata", NULL);

		plist_t apps = NULL;
		instproxy_browse(ip, client_opts, &apps);

		sbservices_client_t sbs = NULL;
		if (sbservices_client_start_service(device, &sbs, TOOL_NAME) != SBSERVICES_E_SUCCESS) {
			printf("Couldn't establish sbservices connection. Continuing anyway.\n");
		}

		if (apps && (plist_get_node_type(apps) == PLIST_ARRAY)) {
			uint32_t app_count = plist_array_get_size(apps);
			uint32_t i;
			for (i = 0; i < app_count; i++) {
				plist_t app_entry = plist_array_get_item(apps, i);
				plist_t bundle_id = plist_dict_get_item(app_entry, "CFBundleIdentifier");
				if (bundle_id) {
					char *bundle_id_str = NULL;
					plist_array_append_item(installed_apps, plist_copy(bundle_id));

					plist_get_string_val(bundle_id, &bundle_id_str);
					plist_t sinf = plist_dict_get_item(app_entry, "ApplicationSINF");
					plist_t meta = plist_dict_get_item(app_entry, "iTunesMetadata");
					if (sinf && meta) {
						plist_t adict = plist_new_dict();
						plist_dict_set_item(adict, "ApplicationSINF", plist_copy(sinf));
						if (sbs) {
							char *pngdata = NULL;
							uint64_t pngsize = 0;
							sbservices_get_icon_pngdata(sbs, bundle_id_str, &pngdata, &pngsize);
							if (pngdata) {
								plist_dict_set_item(adict, "PlaceholderIcon", plist_new_data(pngdata, pngsize));
								free(pngdata);
							}
						}
						plist_dict_set_item(adict, "iTunesMetadata", plist_copy(meta));
						plist_dict_set_item(app_dict, bundle_id_str, adict);
					}
					free(bundle_id_str);
				}
			}
		}
		plist_free(apps);

		if (sbs) {
			sbservices_client_free(sbs);
		}

		instproxy_client_options_free(client_opts);

		instproxy_client_free(ip);
	}

	/* Applications */
	plist_dict_set_item(ret, "Applications", app_dict);

	/* set fields we understand */
	value_node = plist_dict_get_item(root_node, "BuildVersion");
	plist_dict_set_item(ret, "Build Version", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "DeviceName");
	plist_dict_set_item(ret, "Device Name", plist_copy(value_node));
	plist_dict_set_item(ret, "Display Name", plist_copy(value_node));

	char *uuid = get_uuid();
	plist_dict_set_item(ret, "GUID", plist_new_string(uuid));
	free(uuid);

	value_node = plist_dict_get_item(root_node, "IntegratedCircuitCardIdentity");
	if (value_node)
		plist_dict_set_item(ret, "ICCID", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "InternationalMobileEquipmentIdentity");
	if (value_node)
		plist_dict_set_item(ret, "IMEI", plist_copy(value_node));

	/* Installed Applications */
	plist_dict_set_item(ret, "Installed Applications", installed_apps);

	plist_dict_set_item(ret, "Last Backup Date", plist_new_date(time(NULL) - MAC_EPOCH, 0));

	value_node = plist_dict_get_item(root_node, "MobileEquipmentIdentifier");
	if (value_node)
		plist_dict_set_item(ret, "MEID", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "PhoneNumber");
	if (value_node && (plist_get_node_type(value_node) == PLIST_STRING)) {
		plist_dict_set_item(ret, "Phone Number", plist_copy(value_node));
	}

	/* FIXME Product Name */

	value_node = plist_dict_get_item(root_node, "ProductType");
	plist_dict_set_item(ret, "Product Type", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "ProductVersion");
	plist_dict_set_item(ret, "Product Version", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "SerialNumber");
	plist_dict_set_item(ret, "Serial Number", plist_copy(value_node));

	/* FIXME Sync Settings? */

	value_node = plist_dict_get_item(root_node, "UniqueDeviceID");
	plist_dict_set_item(ret, "Target Identifier", plist_new_string(udid));

	plist_dict_set_item(ret, "Target Type", plist_new_string("Device"));

	/* uppercase */
	udid_uppercase = string_toupper((char*)udid);
	plist_dict_set_item(ret, "Unique Identifier", plist_new_string(udid_uppercase));
	free(udid_uppercase);

	char *data_buf = NULL;
	uint64_t data_size = 0;
	mobilebackup_afc_get_file_contents(afc, "/Books/iBooksData2.plist", &data_buf, &data_size);
	if (data_buf) {
		plist_dict_set_item(ret, "iBooks Data 2", plist_new_data(data_buf, data_size));
		free(data_buf);
	}

	plist_t files = plist_new_dict();
	const char *itunesfiles[] = {
		"ApertureAlbumPrefs",
		"IC-Info.sidb",
		"IC-Info.sidv",
		"PhotosFolderAlbums",
		"PhotosFolderName",
		"PhotosFolderPrefs",
		"VoiceMemos.plist",
		"iPhotoAlbumPrefs",
		"iTunesApplicationIDs",
		"iTunesPrefs",
		"iTunesPrefs.plist",
		NULL
	};
	int i = 0;
	for (i = 0; itunesfiles[i]; i++) {
		data_buf = NULL;
		data_size = 0;
		char *fname = (char*)malloc(strlen("/iTunes_Control/iTunes/") + strlen(itunesfiles[i]) + 1);
		strcpy(fname, "/iTunes_Control/iTunes/");
		strcat(fname, itunesfiles[i]);
		mobilebackup_afc_get_file_contents(afc, fname, &data_buf, &data_size);
		free(fname);
		if (data_buf) {
			plist_dict_set_item(files, itunesfiles[i], plist_new_data(data_buf, data_size));
			free(data_buf);
		}
	}
	plist_dict_set_item(ret, "iTunes Files", files);

	plist_dict_set_item(ret, "iTunes Settings", itunes_settings ? plist_copy(itunes_settings) : plist_new_dict());

	/* since we usually don't have iTunes, let's get the minimum required iTunes version from the device */
	if (min_itunes_version) {
		plist_dict_set_item(ret, "iTunes Version", plist_copy(min_itunes_version));
	} else {
		plist_dict_set_item(ret, "iTunes Version", plist_new_string("10.0.1"));
	}

	plist_free(itunes_settings);
	plist_free(min_itunes_version);
	plist_free(root_node);

	return ret;
}

static int write_restore_applications(plist_t info_plist, afc_client_t afc)
{
	int res = -1;
	uint64_t restore_applications_file = 0;
	char * applications_plist_xml = NULL;
	uint32_t applications_plist_xml_length = 0;

	plist_t applications_plist = plist_dict_get_item(info_plist, "Applications");
	if (!applications_plist) {
		printf("No Applications in Info.plist, skipping creation of RestoreApplications.plist\n");
		return 0;
	}
	plist_to_xml(applications_plist, &applications_plist_xml, &applications_plist_xml_length);
	if (!applications_plist_xml) {
		printf("Error preparing RestoreApplications.plist\n");
		goto leave;
	}

	afc_error_t afc_err = 0;
	afc_err = afc_make_directory(afc, "/iTunesRestore");
	if (afc_err != AFC_E_SUCCESS) {
		printf("Error creating directory /iTunesRestore, error code %d\n", afc_err);
		goto leave;
	}

	afc_err = afc_file_open(afc, "/iTunesRestore/RestoreApplications.plist", AFC_FOPEN_WR, &restore_applications_file);
	if (afc_err != AFC_E_SUCCESS  || !restore_applications_file) {
		printf("Error creating /iTunesRestore/RestoreApplications.plist, error code %d\n", afc_err);
		goto leave;
	}

	uint32_t bytes_written = 0;
	afc_err = afc_file_write(afc, restore_applications_file, applications_plist_xml, applications_plist_xml_length, &bytes_written);
	if (afc_err != AFC_E_SUCCESS  || bytes_written != applications_plist_xml_length) {
		printf("Error writing /iTunesRestore/RestoreApplications.plist, error code %d, wrote %u of %u bytes\n", afc_err, bytes_written, applications_plist_xml_length);
		goto leave;
	}

	afc_err = afc_file_close(afc, restore_applications_file);
	restore_applications_file = 0;
	if (afc_err != AFC_E_SUCCESS) {
		goto leave;
	}
	/* success */
	res = 0;

leave:
	free(applications_plist_xml);

	if (restore_applications_file) {
		afc_file_close(afc, restore_applications_file);
		restore_applications_file = 0;
	}

	return res;
}

static int mb2_status_check_snapshot_state(const char *path, const char *udid, const char *matches)
{
	int ret = 0;
	plist_t status_plist = NULL;
	char *file_path = string_build_path(path, udid, "Status.plist", NULL);

	plist_read_from_file(file_path, &status_plist, NULL);
	free(file_path);
	if (!status_plist) {
		printf("Could not read Status.plist!\n");
		return ret;
	}
	plist_t node = plist_dict_get_item(status_plist, "SnapshotState");
	if (node && (plist_get_node_type(node) == PLIST_STRING)) {
		char* sval = NULL;
		plist_get_string_val(node, &sval);
		if (sval) {
			ret = (strcmp(sval, matches) == 0) ? 1 : 0;
			free(sval);
		}
	} else {
		printf("%s: ERROR could not get SnapshotState key from Status.plist!\n", __func__);
	}
	plist_free(status_plist);
	return ret;
}

static void do_post_notification(idevice_t device, const char *notification)
{
	lockdownd_service_descriptor_t service = NULL;
	np_client_t np;

	lockdownd_client_t lockdown = NULL;

	if (lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME) != LOCKDOWN_E_SUCCESS) {
		return;
	}

	lockdownd_error_t ldret = lockdownd_start_service(lockdown, NP_SERVICE_NAME, &service);
	if (ldret == LOCKDOWN_E_SUCCESS) {
		np_client_new(device, service, &np);
		if (np) {
			np_post_notification(np, notification);
			np_client_free(np);
		}
	} else {
		printf("ERROR: Could not start service %s: %s\n", NP_SERVICE_NAME, lockdownd_strerror(ldret));
	}

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}
	lockdownd_client_free(lockdown);
}

static void print_progress_real(double progress, int flush)
{
	int i = 0;
	PRINT_VERBOSE(1, "\r[");
	for(i = 0; i < 50; i++) {
		if(i < progress / 2) {
			PRINT_VERBOSE(1, "=");
		} else {
			PRINT_VERBOSE(1, " ");
		}
	}
	PRINT_VERBOSE(1, "] %3.0f%%", progress);

	if (flush > 0) {
		fflush(stdout);
		if (progress == 100)
			PRINT_VERBOSE(1, "\n");
	}
}

static void print_progress(uint64_t current, uint64_t total)
{
	char *format_size = NULL;
	double progress = ((double)current/(double)total)*100;
	if (progress < 0)
		return;

	if (progress > 100)
		progress = 100;

	print_progress_real((double)progress, 0);

	format_size = string_format_size(current);
	PRINT_VERBOSE(1, " (%s", format_size);
	free(format_size);
	format_size = string_format_size(total);
	PRINT_VERBOSE(1, "/%s)     ", format_size);
	free(format_size);

	fflush(stdout);
	if (progress == 100)
		PRINT_VERBOSE(1, "\n");
}

static double overall_progress = 0;

static void mb2_set_overall_progress(double progress)
{
	if (progress > 0.0)
		overall_progress = progress;
}

static void mb2_set_overall_progress_from_message(plist_t message, char* identifier)
{
	plist_t node = NULL;
	double progress = 0.0;

	if (!strcmp(identifier, "DLMessageDownloadFiles")) {
		node = plist_array_get_item(message, 3);
	} else if (!strcmp(identifier, "DLMessageUploadFiles")) {
		node = plist_array_get_item(message, 2);
	} else if (!strcmp(identifier, "DLMessageMoveFiles") || !strcmp(identifier, "DLMessageMoveItems")) {
		node = plist_array_get_item(message, 3);
	} else if (!strcmp(identifier, "DLMessageRemoveFiles") || !strcmp(identifier, "DLMessageRemoveItems")) {
		node = plist_array_get_item(message, 3);
	}

	if (node != NULL) {
		plist_get_real_val(node, &progress);
		mb2_set_overall_progress(progress);
	}
}

static void mb2_multi_status_add_file_error(plist_t status_dict, const char *path, int error_code, const char *error_message)
{
	if (!status_dict) return;
	plist_t filedict = plist_new_dict();
	plist_dict_set_item(filedict, "DLFileErrorString", plist_new_string(error_message));
	plist_dict_set_item(filedict, "DLFileErrorCode", plist_new_uint(error_code));
	plist_dict_set_item(status_dict, path, filedict);
}

static int errno_to_device_error(int errno_value)
{
	switch (errno_value) {
		case ENOENT:
			return -6;
		case EEXIST:
			return -7;
		case ENOTDIR:
			return -8;
		case EISDIR:
			return -9;
		case ELOOP:
			return -10;
		case EIO:
			return -11;
		case ENOSPC:
			return -15;
		default:
			return -1;
	}
}

static int mb2_handle_send_file(mobilebackup2_client_t mobilebackup2, const char *backup_dir, const char *path, plist_t *errplist)
{
	uint32_t nlen = 0;
	uint32_t pathlen = strlen(path);
	uint32_t bytes = 0;
	char *localfile = string_build_path(backup_dir, path, NULL);
	char buf[32768];
#ifdef _WIN32
	struct _stati64 fst;
#else
	struct stat fst;
#endif

	FILE *f = NULL;
	uint32_t slen = 0;
	int errcode = -1;
	int result = -1;
	uint32_t length;
#ifdef _WIN32
	uint64_t total;
	uint64_t sent;
#else
	off_t total;
	off_t sent;
#endif

	mobilebackup2_error_t err;

	/* send path length */
	nlen = htobe32(pathlen);
	err = mobilebackup2_send_raw(mobilebackup2, (const char*)&nlen, sizeof(nlen), &bytes);
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		goto leave_proto_err;
	}
	if (bytes != (uint32_t)sizeof(nlen)) {
		err = MOBILEBACKUP2_E_MUX_ERROR;
		goto leave_proto_err;
	}

	/* send path */
	err = mobilebackup2_send_raw(mobilebackup2, path, pathlen, &bytes);
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		goto leave_proto_err;
	}
	if (bytes != pathlen) {
		err = MOBILEBACKUP2_E_MUX_ERROR;
		goto leave_proto_err;
	}

#ifdef _WIN32
	if (_stati64(localfile, &fst) < 0)
#else
	if (stat(localfile, &fst) < 0)
#endif
	{
		if (errno != ENOENT)
			printf("%s: stat failed on '%s': %d\n", __func__, localfile, errno);
		errcode = errno;
		goto leave;
	}

	total = fst.st_size;

	char *format_size = string_format_size(total);
	PRINT_VERBOSE(1, "Sending '%s' (%s)\n", path, format_size);
	free(format_size);

	if (total == 0) {
		errcode = 0;
		goto leave;
	}

	f = fopen(localfile, "rb");
	if (!f) {
		printf("%s: Error opening local file '%s': %d\n", __func__, localfile, errno);
		errcode = errno;
		goto leave;
	}

	sent = 0;
	do {
		length = ((total-sent) < (long long)sizeof(buf)) ? (uint32_t)total-sent : (uint32_t)sizeof(buf);
		/* send data size (file size + 1) */
		nlen = htobe32(length+1);
		memcpy(buf, &nlen, sizeof(nlen));
		buf[4] = CODE_FILE_DATA;
		err = mobilebackup2_send_raw(mobilebackup2, (const char*)buf, 5, &bytes);
		if (err != MOBILEBACKUP2_E_SUCCESS) {
			goto leave_proto_err;
		}
		if (bytes != 5) {
			goto leave_proto_err;
		}

		/* send file contents */
		size_t r = fread(buf, 1, sizeof(buf), f);
		if (r <= 0) {
			printf("%s: read error\n", __func__);
			errcode = errno;
			goto leave;
		}
		err = mobilebackup2_send_raw(mobilebackup2, buf, r, &bytes);
		if (err != MOBILEBACKUP2_E_SUCCESS) {
			goto leave_proto_err;
		}
		if (bytes != (uint32_t)r) {
			printf("Error: sent only %d of %d bytes\n", bytes, (int)r);
			goto leave_proto_err;
		}
		sent += r;
	} while (sent < total);
	fclose(f);
	f = NULL;
	errcode = 0;

leave:
	if (errcode == 0) {
		result = 0;
		nlen = 1;
		nlen = htobe32(nlen);
		memcpy(buf, &nlen, 4);
		buf[4] = CODE_SUCCESS;
		mobilebackup2_send_raw(mobilebackup2, buf, 5, &bytes);
	} else {
		if (!*errplist) {
			*errplist = plist_new_dict();
		}
		char *errdesc = strerror(errcode);
		mb2_multi_status_add_file_error(*errplist, path, errno_to_device_error(errcode), errdesc);

		length = strlen(errdesc);
		nlen = htobe32(length+1);
		memcpy(buf, &nlen, 4);
		buf[4] = CODE_ERROR_LOCAL;
		slen = 5;
		memcpy(buf+slen, errdesc, length);
		slen += length;
		err = mobilebackup2_send_raw(mobilebackup2, (const char*)buf, slen, &bytes);
		if (err != MOBILEBACKUP2_E_SUCCESS) {
			printf("could not send message\n");
		}
		if (bytes != slen) {
			printf("could only send %d from %d\n", bytes, slen);
		}
	}

leave_proto_err:
	if (f)
		fclose(f);
	free(localfile);
	return result;
}

static void mb2_handle_send_files(mobilebackup2_client_t mobilebackup2, plist_t message, const char *backup_dir)
{
	uint32_t cnt;
	uint32_t i = 0;
	uint32_t sent;
	plist_t errplist = NULL;

	if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || (plist_array_get_size(message) < 2) || !backup_dir) return;

	plist_t files = plist_array_get_item(message, 1);
	cnt = plist_array_get_size(files);

	for (i = 0; i < cnt; i++) {
		plist_t val = plist_array_get_item(files, i);
		if (plist_get_node_type(val) != PLIST_STRING) {
			continue;
		}
		char *str = NULL;
		plist_get_string_val(val, &str);
		if (!str)
			continue;

		if (mb2_handle_send_file(mobilebackup2, backup_dir, str, &errplist) < 0) {
			free(str);
			//printf("Error when sending file '%s' to device\n", str);
			// TODO: perhaps we can continue, we've got a multi status response?!
			break;
		}
		free(str);
	}

	/* send terminating 0 dword */
	uint32_t zero = 0;
	mobilebackup2_send_raw(mobilebackup2, (char*)&zero, 4, &sent);

	if (!errplist) {
		plist_t emptydict = plist_new_dict();
		mobilebackup2_send_status_response(mobilebackup2, 0, NULL, emptydict);
		plist_free(emptydict);
	} else {
		mobilebackup2_send_status_response(mobilebackup2, -13, "Multi status", errplist);
		plist_free(errplist);
	}
}

static int mb2_receive_filename(mobilebackup2_client_t mobilebackup2, char** filename)
{
	uint32_t nlen = 0;
	uint32_t rlen = 0;

	do {
		nlen = 0;
		rlen = 0;
		mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &rlen);
		nlen = be32toh(nlen);

		if ((nlen == 0) && (rlen == 4)) {
			// a zero length means no more files to receive
			return 0;
		}
		if (rlen == 0) {
			// device needs more time, waiting...
			continue;
		}
		if (nlen > 4096) {
			// filename length is too large
			printf("ERROR: %s: too large filename length (%d)!\n", __func__, nlen);
			return 0;
		}

		if (*filename != NULL) {
			free(*filename);
			*filename = NULL;
		}

		*filename = (char*)malloc(nlen+1);

		rlen = 0;
		mobilebackup2_receive_raw(mobilebackup2, *filename, nlen, &rlen);
		if (rlen != nlen) {
			printf("ERROR: %s: could not read filename\n", __func__);
			return 0;
		}

		char* p = *filename;
		p[rlen] = 0;

		break;
	} while(1 && !quit_flag);

	return nlen;
}

static int mb2_handle_receive_files(mobilebackup2_client_t mobilebackup2, plist_t message, const char *backup_dir)
{
	uint64_t backup_real_size = 0;
	uint64_t backup_total_size = 0;
	uint32_t blocksize;
	uint32_t bdone;
	uint32_t rlen;
	uint32_t nlen = 0;
	uint32_t r;
	char buf[32768];
	char *fname = NULL;
	char *dname = NULL;
	char *bname = NULL;
	char code = 0;
	char last_code = 0;
	plist_t node = NULL;
	FILE *f = NULL;
	unsigned int file_count = 0;
	int errcode = 0;
	char *errdesc = NULL;

	if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || plist_array_get_size(message) < 4 || !backup_dir) return 0;

	node = plist_array_get_item(message, 3);
	if (plist_get_node_type(node) == PLIST_UINT) {
		plist_get_uint_val(node, &backup_total_size);
	}
	if (backup_total_size > 0) {
		PRINT_VERBOSE(1, "Receiving files\n");
	}

	do {
		if (quit_flag)
			break;

		nlen = mb2_receive_filename(mobilebackup2, &dname);
		if (nlen == 0) {
			break;
		}

		nlen = mb2_receive_filename(mobilebackup2, &fname);
		if (!nlen) {
			break;
		}

		if (bname != NULL) {
			free(bname);
			bname = NULL;
		}

		bname = string_build_path(backup_dir, fname, NULL);

		if (fname != NULL) {
			free(fname);
			fname = NULL;
		}

		r = 0;
		nlen = 0;
		mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &r);
		if (r != 4) {
			printf("ERROR: %s: could not receive code length!\n", __func__);
			break;
		}
		nlen = be32toh(nlen);

		last_code = code;
		code = 0;

		mobilebackup2_receive_raw(mobilebackup2, &code, 1, &r);
		if (r != 1) {
			printf("ERROR: %s: could not receive code!\n", __func__);
			break;
		}

		/* TODO remove this */
		if ((code != CODE_SUCCESS) && (code != CODE_FILE_DATA) && (code != CODE_ERROR_REMOTE)) {
			PRINT_VERBOSE(1, "Found new flag %02x\n", code);
		}

		remove_file(bname);
		f = fopen(bname, "wb");
		while (f && (code == CODE_FILE_DATA)) {
			blocksize = nlen-1;
			bdone = 0;
			rlen = 0;
			while (bdone < blocksize) {
				if ((blocksize - bdone) < sizeof(buf)) {
					rlen = blocksize - bdone;
				} else {
					rlen = sizeof(buf);
				}
				mobilebackup2_receive_raw(mobilebackup2, buf, rlen, &r);
				if ((int)r <= 0) {
					break;
				}
				fwrite(buf, 1, r, f);
				bdone += r;
			}
			if (bdone == blocksize) {
				backup_real_size += blocksize;
			}
			if (backup_total_size > 0) {
				print_progress(backup_real_size, backup_total_size);
			}
			if (quit_flag)
				break;
			nlen = 0;
			mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &r);
			nlen = be32toh(nlen);
			if (nlen > 0) {
				last_code = code;
				mobilebackup2_receive_raw(mobilebackup2, &code, 1, &r);
			} else {
				break;
			}
		}
		if (f) {
			fclose(f);
			file_count++;
		} else {
			errcode = errno_to_device_error(errno);
			errdesc = strerror(errno);
			printf("Error opening '%s' for writing: %s\n", bname, errdesc);
			break;
		}
		if (nlen == 0) {
			break;
		}

		/* check if an error message was received */
		if (code == CODE_ERROR_REMOTE) {
			/* error message */
			char *msg = (char*)malloc(nlen);
			mobilebackup2_receive_raw(mobilebackup2, msg, nlen-1, &r);
			msg[r] = 0;
			/* If sent using CODE_FILE_DATA, end marker will be CODE_ERROR_REMOTE which is not an error! */
			if (last_code != CODE_FILE_DATA) {
				fprintf(stdout, "\nReceived an error message from device: %s\n", msg);
			}
			free(msg);
		}
	} while (1);

	if (fname != NULL)
		free(fname);

	/* if there are leftovers to read, finish up cleanly */
	if ((int)nlen-1 > 0) {
		PRINT_VERBOSE(1, "\nDiscarding current data hunk.\n");
		fname = (char*)malloc(nlen-1);
		mobilebackup2_receive_raw(mobilebackup2, fname, nlen-1, &r);
		free(fname);
		remove_file(bname);
	}

	/* clean up */
	if (bname != NULL)
		free(bname);

	if (dname != NULL)
		free(dname);

	plist_t empty_plist = plist_new_dict();
	mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, empty_plist);
	plist_free(empty_plist);

	return file_count;
}

static void mb2_handle_list_directory(mobilebackup2_client_t mobilebackup2, plist_t message, const char *backup_dir)
{
	if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || plist_array_get_size(message) < 2 || !backup_dir) return;

	plist_t node = plist_array_get_item(message, 1);
	char *str = NULL;
	if (plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, &str);
	}
	if (!str) {
		printf("ERROR: Malformed DLContentsOfDirectory message\n");
		// TODO error handling
		return;
	}

	char *path = string_build_path(backup_dir, str, NULL);
	free(str);

	plist_t dirlist = plist_new_dict();

	DIR* cur_dir = opendir(path);
	if (cur_dir) {
		struct dirent* ep;
		while ((ep = readdir(cur_dir))) {
			if ((strcmp(ep->d_name, ".") == 0) || (strcmp(ep->d_name, "..") == 0)) {
				continue;
			}
			char *fpath = string_build_path(path, ep->d_name, NULL);
			if (fpath) {
				plist_t fdict = plist_new_dict();
				struct stat st;
				stat(fpath, &st);
				const char *ftype = "DLFileTypeUnknown";
				if (S_ISDIR(st.st_mode)) {
					ftype = "DLFileTypeDirectory";
				} else if (S_ISREG(st.st_mode)) {
					ftype = "DLFileTypeRegular";
				}
				plist_dict_set_item(fdict, "DLFileType", plist_new_string(ftype));
				plist_dict_set_item(fdict, "DLFileSize", plist_new_uint(st.st_size));
				plist_dict_set_item(fdict, "DLFileModificationDate",
						    plist_new_date(st.st_mtime - MAC_EPOCH, 0));

				plist_dict_set_item(dirlist, ep->d_name, fdict);
				free(fpath);
			}
		}
		closedir(cur_dir);
	}
	free(path);

	/* TODO error handling */
	mobilebackup2_error_t err = mobilebackup2_send_status_response(mobilebackup2, 0, NULL, dirlist);
	plist_free(dirlist);
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		printf("Could not send status response, error %d\n", err);
	}
}

static void mb2_handle_make_directory(mobilebackup2_client_t mobilebackup2, plist_t message, const char *backup_dir)
{
	if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || plist_array_get_size(message) < 2 || !backup_dir) return;

	plist_t dir = plist_array_get_item(message, 1);
	char *str = NULL;
	int errcode = 0;
	char *errdesc = NULL;
	plist_get_string_val(dir, &str);

	char *newpath = string_build_path(backup_dir, str, NULL);
	free(str);

	if (mkdir_with_parents(newpath, 0755) < 0) {
		errdesc = strerror(errno);
		if (errno != EEXIST) {
			printf("mkdir: %s (%d)\n", errdesc, errno);
		}
		errcode = errno_to_device_error(errno);
	}
	free(newpath);
	mobilebackup2_error_t err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, NULL);
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		printf("Could not send status response, error %d\n", err);
	}
}

static void mb2_copy_file_by_path(const char *src, const char *dst)
{
	FILE *from, *to;
	char buf[BUFSIZ];
	size_t length;

	/* open source file */
	if ((from = fopen(src, "rb")) == NULL) {
		printf("Cannot open source path '%s'.\n", src);
		return;
	}

	/* open destination file */
	if ((to = fopen(dst, "wb")) == NULL) {
		printf("Cannot open destination file '%s'.\n", dst);
		fclose(from);
		return;
	}

	/* copy the file */
	while ((length = fread(buf, 1, BUFSIZ, from)) != 0) {
		fwrite(buf, 1, length, to);
	}

	if(fclose(from) == EOF) {
		printf("Error closing source file.\n");
	}

	if(fclose(to) == EOF) {
		printf("Error closing destination file.\n");
	}
}

static void mb2_copy_directory_by_path(const char *src, const char *dst)
{
	if (!src || !dst) {
		return;
	}

	struct stat st;

	/* if src does not exist */
	if ((stat(src, &st) < 0) || !S_ISDIR(st.st_mode)) {
		printf("ERROR: Source directory does not exist '%s': %s (%d)\n", src, strerror(errno), errno);
		return;
	}

	/* if dst directory does not exist */
	if ((stat(dst, &st) < 0) || !S_ISDIR(st.st_mode)) {
		/* create it */
		if (mkdir_with_parents(dst, 0755) < 0) {
			printf("ERROR: Unable to create destination directory '%s': %s (%d)\n", dst, strerror(errno), errno);
			return;
		}
	}

	/* loop over src directory contents */
	DIR *cur_dir = opendir(src);
	if (cur_dir) {
		struct dirent* ep;
		while ((ep = readdir(cur_dir))) {
			if ((strcmp(ep->d_name, ".") == 0) || (strcmp(ep->d_name, "..") == 0)) {
				continue;
			}
			char *srcpath = string_build_path(src, ep->d_name, NULL);
			char *dstpath = string_build_path(dst, ep->d_name, NULL);
			if (srcpath && dstpath) {
				/* copy file */
				mb2_copy_file_by_path(srcpath, dstpath);
			}

			if (srcpath)
				free(srcpath);
			if (dstpath)
				free(dstpath);
		}
		closedir(cur_dir);
	}
}

#ifdef _WIN32
#define BS_CC '\b'
#define my_getch getch
#else
#define BS_CC 0x7f
static int my_getch(void)
{
	struct termios oldt, newt;
	int ch;
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return ch;
}
#endif

static void get_hidden_input(char *buf, int maxlen)
{
	int pwlen = 0;
	int c;

	while ((c = my_getch())) {
		if ((c == '\r') || (c == '\n')) {
			break;
		}
		if (isprint(c)) {
			if (pwlen < maxlen-1)
				buf[pwlen++] = c;
			fputc('*', stderr);
		} else if (c == BS_CC) {
			if (pwlen > 0) {
				fputs("\b \b", stderr);
				pwlen--;
			}
		}
	}
	buf[pwlen] = 0;
}

static char* ask_for_password(const char* msg, int type_again)
{
	char pwbuf[256];

	fprintf(stderr, "%s: ", msg);
	fflush(stderr);
	get_hidden_input(pwbuf, 256);
	fputc('\n', stderr);

	if (type_again) {
		char pwrep[256];

		fprintf(stderr, "%s (repeat): ", msg);
		fflush(stderr);
		get_hidden_input(pwrep, 256);
		fputc('\n', stderr);

		if (strcmp(pwbuf, pwrep) != 0) {
			printf("ERROR: passwords don't match\n");
			return NULL;
		}
	}
	return strdup(pwbuf);
}

/**
 * signal handler function for cleaning up properly
 */
static void clean_exit(int sig)
{
	fprintf(stderr, "Exiting...\n");
	quit_flag++;
}

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] CMD [CMDOPTIONS] DIRECTORY\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Create or restore backup in/from the specified directory.\n"
		"\n"
		"CMD:\n"
		"  backup        create backup for the device\n"
		"    --full              force full backup from device.\n"
		"  restore       restore last backup to the device\n"
		"    --system            restore system files, too.\n"
		"    --no-reboot         do NOT reboot the device when done (default: yes).\n"
		"    --copy              create a copy of backup folder before restoring.\n"
		"    --settings          restore device settings from the backup.\n"
		"    --remove            remove items which are not being restored\n"
		"    --skip-apps         do not trigger re-installation of apps after restore\n"
		"    --password PWD      supply the password for the encrypted source backup\n"
		"  info          show details about last completed backup of device\n"
		"  list          list files of last completed backup in CSV format\n"
		"  unback        unpack a completed backup in DIRECTORY/_unback_/\n"
		"  encryption on|off [PWD]       enable or disable backup encryption\n"
		"  changepw [OLD NEW]    change backup password on target device\n"
		"  cloud on|off          enable or disable cloud use (requires iCloud account)\n"
		"\n"
		"NOTE: Passwords will be requested in interactive mode (-i) if omitted, or can\n"
		"be passed via environment variable BACKUP_PASSWORD/BACKUP_PASSWORD_NEW.\n"
		"See man page for further details.\n"
		"\n"
		"OPTIONS:\n"
		"  -u, --udid UDID       target specific device by UDID\n"
		"  -s, --source UDID     use backup data from device specified by UDID\n"
		"  -n, --network         connect to network device\n"
		"  -i, --interactive     request passwords interactively\n"
		"  -d, --debug           enable communication debugging\n"
		"  -h, --help            prints usage information\n"
		"  -v, --version         prints version information\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

#define DEVICE_VERSION(maj, min, patch) ((((maj) & 0xFF) << 16) | (((min) & 0xFF) << 8) | ((patch) & 0xFF))

int main(int argc, char *argv[])
{
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
	int i = 0;
	char* udid = NULL;
	char* source_udid = NULL;
	int use_network = 0;
	lockdownd_service_descriptor_t service = NULL;
	int cmd = -1;
	int cmd_flags = 0;
	int is_full_backup = 0;
	int result_code = -1;
	char* backup_directory = NULL;
	int interactive_mode = 0;
	char* backup_password = NULL;
	char* newpw = NULL;
	struct stat st;
	plist_t node_tmp = NULL;
	plist_t info_plist = NULL;
	plist_t opts = NULL;

	idevice_t device = NULL;
	afc_client_t afc = NULL;
	np_client_t np = NULL;
	lockdownd_client_t lockdown = NULL;
	mobilebackup2_client_t mobilebackup2 = NULL;
	mobilebackup2_error_t err;
	uint64_t lockfile = 0;

#define OPT_SYSTEM 1
#define OPT_REBOOT 2
#define OPT_NO_REBOOT 3
#define OPT_COPY 4
#define OPT_SETTINGS 5
#define OPT_REMOVE 6
#define OPT_SKIP_APPS 7
#define OPT_PASSWORD 8
#define OPT_FULL 9

	int c = 0;
	const struct option longopts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "udid", required_argument, NULL, 'u' },
		{ "source", required_argument, NULL, 's' },
		{ "interactive", no_argument, NULL, 'i' },
		{ "network", no_argument, NULL, 'n' },
		{ "version", no_argument, NULL, 'v' },
		// command options:
		{ "system", no_argument, NULL, OPT_SYSTEM },
		{ "reboot", no_argument, NULL, OPT_REBOOT },
		{ "no-reboot", no_argument, NULL, OPT_NO_REBOOT },
		{ "copy", no_argument, NULL, OPT_COPY },
		{ "settings", no_argument, NULL, OPT_SETTINGS },
		{ "remove", no_argument, NULL, OPT_REMOVE },
		{ "skip-apps", no_argument, NULL, OPT_SKIP_APPS },
		{ "password", required_argument, NULL, OPT_PASSWORD },
		{ "full", no_argument, NULL, OPT_FULL },
		{ NULL, 0, NULL, 0}
	};

	/* we need to exit cleanly on running backups and restores or we cause havok */
	signal(SIGINT, clean_exit);
	signal(SIGTERM, clean_exit);
#ifndef _WIN32
	signal(SIGQUIT, clean_exit);
	signal(SIGPIPE, SIG_IGN);
#endif

	/* parse cmdline args */
	while ((c = getopt_long(argc, argv, "dhu:s:inv", longopts, NULL)) != -1) {
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
			udid = strdup(optarg);
			break;
		case 's':
			if (!*optarg) {
				fprintf(stderr, "ERROR: SOURCE argument must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			}
			source_udid = strdup(optarg);
			break;
		case 'i':
			interactive_mode = 1;
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
		case OPT_SYSTEM:
			cmd_flags |= CMD_FLAG_RESTORE_SYSTEM_FILES;
			break;
		case OPT_REBOOT:
			cmd_flags &= ~CMD_FLAG_RESTORE_NO_REBOOT;
			break;
		case OPT_NO_REBOOT:
			cmd_flags |= CMD_FLAG_RESTORE_NO_REBOOT;
			break;
		case OPT_COPY:
			cmd_flags |= CMD_FLAG_RESTORE_COPY_BACKUP;
			break;
		case OPT_SETTINGS:
			cmd_flags |= CMD_FLAG_RESTORE_SETTINGS;
			break;
		case OPT_REMOVE:
			cmd_flags |= CMD_FLAG_RESTORE_REMOVE_ITEMS;
			break;
		case OPT_SKIP_APPS:
			cmd_flags |= CMD_FLAG_RESTORE_SKIP_APPS;
			break;
		case OPT_PASSWORD:
			free(backup_password);
			backup_password = strdup(optarg);
			break;
		case OPT_FULL:
			cmd_flags |= CMD_FLAG_FORCE_FULL_BACKUP;
			break;
		default:
			print_usage(argc, argv, 1);
			return 2;
		}
	}
	argc -= optind;
	argv += optind;

	if (!argv[0]) {
		fprintf(stderr, "ERROR: No command specified.\n");
		print_usage(argc+optind, argv-optind, 1);
		return 2;
	}

	if (!strcmp(argv[0], "backup")) {
		cmd = CMD_BACKUP;
	}
	else if (!strcmp(argv[0], "restore")) {
		cmd = CMD_RESTORE;
	}
	else if (!strcmp(argv[0], "cloud")) {
		cmd = CMD_CLOUD;
		i = 1;
		if (!argv[i]) {
			fprintf(stderr, "ERROR: No argument given for cloud command; requires either 'on' or 'off'.\n");
			print_usage(argc+optind, argv-optind, 1);
			return 2;
		}
		if (!strcmp(argv[i], "on")) {
			cmd_flags |= CMD_FLAG_CLOUD_ENABLE;
		} else if (!strcmp(argv[i], "off")) {
			cmd_flags |= CMD_FLAG_CLOUD_DISABLE;
		} else {
			fprintf(stderr, "ERROR: Invalid argument '%s' for cloud command; must be either 'on' or 'off'.\n", argv[i]);
			print_usage(argc+optind, argv-optind, 1);
			return 2;
		}
	}
	else if (!strcmp(argv[0], "info")) {
		cmd = CMD_INFO;
		verbose = 0;
	}
	else if (!strcmp(argv[0], "list")) {
		cmd = CMD_LIST;
		verbose = 0;
	}
	else if (!strcmp(argv[0], "unback")) {
		cmd = CMD_UNBACK;
	}
	else if (!strcmp(argv[0], "encryption")) {
		cmd = CMD_CHANGEPW;
		i = 1;
		if (!argv[i]) {
			fprintf(stderr, "ERROR: No argument given for encryption command; requires either 'on' or 'off'.\n");
			print_usage(argc+optind, argv-optind, 1);
			return 2;
		}
		if (!strcmp(argv[i], "on")) {
			cmd_flags |= CMD_FLAG_ENCRYPTION_ENABLE;
		} else if (!strcmp(argv[i], "off")) {
			cmd_flags |= CMD_FLAG_ENCRYPTION_DISABLE;
		} else {
			fprintf(stderr, "ERROR: Invalid argument '%s' for encryption command; must be either 'on' or 'off'.\n", argv[i]);
			print_usage(argc+optind, argv-optind, 1);
			return 2;
		}
		// check if a password was given on the command line
		free(newpw);
		newpw = NULL;
		free(backup_password);
		backup_password = NULL;
		i++;
		if (argv[i]) {
			if (cmd_flags & CMD_FLAG_ENCRYPTION_ENABLE) {
				newpw = strdup(argv[i]);
			} else if (cmd_flags & CMD_FLAG_ENCRYPTION_DISABLE) {
				backup_password = strdup(argv[i]);
			}
		}
	}
	else if (!strcmp(argv[0], "changepw")) {
		cmd = CMD_CHANGEPW;
		cmd_flags |= CMD_FLAG_ENCRYPTION_CHANGEPW;
		// check if passwords were given on command line
		free(newpw);
		newpw = NULL;
		free(backup_password);
		backup_password = NULL;
		i = 1;
		if (argv[i]) {
			backup_password = strdup(argv[i]);
			i++;
			if (!argv[i]) {
				fprintf(stderr, "ERROR: Old and new passwords have to be passed as arguments for the changepw command\n");
				print_usage(argc+optind, argv-optind, 1);
				return 2;
			}
			newpw = strdup(argv[i]);
		}
	}

	i++;
	if (argv[i]) {
		backup_directory = argv[i];
	}

	/* verify options */
	if (cmd == -1) {
		fprintf(stderr, "ERROR: Unsupported command '%s'.\n", argv[0]);
		print_usage(argc+optind, argv-optind, 1);
		return 2;
	}

	if (cmd == CMD_CHANGEPW || cmd == CMD_CLOUD) {
		backup_directory = (char*)".this_folder_is_not_present_on_purpose";
	} else {
		if (backup_directory == NULL) {
			fprintf(stderr, "ERROR: No target backup directory specified.\n");
			print_usage(argc+optind, argv-optind, 1);
			return 2;
		}

		/* verify if passed backup directory exists */
		if (stat(backup_directory, &st) != 0) {
			fprintf(stderr, "ERROR: Backup directory \"%s\" does not exist!\n", backup_directory);
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

	if (!udid) {
		idevice_get_udid(device, &udid);
	}

	if (!source_udid) {
		source_udid = strdup(udid);
	}

	uint8_t is_encrypted = 0;
	char *info_path = NULL;
	if (cmd == CMD_CHANGEPW) {
		if (!interactive_mode) {
			if (!newpw) {
				newpw = getenv("BACKUP_PASSWORD_NEW");
				if (newpw) {
					newpw = strdup(newpw);
				}
			}
			if (!backup_password) {
				backup_password = getenv("BACKUP_PASSWORD");
				if (backup_password) {
					backup_password = strdup(backup_password);
				}
			}
		}
		if (!interactive_mode && !backup_password && !newpw) {
			idevice_free(device);
			printf("ERROR: Can't get password input in non-interactive mode. Either pass password(s) on the command line, or enable interactive mode with -i or --interactive.\n");
			return -1;
		}
	} else if (cmd != CMD_CLOUD) {
		/* backup directory must contain an Info.plist */
		info_path = string_build_path(backup_directory, source_udid, "Info.plist", NULL);
		if (cmd == CMD_RESTORE || cmd == CMD_UNBACK) {
			if (stat(info_path, &st) != 0) {
				idevice_free(device);
				free(info_path);
				printf("ERROR: Backup directory \"%s\" is invalid. No Info.plist found for UDID %s.\n", backup_directory, source_udid);
				return -1;
			}
			char* manifest_path = string_build_path(backup_directory, source_udid, "Manifest.plist", NULL);
			if (stat(manifest_path, &st) != 0) {
				free(info_path);
			}
			plist_t manifest_plist = NULL;
			plist_read_from_file(manifest_path, &manifest_plist, NULL);
			if (!manifest_plist) {
				idevice_free(device);
				free(info_path);
				free(manifest_path);
				printf("ERROR: Backup directory \"%s\" is invalid. No Manifest.plist found for UDID %s.\n", backup_directory, source_udid);
				return -1;
			}
			node_tmp = plist_dict_get_item(manifest_plist, "IsEncrypted");
			if (node_tmp && (plist_get_node_type(node_tmp) == PLIST_BOOLEAN)) {
				plist_get_bool_val(node_tmp, &is_encrypted);
			}
			plist_free(manifest_plist);
			free(manifest_path);
		}
		PRINT_VERBOSE(1, "Backup directory is \"%s\"\n", backup_directory);
	}

	if (cmd != CMD_CLOUD && is_encrypted) {
		PRINT_VERBOSE(1, "This is an encrypted backup.\n");
		if (backup_password == NULL) {
			backup_password = getenv("BACKUP_PASSWORD");
			if (backup_password) {
				backup_password = strdup(backup_password);
			}
		}
		if (backup_password == NULL) {
			if (interactive_mode) {
				backup_password = ask_for_password("Enter backup password", 0);
			}
			if (!backup_password || (strlen(backup_password) == 0)) {
				if (backup_password) {
					free(backup_password);
				}
				idevice_free(device);
				if (cmd == CMD_RESTORE) {
					printf("ERROR: a backup password is required to restore an encrypted backup. Cannot continue.\n");
				} else if (cmd == CMD_UNBACK) {
					printf("ERROR: a backup password is required to unback an encrypted backup. Cannot continue.\n");
				}
				return -1;
			}
		}
	}

	if (LOCKDOWN_E_SUCCESS != (ldret = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME))) {
		printf("ERROR: Could not connect to lockdownd, error code %d\n", ldret);
		idevice_free(device);
		return -1;
	}

	uint8_t willEncrypt = 0;
	node_tmp = NULL;
	lockdownd_get_value(lockdown, "com.apple.mobile.backup", "WillEncrypt", &node_tmp);
	if (node_tmp) {
		if (plist_get_node_type(node_tmp) == PLIST_BOOLEAN) {
			plist_get_bool_val(node_tmp, &willEncrypt);
		}
		plist_free(node_tmp);
		node_tmp = NULL;
	}

	/* get ProductVersion */
	char *product_version = NULL;
	int device_version = 0;
	node_tmp = NULL;
	lockdownd_get_value(lockdown, NULL, "ProductVersion", &node_tmp);
	if (node_tmp) {
		if (plist_get_node_type(node_tmp) == PLIST_STRING) {
			plist_get_string_val(node_tmp, &product_version);
		}
		plist_free(node_tmp);
		node_tmp = NULL;
	}
	if (product_version) {
		int vers[3] = { 0, 0, 0 };
		if (sscanf(product_version, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
			device_version = DEVICE_VERSION(vers[0], vers[1], vers[2]);
		}
	}

	/* start notification_proxy */
	ldret = lockdownd_start_service(lockdown, NP_SERVICE_NAME, &service);
	if ((ldret == LOCKDOWN_E_SUCCESS) && service && service->port) {
		np_client_new(device, service, &np);
		np_set_notify_callback(np, notify_cb, NULL);
		const char *noties[7] = {
			NP_SYNC_CANCEL_REQUEST,
			NP_SYNC_SUSPEND_REQUEST,
			NP_SYNC_RESUME_REQUEST,
			NP_BACKUP_DOMAIN_CHANGED,
			"com.apple.LocalAuthentication.ui.presented",
			"com.apple.LocalAuthentication.ui.dismissed",
			NULL
		};
		np_observe_notifications(np, noties);
	} else {
		printf("ERROR: Could not start service %s: %s\n", NP_SERVICE_NAME, lockdownd_strerror(ldret));
		cmd = CMD_LEAVE;
		goto checkpoint;
	}
	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

	if (cmd == CMD_BACKUP || cmd == CMD_RESTORE) {
		/* start AFC, we need this for the lock file */
		ldret = lockdownd_start_service(lockdown, AFC_SERVICE_NAME, &service);
		if ((ldret == LOCKDOWN_E_SUCCESS) && service->port) {
			afc_client_new(device, service, &afc);
		} else {
			printf("ERROR: Could not start service %s: %s\n", AFC_SERVICE_NAME, lockdownd_strerror(ldret));
			cmd = CMD_LEAVE;
			goto checkpoint;
		}
	}

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

	/* start mobilebackup service and retrieve port */
	ldret = lockdownd_start_service_with_escrow_bag(lockdown, MOBILEBACKUP2_SERVICE_NAME, &service);
	lockdownd_client_free(lockdown);
	lockdown = NULL;
	if ((ldret == LOCKDOWN_E_SUCCESS) && service && service->port) {
		PRINT_VERBOSE(1, "Started \"%s\" service on port %d.\n", MOBILEBACKUP2_SERVICE_NAME, service->port);
		mobilebackup2_client_new(device, service, &mobilebackup2);

		if (service) {
			lockdownd_service_descriptor_free(service);
			service = NULL;
		}

		/* send Hello message */
		double local_versions[2] = {2.0, 2.1};
		double remote_version = 0.0;
		err = mobilebackup2_version_exchange(mobilebackup2, local_versions, 2, &remote_version);
		if (err != MOBILEBACKUP2_E_SUCCESS) {
			printf("Could not perform backup protocol version exchange, error code %d\n", err);
			cmd = CMD_LEAVE;
			goto checkpoint;
		}

		PRINT_VERBOSE(1, "Negotiated Protocol Version %.1f\n", remote_version);

		/* check abort conditions */
		if (quit_flag > 0) {
			PRINT_VERBOSE(1, "Aborting as requested by user...\n");
			cmd = CMD_LEAVE;
			goto checkpoint;
		}

		/* verify existing Info.plist */
		if (info_path && (stat(info_path, &st) == 0) && cmd != CMD_CLOUD) {
			PRINT_VERBOSE(1, "Reading Info.plist from backup.\n");
			plist_read_from_file(info_path, &info_plist, NULL);

			if (!info_plist) {
				printf("Could not read Info.plist\n");
				is_full_backup = 1;
			}
		} else {
			if (cmd == CMD_RESTORE) {
				printf("Aborting restore. Info.plist is missing.\n");
				cmd = CMD_LEAVE;
			} else {
				is_full_backup = 1;
			}
		}

		if (cmd == CMD_BACKUP || cmd == CMD_RESTORE) {
			do_post_notification(device, NP_SYNC_WILL_START);
			afc_file_open(afc, "/com.apple.itunes.lock_sync", AFC_FOPEN_RW, &lockfile);
		}
		if (lockfile) {
			afc_error_t aerr;
			do_post_notification(device, NP_SYNC_LOCK_REQUEST);
			for (i = 0; i < LOCK_ATTEMPTS; i++) {
				aerr = afc_file_lock(afc, lockfile, AFC_LOCK_EX);
				if (aerr == AFC_E_SUCCESS) {
					do_post_notification(device, NP_SYNC_DID_START);
					break;
				}
				if (aerr == AFC_E_OP_WOULD_BLOCK) {
					usleep(LOCK_WAIT);
					continue;
				}

				fprintf(stderr, "ERROR: could not lock file! error code: %d\n", aerr);
				afc_file_close(afc, lockfile);
				lockfile = 0;
				cmd = CMD_LEAVE;
			}
			if (i == LOCK_ATTEMPTS) {
				fprintf(stderr, "ERROR: timeout while locking for sync\n");
				afc_file_close(afc, lockfile);
				lockfile = 0;
				cmd = CMD_LEAVE;
			}
		}

checkpoint:

		switch(cmd) {
			case CMD_CLOUD:
			opts = plist_new_dict();
			plist_dict_set_item(opts, "CloudBackupState", plist_new_bool(cmd_flags & CMD_FLAG_CLOUD_ENABLE ? 1: 0));
			err = mobilebackup2_send_request(mobilebackup2, "EnableCloudBackup", udid, source_udid, opts);
			plist_free(opts);
			opts = NULL;
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				printf("Error setting cloud backup state on device, error code %d\n", err);
				cmd = CMD_LEAVE;
			}
			break;
			case CMD_BACKUP:
			PRINT_VERBOSE(1, "Starting backup...\n");

			/* make sure backup device sub-directory exists */
			char* devbackupdir = string_build_path(backup_directory, source_udid, NULL);
			__mkdir(devbackupdir, 0755);
			free(devbackupdir);

			if (strcmp(source_udid, udid) != 0) {
				/* handle different source backup directory */
				// make sure target backup device sub-directory exists
				devbackupdir = string_build_path(backup_directory, udid, NULL);
				__mkdir(devbackupdir, 0755);
				free(devbackupdir);

				// use Info.plist path in target backup folder */
				free(info_path);
				info_path = string_build_path(backup_directory, udid, "Info.plist", NULL);
			}

			/* TODO: check domain com.apple.mobile.backup key RequiresEncrypt and WillEncrypt with lockdown */
			/* TODO: verify battery on AC enough battery remaining */

			/* re-create Info.plist (Device infos, IC-Info.sidb, photos, app_ids, iTunesPrefs) */
			if (info_plist) {
				plist_free(info_plist);
				info_plist = NULL;
			}
			info_plist = mobilebackup_factory_info_plist_new(udid, device, afc);
			if (!info_plist) {
				fprintf(stderr, "Failed to generate Info.plist - aborting\n");
				cmd = CMD_LEAVE;
			}
			remove_file(info_path);
			plist_write_to_file(info_plist, info_path, PLIST_FORMAT_XML, 0);
			free(info_path);

			plist_free(info_plist);
			info_plist = NULL;

			if (cmd_flags & CMD_FLAG_FORCE_FULL_BACKUP) {
				PRINT_VERBOSE(1, "Enforcing full backup from device.\n");
				opts = plist_new_dict();
				plist_dict_set_item(opts, "ForceFullBackup", plist_new_bool(1));
			}
			/* request backup from device with manifest from last backup */
			if (willEncrypt) {
				PRINT_VERBOSE(1, "Backup will be encrypted.\n");
			} else {
				PRINT_VERBOSE(1, "Backup will be unencrypted.\n");
			}
			PRINT_VERBOSE(1, "Requesting backup from device...\n");
			err = mobilebackup2_send_request(mobilebackup2, "Backup", udid, source_udid, opts);
			if (opts)
				plist_free(opts);
			if (err == MOBILEBACKUP2_E_SUCCESS) {
				if (is_full_backup) {
					PRINT_VERBOSE(1, "Full backup mode.\n");
				}	else {
					PRINT_VERBOSE(1, "Incremental backup mode.\n");
				}
				if (device_version >= DEVICE_VERSION(16,1,0)) {
					/* let's wait 2 second to see if the device passcode is requested */
					int retries = 20;
					while (retries-- > 0 && !passcode_requested) {
						usleep(100000);
					}
					if (passcode_requested) {
						printf("*** Waiting for passcode to be entered on the device ***\n");
					}
				}
			} else {
				if (err == MOBILEBACKUP2_E_BAD_VERSION) {
					printf("ERROR: Could not start backup process: backup protocol version mismatch!\n");
				} else if (err == MOBILEBACKUP2_E_REPLY_NOT_OK) {
					printf("ERROR: Could not start backup process: device refused to start the backup process.\n");
				} else {
					printf("ERROR: Could not start backup process: unspecified error occurred\n");
				}
				cmd = CMD_LEAVE;
			}
			break;
			case CMD_RESTORE:
			/* TODO: verify battery on AC enough battery remaining */

			/* verify if Status.plist says we read from an successful backup */
			if (!mb2_status_check_snapshot_state(backup_directory, source_udid, "finished")) {
				printf("ERROR: Cannot ensure we restore from a successful backup. Aborting.\n");
				cmd = CMD_LEAVE;
				break;
			}

			PRINT_VERBOSE(1, "Starting Restore...\n");

			opts = plist_new_dict();
			plist_dict_set_item(opts, "RestoreSystemFiles", plist_new_bool(cmd_flags & CMD_FLAG_RESTORE_SYSTEM_FILES));
			PRINT_VERBOSE(1, "Restoring system files: %s\n", (cmd_flags & CMD_FLAG_RESTORE_SYSTEM_FILES ? "Yes":"No"));
			if (cmd_flags & CMD_FLAG_RESTORE_NO_REBOOT)
				plist_dict_set_item(opts, "RestoreShouldReboot", plist_new_bool(0));
			PRINT_VERBOSE(1, "Rebooting after restore: %s\n", (cmd_flags & CMD_FLAG_RESTORE_NO_REBOOT ? "No":"Yes"));
			if ((cmd_flags & CMD_FLAG_RESTORE_COPY_BACKUP) == 0)
				plist_dict_set_item(opts, "RestoreDontCopyBackup", plist_new_bool(1));
			PRINT_VERBOSE(1, "Don't copy backup: %s\n", ((cmd_flags & CMD_FLAG_RESTORE_COPY_BACKUP) == 0 ? "Yes":"No"));
			plist_dict_set_item(opts, "RestorePreserveSettings", plist_new_bool((cmd_flags & CMD_FLAG_RESTORE_SETTINGS) == 0));
			PRINT_VERBOSE(1, "Preserve settings of device: %s\n", ((cmd_flags & CMD_FLAG_RESTORE_SETTINGS) == 0 ? "Yes":"No"));
			plist_dict_set_item(opts, "RemoveItemsNotRestored", plist_new_bool(cmd_flags & CMD_FLAG_RESTORE_REMOVE_ITEMS));
			PRINT_VERBOSE(1, "Remove items that are not restored: %s\n", ((cmd_flags & CMD_FLAG_RESTORE_REMOVE_ITEMS) ? "Yes":"No"));
			if (backup_password != NULL) {
				plist_dict_set_item(opts, "Password", plist_new_string(backup_password));
			}
			PRINT_VERBOSE(1, "Backup password: %s\n", (backup_password == NULL ? "No":"Yes"));

			if (cmd_flags & CMD_FLAG_RESTORE_SKIP_APPS) {
				PRINT_VERBOSE(1, "Not writing RestoreApplications.plist - apps will not be re-installed after restore\n");
			} else {
				/* Write /iTunesRestore/RestoreApplications.plist so that the device will start
				 * restoring applications once the rest of the restore process is finished */
				if (write_restore_applications(info_plist, afc) < 0) {
					cmd = CMD_LEAVE;
					break;
				}
				PRINT_VERBOSE(1, "Wrote RestoreApplications.plist\n");
			}

			/* Start restore */
			err = mobilebackup2_send_request(mobilebackup2, "Restore", udid, source_udid, opts);
			plist_free(opts);
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				if (err == MOBILEBACKUP2_E_BAD_VERSION) {
					printf("ERROR: Could not start restore process: backup protocol version mismatch!\n");
				} else if (err == MOBILEBACKUP2_E_REPLY_NOT_OK) {
					printf("ERROR: Could not start restore process: device refused to start the restore process.\n");
				} else {
					printf("ERROR: Could not start restore process: unspecified error occurred\n");
				}
				cmd = CMD_LEAVE;
			}
			break;
			case CMD_INFO:
			PRINT_VERBOSE(1, "Requesting backup info from device...\n");
			err = mobilebackup2_send_request(mobilebackup2, "Info", udid, source_udid, NULL);
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				printf("Error requesting backup info from device, error code %d\n", err);
				cmd = CMD_LEAVE;
			}
			break;
			case CMD_LIST:
			PRINT_VERBOSE(1, "Requesting backup list from device...\n");
			err = mobilebackup2_send_request(mobilebackup2, "List", udid, source_udid, NULL);
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				printf("Error requesting backup list from device, error code %d\n", err);
				cmd = CMD_LEAVE;
			}
			break;
			case CMD_UNBACK:
			PRINT_VERBOSE(1, "Starting to unpack backup...\n");
			if (backup_password != NULL) {
				opts = plist_new_dict();
				plist_dict_set_item(opts, "Password", plist_new_string(backup_password));
			}
			PRINT_VERBOSE(1, "Backup password: %s\n", (backup_password == NULL ? "No":"Yes"));
			err = mobilebackup2_send_request(mobilebackup2, "Unback", udid, source_udid, opts);
			if (backup_password !=NULL) {
				plist_free(opts);
			}
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				printf("Error requesting unback operation from device, error code %d\n", err);
				cmd = CMD_LEAVE;
			}
			break;
			case CMD_CHANGEPW:
			opts = plist_new_dict();
			plist_dict_set_item(opts, "TargetIdentifier", plist_new_string(udid));
			if (cmd_flags & CMD_FLAG_ENCRYPTION_ENABLE) {
				if (!willEncrypt) {
					if (!newpw) {
						newpw = getenv("BACKUP_PASSWORD");
						if (newpw) {
							newpw = strdup(newpw);
						}
					}
					if (!newpw) {
						newpw = ask_for_password("Enter new backup password", 1);
					}
					if (!newpw) {
						printf("No backup password given. Aborting.\n");
					}
				} else {
					printf("ERROR: Backup encryption is already enabled. Aborting.\n");
					cmd = CMD_LEAVE;
					if (newpw) {
						free(newpw);
						newpw = NULL;
					}
				}
			} else if (cmd_flags & CMD_FLAG_ENCRYPTION_DISABLE) {
				if (willEncrypt) {
					if (!backup_password) {
						backup_password = getenv("BACKUP_PASSWORD");
						if (backup_password) {
							backup_password = strdup(backup_password);
						}
					}
					if (!backup_password) {
						backup_password = ask_for_password("Enter current backup password", 0);
					}
				} else {
					printf("ERROR: Backup encryption is not enabled. Aborting.\n");
					cmd = CMD_LEAVE;
					if (backup_password) {
						free(backup_password);
						backup_password = NULL;
					}
				}
			} else if (cmd_flags & CMD_FLAG_ENCRYPTION_CHANGEPW) {
				if (willEncrypt) {
					if (!backup_password) {
						backup_password = ask_for_password("Enter old backup password", 0);
						newpw = ask_for_password("Enter new backup password", 1);
					}
				} else {
					printf("ERROR: Backup encryption is not enabled so can't change password. Aborting.\n");
					cmd = CMD_LEAVE;
					if (newpw) {
						free(newpw);
						newpw = NULL;
					}
					if (backup_password) {
						free(backup_password);
						backup_password = NULL;
					}
				}
			}
			if (newpw) {
				plist_dict_set_item(opts, "NewPassword", plist_new_string(newpw));
			}
			if (backup_password) {
				plist_dict_set_item(opts, "OldPassword", plist_new_string(backup_password));
			}
			if (newpw || backup_password) {
				mobilebackup2_send_message(mobilebackup2, "ChangePassword", opts);
				uint8_t passcode_hint = 0;
				if (device_version >= DEVICE_VERSION(13,0,0)) {
					diagnostics_relay_client_t diag = NULL;
					if (diagnostics_relay_client_start_service(device, &diag, TOOL_NAME) == DIAGNOSTICS_RELAY_E_SUCCESS) {
						plist_t dict = NULL;
						plist_t keys = plist_new_array();
						plist_array_append_item(keys, plist_new_string("PasswordConfigured"));
						if (diagnostics_relay_query_mobilegestalt(diag, keys, &dict) == DIAGNOSTICS_RELAY_E_SUCCESS) {
							plist_t node = plist_access_path(dict, 2, "MobileGestalt", "PasswordConfigured");
							plist_get_bool_val(node, &passcode_hint);
						}
						plist_free(keys);
						plist_free(dict);
						diagnostics_relay_goodbye(diag);
						diagnostics_relay_client_free(diag);
					}
				}
				if (passcode_hint) {
					if (cmd_flags & CMD_FLAG_ENCRYPTION_CHANGEPW) {
						PRINT_VERBOSE(1, "Please confirm changing the backup password by entering the passcode on the device.\n");
					} else if (cmd_flags & CMD_FLAG_ENCRYPTION_ENABLE) {
						PRINT_VERBOSE(1, "Please confirm enabling the backup encryption by entering the passcode on the device.\n");
					} else if (cmd_flags & CMD_FLAG_ENCRYPTION_DISABLE) {
						PRINT_VERBOSE(1, "Please confirm disabling the backup encryption by entering the passcode on the device.\n");
					}
				}
				/*if (cmd_flags & CMD_FLAG_ENCRYPTION_ENABLE) {
					int retr = 10;
					while ((retr-- >= 0) && !backup_domain_changed) {
						sleep(1);
					}
				}*/
			} else {
				cmd = CMD_LEAVE;
			}
			plist_free(opts);
			break;
			default:
			break;
		}

		if (cmd != CMD_LEAVE) {
			/* reset operation success status */
			int operation_ok = 0;
			plist_t message = NULL;

			mobilebackup2_error_t mberr;
			char *dlmsg = NULL;
			int file_count = 0;
			int errcode = 0;
			const char *errdesc = NULL;
			int progress_finished = 0;

			/* process series of DLMessage* operations */
			do {
				free(dlmsg);
				dlmsg = NULL;
				mberr = mobilebackup2_receive_message(mobilebackup2, &message, &dlmsg);
				if (mberr == MOBILEBACKUP2_E_RECEIVE_TIMEOUT) {
					PRINT_VERBOSE(2, "Device is not ready yet, retrying...\n");
					goto files_out;
				} else if (mberr != MOBILEBACKUP2_E_SUCCESS) {
					PRINT_VERBOSE(0, "ERROR: Could not receive from mobilebackup2 (%d)\n", mberr);
					quit_flag++;
					goto files_out;
				}

				if (!strcmp(dlmsg, "DLMessageDownloadFiles")) {
					/* device wants to download files from the computer */
					mb2_set_overall_progress_from_message(message, dlmsg);
					mb2_handle_send_files(mobilebackup2, message, backup_directory);
				} else if (!strcmp(dlmsg, "DLMessageUploadFiles")) {
					/* device wants to send files to the computer */
					mb2_set_overall_progress_from_message(message, dlmsg);
					file_count += mb2_handle_receive_files(mobilebackup2, message, backup_directory);
				} else if (!strcmp(dlmsg, "DLMessageGetFreeDiskSpace")) {
					/* device wants to know how much disk space is available on the computer */
					uint64_t freespace = 0;
					int res = -1;
#ifdef _WIN32
					if (GetDiskFreeSpaceEx(backup_directory, (PULARGE_INTEGER)&freespace, NULL, NULL)) {
						res = 0;
					}
#else
					struct statvfs fs;
					memset(&fs, '\0', sizeof(fs));
					res = statvfs(backup_directory, &fs);
					if (res == 0) {
						freespace = (uint64_t)fs.f_bavail * (uint64_t)fs.f_frsize;
					}
#endif
					plist_t freespace_item = plist_new_uint(freespace);
					mobilebackup2_send_status_response(mobilebackup2, res, NULL, freespace_item);
					plist_free(freespace_item);
				} else if (!strcmp(dlmsg, "DLMessagePurgeDiskSpace")) {
					/* device wants to purge disk space on the host - not supported */
					plist_t empty_dict = plist_new_dict();
					err = mobilebackup2_send_status_response(mobilebackup2, -1, "Operation not supported", empty_dict);
					plist_free(empty_dict);
				} else if (!strcmp(dlmsg, "DLContentsOfDirectory")) {
					/* list directory contents */
					mb2_handle_list_directory(mobilebackup2, message, backup_directory);
				} else if (!strcmp(dlmsg, "DLMessageCreateDirectory")) {
					/* make a directory */
					mb2_handle_make_directory(mobilebackup2, message, backup_directory);
				} else if (!strcmp(dlmsg, "DLMessageMoveFiles") || !strcmp(dlmsg, "DLMessageMoveItems")) {
					/* perform a series of rename operations */
					mb2_set_overall_progress_from_message(message, dlmsg);
					plist_t moves = plist_array_get_item(message, 1);
					uint32_t cnt = plist_dict_get_size(moves);
					PRINT_VERBOSE(1, "Moving %d file%s\n", cnt, (cnt == 1) ? "" : "s");
					plist_dict_iter iter = NULL;
					plist_dict_new_iter(moves, &iter);
					errcode = 0;
					errdesc = NULL;
					if (iter) {
						char *key = NULL;
						plist_t val = NULL;
						do {
							plist_dict_next_item(moves, iter, &key, &val);
							if (key && (plist_get_node_type(val) == PLIST_STRING)) {
								char *str = NULL;
								plist_get_string_val(val, &str);
								if (str) {
									char *newpath = string_build_path(backup_directory, str, NULL);
									free(str);
									char *oldpath = string_build_path(backup_directory, key, NULL);

									if ((stat(newpath, &st) == 0) && S_ISDIR(st.st_mode))
										rmdir_recursive(newpath);
									else
										remove_file(newpath);
									if (rename(oldpath, newpath) < 0) {
										printf("Renameing '%s' to '%s' failed: %s (%d)\n", oldpath, newpath, strerror(errno), errno);
										errcode = errno_to_device_error(errno);
										errdesc = strerror(errno);
										break;
									}
									free(oldpath);
									free(newpath);
								}
								free(key);
								key = NULL;
							}
						} while (val);
						free(iter);
					} else {
						errcode = -1;
						errdesc = "Could not create dict iterator";
						printf("Could not create dict iterator\n");
					}
					plist_t empty_dict = plist_new_dict();
					err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, empty_dict);
					plist_free(empty_dict);
					if (err != MOBILEBACKUP2_E_SUCCESS) {
						printf("Could not send status response, error %d\n", err);
					}
				} else if (!strcmp(dlmsg, "DLMessageRemoveFiles") || !strcmp(dlmsg, "DLMessageRemoveItems")) {
					mb2_set_overall_progress_from_message(message, dlmsg);
					plist_t removes = plist_array_get_item(message, 1);
					uint32_t cnt = plist_array_get_size(removes);
					PRINT_VERBOSE(1, "Removing %d file%s\n", cnt, (cnt == 1) ? "" : "s");
					uint32_t ii = 0;
					errcode = 0;
					errdesc = NULL;
					for (ii = 0; ii < cnt; ii++) {
						plist_t val = plist_array_get_item(removes, ii);
						if (plist_get_node_type(val) == PLIST_STRING) {
							char *str = NULL;
							plist_get_string_val(val, &str);
							if (str) {
								const char *checkfile = strchr(str, '/');
								int suppress_warning = 0;
								if (checkfile) {
									if (strcmp(checkfile+1, "Manifest.mbdx") == 0) {
										suppress_warning = 1;
									}
								}
								char *newpath = string_build_path(backup_directory, str, NULL);
								free(str);
								int res = 0;
								if ((stat(newpath, &st) == 0) && S_ISDIR(st.st_mode)) {
									res = rmdir_recursive(newpath);
								} else {
									res = remove_file(newpath);
								}
								if (res != 0 && res != ENOENT) {
									if (!suppress_warning)
										printf("Could not remove '%s': %s (%d)\n", newpath, strerror(res), res);
									errcode = errno_to_device_error(res);
									errdesc = strerror(res);
								}
								free(newpath);
							}
						}
					}
					plist_t empty_dict = plist_new_dict();
					err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, empty_dict);
					plist_free(empty_dict);
					if (err != MOBILEBACKUP2_E_SUCCESS) {
						printf("Could not send status response, error %d\n", err);
					}
				} else if (!strcmp(dlmsg, "DLMessageCopyItem")) {
					plist_t srcpath = plist_array_get_item(message, 1);
					plist_t dstpath = plist_array_get_item(message, 2);
					errcode = 0;
					errdesc = NULL;
					if ((plist_get_node_type(srcpath) == PLIST_STRING) && (plist_get_node_type(dstpath) == PLIST_STRING)) {
						char *src = NULL;
						char *dst = NULL;
						plist_get_string_val(srcpath, &src);
						plist_get_string_val(dstpath, &dst);
						if (src && dst) {
							char *oldpath = string_build_path(backup_directory, src, NULL);
							char *newpath = string_build_path(backup_directory, dst, NULL);

							PRINT_VERBOSE(1, "Copying '%s' to '%s'\n", src, dst);

							/* check that src exists */
							if ((stat(oldpath, &st) == 0) && S_ISDIR(st.st_mode)) {
								mb2_copy_directory_by_path(oldpath, newpath);
							} else if ((stat(oldpath, &st) == 0) && S_ISREG(st.st_mode)) {
								mb2_copy_file_by_path(oldpath, newpath);
							}

							free(newpath);
							free(oldpath);
						}
						free(src);
						free(dst);
					}
					plist_t empty_dict = plist_new_dict();
					err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, empty_dict);
					plist_free(empty_dict);
					if (err != MOBILEBACKUP2_E_SUCCESS) {
						printf("Could not send status response, error %d\n", err);
					}
				} else if (!strcmp(dlmsg, "DLMessageDisconnect")) {
					break;
				} else if (!strcmp(dlmsg, "DLMessageProcessMessage")) {
					node_tmp = plist_array_get_item(message, 1);
					if (plist_get_node_type(node_tmp) != PLIST_DICT) {
						printf("Unknown message received!\n");
					}
					plist_t nn;
					int error_code = -1;
					nn = plist_dict_get_item(node_tmp, "ErrorCode");
					if (nn && (plist_get_node_type(nn) == PLIST_UINT)) {
						uint64_t ec = 0;
						plist_get_uint_val(nn, &ec);
						error_code = (uint32_t)ec;
						if (error_code == 0) {
							operation_ok = 1;
							result_code = 0;
						} else {
							result_code = -error_code;
						}
					}
					nn = plist_dict_get_item(node_tmp, "ErrorDescription");
					char *str = NULL;
					if (nn && (plist_get_node_type(nn) == PLIST_STRING)) {
						plist_get_string_val(nn, &str);
					}
					if (error_code != 0) {
						if (str) {
							printf("ErrorCode %d: %s\n", error_code, str);
						} else {
							printf("ErrorCode %d: (Unknown)\n", error_code);
						}
					}
					if (str) {
						free(str);
					}
					nn = plist_dict_get_item(node_tmp, "Content");
					if (nn && (plist_get_node_type(nn) == PLIST_STRING)) {
						str = NULL;
						plist_get_string_val(nn, &str);
						PRINT_VERBOSE(1, "Content:\n");
						printf("%s", str);
						free(str);
					}
					break;
				}

				/* print status */
				if ((overall_progress > 0) && !progress_finished) {
					if (overall_progress >= 100.0F) {
						progress_finished = 1;
					}
					print_progress_real(overall_progress, 0);
					PRINT_VERBOSE(1, " Finished\n");
				}

files_out:
				plist_free(message);
				message = NULL;
				free(dlmsg);
				dlmsg = NULL;

				if (quit_flag > 0) {
					/* need to cancel the backup here */
					//mobilebackup_send_error(mobilebackup, "Cancelling DLSendFile");

					/* remove any atomic Manifest.plist.tmp */

					/*manifest_path = mobilebackup_build_path(backup_directory, "Manifest", ".plist.tmp");
					if (stat(manifest_path, &st) == 0)
						remove(manifest_path);*/
					break;
				}
			} while (1);

			plist_free(message);
			free(dlmsg);

			/* report operation status to user */
			switch (cmd) {
				case CMD_CLOUD:
				if (cmd_flags & CMD_FLAG_CLOUD_ENABLE) {
					if (operation_ok) {
						PRINT_VERBOSE(1, "Cloud backup has been enabled successfully.\n");
					} else {
						PRINT_VERBOSE(1, "Could not enable cloud backup.\n");
					}
				} else if (cmd_flags & CMD_FLAG_CLOUD_DISABLE) {
					if (operation_ok) {
						PRINT_VERBOSE(1, "Cloud backup has been disabled successfully.\n");
					} else {
						PRINT_VERBOSE(1, "Could not disable cloud backup.\n");
					}
				}
				break;
				case CMD_BACKUP:
					PRINT_VERBOSE(1, "Received %d files from device.\n", file_count);
					if (operation_ok && mb2_status_check_snapshot_state(backup_directory, udid, "finished")) {
						PRINT_VERBOSE(1, "Backup Successful.\n");
					} else {
						if (quit_flag) {
							PRINT_VERBOSE(1, "Backup Aborted.\n");
						} else {
							PRINT_VERBOSE(1, "Backup Failed (Error Code %d).\n", -result_code);
						}
					}
				break;
				case CMD_UNBACK:
				if (quit_flag) {
					PRINT_VERBOSE(1, "Unback Aborted.\n");
				} else {
					PRINT_VERBOSE(1, "The files can now be found in the \"_unback_\" directory.\n");
					PRINT_VERBOSE(1, "Unback Successful.\n");
				}
				break;
				case CMD_CHANGEPW:
				if (cmd_flags & CMD_FLAG_ENCRYPTION_ENABLE) {
					if (operation_ok) {
						PRINT_VERBOSE(1, "Backup encryption has been enabled successfully.\n");
					} else {
						PRINT_VERBOSE(1, "Could not enable backup encryption.\n");
					}
				} else if (cmd_flags & CMD_FLAG_ENCRYPTION_DISABLE) {
					if (operation_ok) {
						PRINT_VERBOSE(1, "Backup encryption has been disabled successfully.\n");
					} else {
						PRINT_VERBOSE(1, "Could not disable backup encryption.\n");
					}
				} else if (cmd_flags & CMD_FLAG_ENCRYPTION_CHANGEPW) {
					if (operation_ok) {
						PRINT_VERBOSE(1, "Backup encryption password has been changed successfully.\n");
					} else {
						PRINT_VERBOSE(1, "Could not change backup encryption password.\n");
					}
				}
				break;
				case CMD_RESTORE:
				if (operation_ok) {
					if ((cmd_flags & CMD_FLAG_RESTORE_NO_REBOOT) == 0)
						PRINT_VERBOSE(1, "The device should reboot now.\n");
					PRINT_VERBOSE(1, "Restore Successful.\n");
				} else {
					afc_remove_path(afc, "/iTunesRestore/RestoreApplications.plist");
					afc_remove_path(afc, "/iTunesRestore");
					if (quit_flag) {
						PRINT_VERBOSE(1, "Restore Aborted.\n");
					} else {
						PRINT_VERBOSE(1, "Restore Failed (Error Code %d).\n", -result_code);
					}
				}
				break;
				case CMD_INFO:
				case CMD_LIST:
				case CMD_LEAVE:
				default:
				if (quit_flag) {
					PRINT_VERBOSE(1, "Operation Aborted.\n");
				} else if (cmd == CMD_LEAVE) {
					PRINT_VERBOSE(1, "Operation Failed.\n");
				} else {
					PRINT_VERBOSE(1, "Operation Successful.\n");
				}
				break;
			}
		}
		if (lockfile) {
			afc_file_lock(afc, lockfile, AFC_LOCK_UN);
			afc_file_close(afc, lockfile);
			lockfile = 0;
			if (cmd == CMD_BACKUP || cmd == CMD_RESTORE)
				do_post_notification(device, NP_SYNC_DID_FINISH);
		}
	} else {
		printf("ERROR: Could not start service %s: %s\n", MOBILEBACKUP2_SERVICE_NAME, lockdownd_strerror(ldret));
		lockdownd_client_free(lockdown);
		lockdown = NULL;
	}

	if (lockdown) {
		lockdownd_client_free(lockdown);
		lockdown = NULL;
	}

	if (mobilebackup2) {
		mobilebackup2_client_free(mobilebackup2);
		mobilebackup2 = NULL;
	}

	if (afc) {
		afc_client_free(afc);
		afc = NULL;
	}

	if (np) {
		np_client_free(np);
		np = NULL;
	}

	idevice_free(device);
	device = NULL;

	if (backup_password) {
		free(backup_password);
	}

	if (udid) {
		free(udid);
		udid = NULL;
	}
	if (source_udid) {
		free(source_udid);
		source_udid = NULL;
	}

	return result_code;
}

