/*
 * idevicebackup2.c
 * Command line interface to use the device's backup and restore service
 *
 * Copyright (c) 2009-2010 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2010      Nikias Bassen All Rights Reserved.
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
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <time.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/mobilebackup2.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/afc.h>
#include "common/utils.h"

#include <endianness.h>

#define LOCK_ATTEMPTS 50
#define LOCK_WAIT 200000

#ifdef WIN32
#include <windows.h>
#include <conio.h>
#define sleep(x) Sleep(x*1000)
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
	CMD_FLAG_RESTORE_REBOOT             = (1 << 2),
	CMD_FLAG_RESTORE_COPY_BACKUP        = (1 << 3),
	CMD_FLAG_RESTORE_SETTINGS           = (1 << 4),
	CMD_FLAG_RESTORE_REMOVE_ITEMS       = (1 << 5),
	CMD_FLAG_ENCRYPTION_ENABLE          = (1 << 6),
	CMD_FLAG_ENCRYPTION_DISABLE         = (1 << 7),
	CMD_FLAG_ENCRYPTION_CHANGEPW        = (1 << 8),
	CMD_FLAG_FORCE_FULL_BACKUP          = (1 << 9),
	CMD_FLAG_CLOUD_ENABLE               = (1 << 10),
	CMD_FLAG_CLOUD_DISABLE              = (1 << 11)
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
		} else {
			break;
		}
		done += bread;
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
#ifdef WIN32
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
	} else {
		if (errno == EEXIST) return 0;
	}
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

static plist_t mobilebackup_factory_info_plist_new(const char* udid, lockdownd_client_t lockdown, afc_client_t afc)
{
	/* gather data from lockdown */
	plist_t value_node = NULL;
	plist_t root_node = NULL;
	char *udid_uppercase = NULL;

	plist_t ret = plist_new_dict();

	/* get basic device information in one go */
	lockdownd_get_value(lockdown, NULL, NULL, &root_node);

	/* set fields we understand */
	value_node = plist_dict_get_item(root_node, "BuildVersion");
	plist_dict_set_item(ret, "Build Version", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "DeviceName");
	plist_dict_set_item(ret, "Device Name", plist_copy(value_node));
	plist_dict_set_item(ret, "Display Name", plist_copy(value_node));

	/* FIXME: How is the GUID generated? */
	plist_dict_set_item(ret, "GUID", plist_new_string("---"));

	value_node = plist_dict_get_item(root_node, "IntegratedCircuitCardIdentity");
	if (value_node)
		plist_dict_set_item(ret, "ICCID", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "InternationalMobileEquipmentIdentity");
	if (value_node)
		plist_dict_set_item(ret, "IMEI", plist_copy(value_node));

	plist_dict_set_item(ret, "Last Backup Date", plist_new_date(time(NULL), 0));

	value_node = plist_dict_get_item(root_node, "PhoneNumber");
	if (value_node && (plist_get_node_type(value_node) == PLIST_STRING)) {
		plist_dict_set_item(ret, "Phone Number", plist_copy(value_node));
	}

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

	plist_t itunes_settings = NULL;
	lockdownd_get_value(lockdown, "com.apple.iTunes", NULL, &itunes_settings);
	plist_dict_set_item(ret, "iTunes Settings", itunes_settings ? itunes_settings : plist_new_dict());

	plist_dict_set_item(ret, "iTunes Version", plist_new_string("10.0.1"));

	plist_free(root_node);

	return ret;
}

static int mb2_status_check_snapshot_state(const char *path, const char *udid, const char *matches)
{
	int ret = -1;
	plist_t status_plist = NULL;
	char *file_path = string_build_path(path, udid, "Status.plist", NULL);

	plist_read_from_filename(&status_plist, file_path);
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

	if (lockdownd_client_new_with_handshake(device, &lockdown, "idevicebackup2") != LOCKDOWN_E_SUCCESS) {
		return;
	}

	lockdownd_start_service(lockdown, NP_SERVICE_NAME, &service);
	if (service && service->port) {
		np_client_new(device, service, &np);
		if (np) {
			np_post_notification(np, notification);
			np_client_free(np);
		}
	} else {
		printf("Could not start %s\n", NP_SERVICE_NAME);
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
		default:
			return -errno_value;
	}
}

#ifdef WIN32
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

static int mb2_handle_send_file(mobilebackup2_client_t mobilebackup2, const char *backup_dir, const char *path, plist_t *errplist)
{
	uint32_t nlen = 0;
	uint32_t pathlen = strlen(path);
	uint32_t bytes = 0;
	char *localfile = string_build_path(backup_dir, path, NULL);
	char buf[32768];
#ifdef WIN32
	struct _stati64 fst;
#else
	struct stat fst;
#endif

	FILE *f = NULL;
	uint32_t slen = 0;
	int errcode = -1;
	int result = -1;
	uint32_t length;
#ifdef WIN32
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

#ifdef WIN32
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
		} else if(rlen == 0) {
			// device needs more time, waiting...
			continue;
		} else if (nlen > 4096) {
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

		remove(bname);
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
			printf("Error opening '%s' for writing: %s\n", bname, strerror(errno));
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
		remove(bname);
	}

	/* clean up */
	if (bname != NULL)
		free(bname);

	if (dname != NULL)
		free(dname);

	// TODO error handling?!
	plist_t empty_plist = plist_new_dict();
	mobilebackup2_send_status_response(mobilebackup2, 0, NULL, empty_plist);
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
				plist_dict_set_item(fdict, "DLFileModificationDate", plist_new_date(st.st_mtime, 0));

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

				free(srcpath);
				free(dstpath);
			}
		}
		closedir(cur_dir);
	}
}

#ifdef WIN32
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
		} else if (isprint(c)) {
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

static void print_usage(int argc, char **argv)
{
	char *name = NULL;
	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] CMD [CMDOPTIONS] DIRECTORY\n", (name ? name + 1: argv[0]));
	printf("Create or restore backup from the current or specified directory.\n\n");
	printf("commands:\n");
	printf("  backup\tcreate backup for the device\n");
	printf("    --full\t\tforce full backup from device.\n");
	printf("  restore\trestore last backup to the device\n");
	printf("    --system\t\trestore system files, too.\n");
	printf("    --reboot\t\treboot the system when done.\n");
	printf("    --copy\t\tcreate a copy of backup folder before restoring.\n");
	printf("    --settings\t\trestore device settings from the backup.\n");
	printf("    --remove\t\tremove items which are not being restored\n");
	printf("    --password PWD\tsupply the password of the source backup\n");
	printf("  info\t\tshow details about last completed backup of device\n");
	printf("  list\t\tlist files of last completed backup in CSV format\n");
	printf("  unback\tunpack a completed backup in DIRECTORY/_unback_/\n");
	printf("  encryption on|off [PWD]\tenable or disable backup encryption\n");
	printf("    NOTE: password will be requested in interactive mode if omitted\n");
	printf("  changepw [OLD NEW]  change backup password on target device\n");
	printf("    NOTE: passwords will be requested in interactive mode if omitted\n");
	printf("  cloud on|off\tenable or disable cloud use (requires iCloud account)\n");
	printf("\n");
	printf("options:\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
	printf("  -s, --source UDID\tuse backup data from device specified by UDID\n");
	printf("  -i, --interactive\trequest passwords interactively\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
	printf("Homepage: <http://libimobiledevice.org>\n");
}

int main(int argc, char *argv[])
{
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
	int i;
	char* udid = NULL;
	char* source_udid = NULL;
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
	mobilebackup2_error_t err;

	/* we need to exit cleanly on running backups and restores or we cause havok */
	signal(SIGINT, clean_exit);
	signal(SIGTERM, clean_exit);
#ifndef WIN32
	signal(SIGQUIT, clean_exit);
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
			if (!argv[i] || (strlen(argv[i]) != 40)) {
				print_usage(argc, argv);
				return -1;
			}
			udid = strdup(argv[i]);
			continue;
		}
		else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--source")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) != 40)) {
				print_usage(argc, argv);
				return -1;
			}
			source_udid = strdup(argv[i]);
			continue;
		}
		else if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--interactive")) {
			interactive_mode = 1;
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
		else if (!strcmp(argv[i], "backup")) {
			cmd = CMD_BACKUP;
		}
		else if (!strcmp(argv[i], "restore")) {
			cmd = CMD_RESTORE;
		}
		else if (!strcmp(argv[i], "--system")) {
			cmd_flags |= CMD_FLAG_RESTORE_SYSTEM_FILES;
		}
		else if (!strcmp(argv[i], "--reboot")) {
			cmd_flags |= CMD_FLAG_RESTORE_REBOOT;
		}
		else if (!strcmp(argv[i], "--copy")) {
			cmd_flags |= CMD_FLAG_RESTORE_COPY_BACKUP;
		}
		else if (!strcmp(argv[i], "--settings")) {
			cmd_flags |= CMD_FLAG_RESTORE_SETTINGS;
		}
		else if (!strcmp(argv[i], "--remove")) {
			cmd_flags |= CMD_FLAG_RESTORE_REMOVE_ITEMS;
		}
		else if (!strcmp(argv[i], "--password")) {
			i++;
			if (!argv[i]) {
				print_usage(argc, argv);
				return -1;
			}
			if (backup_password)
				free(backup_password);
			backup_password = strdup(argv[i]);
			continue;
		}
		else if (!strcmp(argv[i], "cloud")) {
			cmd = CMD_CLOUD;
			i++;
			if (!argv[i]) {
				printf("No argument given for cloud command; requires either 'on' or 'off'.\n");
				print_usage(argc, argv);
				return -1;
			}
			if (!strcmp(argv[i], "on")) {
				cmd_flags |= CMD_FLAG_CLOUD_ENABLE;
			} else if (!strcmp(argv[i], "off")) {
				cmd_flags |= CMD_FLAG_CLOUD_DISABLE;
			} else {
				printf("Invalid argument '%s' for cloud command; must be either 'on' or 'off'.\n", argv[i]);
			}
			continue;
		}
		else if (!strcmp(argv[i], "--full")) {
			cmd_flags |= CMD_FLAG_FORCE_FULL_BACKUP;
		}
		else if (!strcmp(argv[i], "info")) {
			cmd = CMD_INFO;
			verbose = 0;
		}
		else if (!strcmp(argv[i], "list")) {
			cmd = CMD_LIST;
			verbose = 0;
		}
		else if (!strcmp(argv[i], "unback")) {
			cmd = CMD_UNBACK;
		}
		else if (!strcmp(argv[i], "encryption")) {
			cmd = CMD_CHANGEPW;
			i++;
			if (!argv[i]) {
				printf("No argument given for encryption command; requires either 'on' or 'off'.\n");
				print_usage(argc, argv);
				return -1;
			}
			if (!strcmp(argv[i], "on")) {
				cmd_flags |= CMD_FLAG_ENCRYPTION_ENABLE;
			} else if (!strcmp(argv[i], "off")) {
				cmd_flags |= CMD_FLAG_ENCRYPTION_DISABLE;
			} else {
				printf("Invalid argument '%s' for encryption command; must be either 'on' or 'off'.\n", argv[i]);
			}
			// check if a password was given on the command line
			if (newpw) {
				free(newpw);
				newpw = NULL;
			}
			if (backup_password) {
				free(backup_password);
				backup_password = NULL;
			}
			i++;
			if (argv[i]) {
				if (cmd_flags & CMD_FLAG_ENCRYPTION_ENABLE) {
					newpw = strdup(argv[i]);
				} else if (cmd_flags & CMD_FLAG_ENCRYPTION_DISABLE) {
					backup_password = strdup(argv[i]);
				}
			}
			continue;
		}
		else if (!strcmp(argv[i], "changepw")) {
			cmd = CMD_CHANGEPW;
			cmd_flags |= CMD_FLAG_ENCRYPTION_CHANGEPW;
			// check if passwords were given on command line
			if (newpw) {
				free(newpw);
				newpw = NULL;
			}
			if (backup_password) {
				free(backup_password);
				backup_password = NULL;
			}
			i++;
			if (argv[i]) {
				backup_password = strdup(argv[i]);
				i++;
				if (!argv[i]) {
					printf("Old and new passwords have to be passed as arguments for the changepw command\n");
					print_usage(argc, argv);
					return -1;
				}
				newpw = strdup(argv[i]);
			}
			continue;
		}
		else if (backup_directory == NULL) {
			backup_directory = argv[i];
		}
		else {
			print_usage(argc, argv);
			return -1;
		}
	}

	/* verify options */
	if (cmd == -1) {
		printf("No command specified.\n");
		print_usage(argc, argv);
		return -1;
	}

	if (cmd == CMD_CHANGEPW || cmd == CMD_CLOUD) {
		backup_directory = (char*)".this_folder_is_not_present_on_purpose";
	} else {
		if (backup_directory == NULL) {
			printf("No target backup directory specified.\n");
			print_usage(argc, argv);
			return -1;
		}

		/* verify if passed backup directory exists */
		if (stat(backup_directory, &st) != 0) {
			printf("ERROR: Backup directory \"%s\" does not exist!\n", backup_directory);
			return -1;
		}
	}

	idevice_t device = NULL;
	if (udid) {
		ret = idevice_new(&device, udid);
		if (ret != IDEVICE_E_SUCCESS) {
			printf("No device found with udid %s, is it plugged in?\n", udid);
			return -1;
		}
	}
	else
	{
		ret = idevice_new(&device, NULL);
		if (ret != IDEVICE_E_SUCCESS) {
			printf("No device found, is it plugged in?\n");
			return -1;
		}
		idevice_get_udid(device, &udid);
	}

	if (!source_udid) {
		source_udid = strdup(udid);
	}

	uint8_t is_encrypted = 0;
	char *info_path = NULL;
	if (cmd == CMD_CHANGEPW) {
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
			plist_read_from_filename(&manifest_plist, manifest_path);
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

	lockdownd_client_t lockdown = NULL;
	if (LOCKDOWN_E_SUCCESS != (ldret = lockdownd_client_new_with_handshake(device, &lockdown, "idevicebackup2"))) {
		printf("ERROR: Could not connect to lockdownd, error code %d\n", ldret);
		idevice_free(device);
		return -1;
	}

	/* start notification_proxy */
	np_client_t np = NULL;
	ldret = lockdownd_start_service(lockdown, NP_SERVICE_NAME, &service);
	if ((ldret == LOCKDOWN_E_SUCCESS) && service && service->port) {
		np_client_new(device, service, &np);
		np_set_notify_callback(np, notify_cb, NULL);
		const char *noties[5] = {
			NP_SYNC_CANCEL_REQUEST,
			NP_SYNC_SUSPEND_REQUEST,
			NP_SYNC_RESUME_REQUEST,
			NP_BACKUP_DOMAIN_CHANGED,
			NULL
		};
		np_observe_notifications(np, noties);
	} else {
		printf("ERROR: Could not start service %s.\n", NP_SERVICE_NAME);
	}

	afc_client_t afc = NULL;
	if (cmd == CMD_BACKUP) {
		/* start AFC, we need this for the lock file */
		service->port = 0;
		service->ssl_enabled = 0;
		ldret = lockdownd_start_service(lockdown, AFC_SERVICE_NAME, &service);
		if ((ldret == LOCKDOWN_E_SUCCESS) && service->port) {
			afc_client_new(device, service, &afc);
		}
	}

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

	/* start mobilebackup service and retrieve port */
	mobilebackup2_client_t mobilebackup2 = NULL;
	ldret = lockdownd_start_service_with_escrow_bag(lockdown, MOBILEBACKUP2_SERVICE_NAME, &service);
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
			plist_read_from_filename(&info_plist, info_path);

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

		uint64_t lockfile = 0;
		if (cmd == CMD_BACKUP) {
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
				} else if (aerr == AFC_E_OP_WOULD_BLOCK) {
					usleep(LOCK_WAIT);
					continue;
				} else {
					fprintf(stderr, "ERROR: could not lock file! error code: %d\n", aerr);
					afc_file_close(afc, lockfile);
					lockfile = 0;
					cmd = CMD_LEAVE;
				}
			}
			if (i == LOCK_ATTEMPTS) {
				fprintf(stderr, "ERROR: timeout while locking for sync\n");
				afc_file_close(afc, lockfile);
				lockfile = 0;
				cmd = CMD_LEAVE;
			}
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
			info_plist = mobilebackup_factory_info_plist_new(udid, lockdown, afc);
			remove(info_path);
			plist_write_to_filename(info_plist, info_path, PLIST_FORMAT_XML);
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
			} else {
				if (err == MOBILEBACKUP2_E_BAD_VERSION) {
					printf("ERROR: Could not start backup process: backup protocol version mismatch!\n");
				} else if (err == MOBILEBACKUP2_E_REPLY_NOT_OK) {
					printf("ERROR: Could not start backup process: device refused to start the backup process.\n");
				} else {
					printf("ERROR: Could not start backup process: unspecified error occured\n");
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
			if ((cmd_flags & CMD_FLAG_RESTORE_REBOOT) == 0)
				plist_dict_set_item(opts, "RestoreShouldReboot", plist_new_bool(0));
			PRINT_VERBOSE(1, "Rebooting after restore: %s\n", (cmd_flags & CMD_FLAG_RESTORE_REBOOT ? "Yes":"No"));
			if ((cmd_flags & CMD_FLAG_RESTORE_COPY_BACKUP) == 0)
				plist_dict_set_item(opts, "RestoreDontCopyBackup", plist_new_bool(1));
			PRINT_VERBOSE(1, "Don't copy backup: %s\n", ((cmd_flags & CMD_FLAG_RESTORE_COPY_BACKUP) == 0 ? "Yes":"No"));
			plist_dict_set_item(opts, "RestorePreserveSettings", plist_new_bool((cmd_flags & CMD_FLAG_RESTORE_SETTINGS) == 0));
			PRINT_VERBOSE(1, "Preserve settings of device: %s\n", ((cmd_flags & CMD_FLAG_RESTORE_SETTINGS) == 0 ? "Yes":"No"));
			if (cmd_flags & CMD_FLAG_RESTORE_REMOVE_ITEMS)
				plist_dict_set_item(opts, "RemoveItemsNotRestored", plist_new_bool(1));
				PRINT_VERBOSE(1, "Remove items that are not restored: %s\n", ((cmd_flags & CMD_FLAG_RESTORE_REMOVE_ITEMS) ? "Yes":"No"));
			if (backup_password != NULL) {
				plist_dict_set_item(opts, "Password", plist_new_string(backup_password));
			}
			PRINT_VERBOSE(1, "Backup password: %s\n", (backup_password == NULL ? "No":"Yes"));

			err = mobilebackup2_send_request(mobilebackup2, "Restore", udid, source_udid, opts);
			plist_free(opts);
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				if (err == MOBILEBACKUP2_E_BAD_VERSION) {
					printf("ERROR: Could not start restore process: backup protocol version mismatch!\n");
				} else if (err == MOBILEBACKUP2_E_REPLY_NOT_OK) {
					printf("ERROR: Could not start restore process: device refused to start the restore process.\n");
				} else {
					printf("ERROR: Could not start restore process: unspecified error occured\n");
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

		/* close down the lockdown connection as it is no longer needed */
		if (lockdown) {
			lockdownd_client_free(lockdown);
			lockdown = NULL;
		}

		if (cmd != CMD_LEAVE) {
			/* reset operation success status */
			int operation_ok = 0;
			plist_t message = NULL;

			char *dlmsg = NULL;
			int file_count = 0;
			int errcode = 0;
			const char *errdesc = NULL;

			/* process series of DLMessage* operations */
			do {
				if (dlmsg) {
					free(dlmsg);
					dlmsg = NULL;
				}
				mobilebackup2_receive_message(mobilebackup2, &message, &dlmsg);
				if (!message || !dlmsg) {
					PRINT_VERBOSE(1, "Device is not ready yet. Going to try again in 2 seconds...\n");
					sleep(2);
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
#ifdef WIN32
					if (GetDiskFreeSpaceEx(backup_directory, (PULARGE_INTEGER)&freespace, NULL, NULL)) {
						res = 0;
					}
#else
					struct statvfs fs;
					memset(&fs, '\0', sizeof(fs));
					res = statvfs(backup_directory, &fs);
					if (res == 0) {
						freespace = (uint64_t)fs.f_bavail * (uint64_t)fs.f_bsize;
					}
#endif
					plist_t freespace_item = plist_new_uint(freespace);
					mobilebackup2_send_status_response(mobilebackup2, res, NULL, freespace_item);
					plist_free(freespace_item);
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

#ifdef WIN32
									if ((stat(newpath, &st) == 0) && S_ISDIR(st.st_mode))
										RemoveDirectory(newpath);
									else
										DeleteFile(newpath);
#else
									remove(newpath);
#endif
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
#ifdef WIN32
								int res = 0;
								if ((stat(newpath, &st) == 0) && S_ISDIR(st.st_mode))
									res = RemoveDirectory(newpath);
								else
									res = DeleteFile(newpath);
								if (!res) {
									int e = win32err_to_errno(GetLastError());
									if (!suppress_warning)
										printf("Could not remove '%s': %s (%d)\n", newpath, strerror(e), e);
									errcode = errno_to_device_error(e);
									errdesc = strerror(e);
								}
#else
								if (remove(newpath) < 0) {
									if (!suppress_warning)
										printf("Could not remove '%s': %s (%d)\n", newpath, strerror(errno), errno);
									errcode = errno_to_device_error(errno);
									errdesc = strerror(errno);
								}
#endif
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
				if (overall_progress > 0) {
					print_progress_real(overall_progress, 0);
					PRINT_VERBOSE(1, " Finished\n");
				}

files_out:
				if (message)
					plist_free(message);
				message = NULL;
				if (dlmsg)
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
				if (cmd_flags & CMD_FLAG_RESTORE_REBOOT)
					PRINT_VERBOSE(1, "The device should reboot now.\n");
				if (operation_ok) {
					PRINT_VERBOSE(1, "Restore Successful.\n");
				} else {
					PRINT_VERBOSE(1, "Restore Failed (Error Code %d).\n", -result_code);
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
			if (cmd == CMD_BACKUP)
				do_post_notification(device, NP_SYNC_DID_FINISH);
		}
	} else {
		printf("ERROR: Could not start service %s.\n", MOBILEBACKUP2_SERVICE_NAME);
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

