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
#include <glib.h>
#include <glib/gstdio.h>
#include <unistd.h>

#if !GLIB_CHECK_VERSION(2,25,0)
typedef struct stat GStatBuf;
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/mobilebackup2.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/afc.h>

#define MOBILEBACKUP2_SERVICE_NAME "com.apple.mobilebackup2"
#define NP_SERVICE_NAME "com.apple.mobile.notification_proxy"

#define LOCK_ATTEMPTS 50
#define LOCK_WAIT 200000

#define CODE_SUCCESS 0x00
#define CODE_ERROR_LOCAL 0x06
#define CODE_ERROR_REMOTE 0x0b
#define CODE_FILE_DATA 0x0c

static mobilebackup2_client_t mobilebackup2 = NULL;
static lockdownd_client_t client = NULL;
static afc_client_t afc = NULL;
static idevice_t phone = NULL;

static int verbose = 1;
static int quit_flag = 0;

#define PRINT_VERBOSE(min_level, ...) if (verbose >= min_level) { printf(__VA_ARGS__); };

enum cmd_mode {
	CMD_BACKUP,
	CMD_RESTORE,
	CMD_INFO,
	CMD_LIST,
	CMD_UNBACK,
	CMD_LEAVE
};

enum plist_format_t {
	PLIST_FORMAT_XML,
	PLIST_FORMAT_BINARY
};

enum cmd_flags {
	CMD_FLAG_RESTORE_SYSTEM_FILES       = (1 << 1),
	CMD_FLAG_RESTORE_REBOOT             = (1 << 2),
	CMD_FLAG_RESTORE_COPY_BACKUP        = (1 << 3),
	CMD_FLAG_RESTORE_SETTINGS           = (1 << 4)
};

static void notify_cb(const char *notification, void *userdata)
{
	if (!strcmp(notification, NP_SYNC_CANCEL_REQUEST)) {
		PRINT_VERBOSE(1, "User has cancelled the backup process on the device.\n");
		quit_flag++;
	} else {
		PRINT_VERBOSE(1, "Unhandled notification '%s' (TODO: implement)\n", notification);
	}
}

static void free_dictionary(char **dictionary)
{
	int i = 0;

	if (!dictionary)
		return;

	for (i = 0; dictionary[i]; i++) {
		free(dictionary[i]);
	}
	free(dictionary);
}

static void mobilebackup_afc_get_file_contents(const char *filename, char **data, uint64_t *size)
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
	free_dictionary(fileinfo);

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

static plist_t mobilebackup_factory_info_plist_new()
{
	/* gather data from lockdown */
	GTimeVal tv = {0, 0};
	plist_t value_node = NULL;
	plist_t root_node = NULL;
	char *uuid = NULL;
	char *uuid_uppercase = NULL;

	plist_t ret = plist_new_dict();

	/* get basic device information in one go */
	lockdownd_get_value(client, NULL, NULL, &root_node);

	/* set fields we understand */
	value_node = plist_dict_get_item(root_node, "BuildVersion");
	plist_dict_insert_item(ret, "Build Version", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "DeviceName");
	plist_dict_insert_item(ret, "Device Name", plist_copy(value_node));
	plist_dict_insert_item(ret, "Display Name", plist_copy(value_node));

	/* FIXME: How is the GUID generated? */
	plist_dict_insert_item(ret, "GUID", plist_new_string("---"));

	value_node = plist_dict_get_item(root_node, "IntegratedCircuitCardIdentity");
	if (value_node)
		plist_dict_insert_item(ret, "ICCID", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "InternationalMobileEquipmentIdentity");
	if (value_node)
		plist_dict_insert_item(ret, "IMEI", plist_copy(value_node));

	g_get_current_time(&tv);
	plist_dict_insert_item(ret, "Last Backup Date", plist_new_date(tv.tv_sec, 0));

	value_node = plist_dict_get_item(root_node, "PhoneNumber");
	if (value_node && (plist_get_node_type(value_node) == PLIST_STRING)) {
		plist_dict_insert_item(ret, "Phone Number", plist_copy(value_node));
	}

	value_node = plist_dict_get_item(root_node, "ProductType");
	plist_dict_insert_item(ret, "Product Type", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "ProductVersion");
	plist_dict_insert_item(ret, "Product Version", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "SerialNumber");
	plist_dict_insert_item(ret, "Serial Number", plist_copy(value_node));

	/* FIXME Sync Settings? */

	value_node = plist_dict_get_item(root_node, "UniqueDeviceID");
	idevice_get_uuid(phone, &uuid);
	plist_dict_insert_item(ret, "Target Identifier", plist_new_string(uuid));

	plist_dict_insert_item(ret, "Target Type", plist_new_string("Device"));

	/* uppercase */
	uuid_uppercase = g_ascii_strup(uuid, -1);
	plist_dict_insert_item(ret, "Unique Identifier", plist_new_string(uuid_uppercase));
	free(uuid_uppercase);
	free(uuid);

	char *data_buf = NULL;
	uint64_t data_size = 0;
	mobilebackup_afc_get_file_contents("/Books/iBooksData2.plist", &data_buf, &data_size);
	if (data_buf) {
		plist_dict_insert_item(ret, "iBooks Data 2", plist_new_data(data_buf, data_size));
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
		gchar *fname = g_strconcat("/iTunes_Control/iTunes/", itunesfiles[i], NULL);
		mobilebackup_afc_get_file_contents(fname, &data_buf, &data_size);
		g_free(fname);
		if (data_buf) {
			plist_dict_insert_item(files, itunesfiles[i], plist_new_data(data_buf, data_size));
			free(data_buf);
		}
	}
	plist_dict_insert_item(ret, "iTunes Files", files);

	plist_t itunes_settings = plist_new_dict();
	lockdownd_get_value(client, "com.apple.iTunes", NULL, &itunes_settings);
	plist_dict_insert_item(ret, "iTunes Settings", itunes_settings);

	plist_dict_insert_item(ret, "iTunes Version", plist_new_string("10.0.1"));

	plist_free(root_node);

	return ret;
}

static void buffer_read_from_filename(const char *filename, char **buffer, uint64_t *length)
{
	FILE *f;
	uint64_t size;

	*length = 0;

	f = fopen(filename, "rb");
	if (!f) {
		return;
	}

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	rewind(f);

	if (size == 0) {
		return;
	}

	*buffer = (char*)malloc(sizeof(char)*size);
	fread(*buffer, sizeof(char), size, f);
	fclose(f);

	*length = size;
}

static void buffer_write_to_filename(const char *filename, const char *buffer, uint64_t length)
{
	FILE *f;

	f = fopen(filename, "ab");
	if (!f)
		f = fopen(filename, "wb");
	if (f) {
		fwrite(buffer, sizeof(char), length, f);
		fclose(f);
	}
}

static int plist_read_from_filename(plist_t *plist, const char *filename)
{
	char *buffer = NULL;
	uint64_t length;

	if (!filename)
		return 0;

	buffer_read_from_filename(filename, &buffer, &length);

	if (!buffer) {
		return 0;
	}

	if ((length > 8) && (memcmp(buffer, "bplist00", 8) == 0)) {
		plist_from_bin(buffer, length, plist);
	} else {
		plist_from_xml(buffer, length, plist);
	}

	free(buffer);

	return 1;
}

static int plist_write_to_filename(plist_t plist, const char *filename, enum plist_format_t format)
{
	char *buffer = NULL;
	uint32_t length;

	if (!plist || !filename)
		return 0;

	if (format == PLIST_FORMAT_XML)
		plist_to_xml(plist, &buffer, &length);
	else if (format == PLIST_FORMAT_BINARY)
		plist_to_bin(plist, &buffer, &length);
	else
		return 0;

	buffer_write_to_filename(filename, buffer, length);

	free(buffer);

	return 1;
}

static int mb2_status_check_snapshot_state(const char *path, const char *uuid, const char *matches)
{
	int ret = -1;
	plist_t status_plist = NULL;
	gchar *file_path = g_build_path(G_DIR_SEPARATOR_S, path, uuid, "Status.plist", NULL);

	plist_read_from_filename(&status_plist, file_path);
	g_free(file_path);
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
		}
	} else {
		printf("%s: ERROR could not get SnapshotState key from Status.plist!\n", __func__);
	}
	plist_free(status_plist);
	return ret;
}

static int mobilebackup_info_is_current_device(plist_t info)
{
	plist_t value_node = NULL;
	plist_t node = NULL;
	plist_t root_node = NULL;
	int ret = 0;

	if (!info)
		return ret;

	if (plist_get_node_type(info) != PLIST_DICT)
		return ret;

	/* get basic device information in one go */
	lockdownd_get_value(client, NULL, NULL, &root_node);

	/* verify UUID */
	value_node = plist_dict_get_item(root_node, "UniqueDeviceID");
	node = plist_dict_get_item(info, "Target Identifier");

	if(plist_compare_node_value(value_node, node))
		ret = 1;
	else {
		printf("Info.plist: UniqueDeviceID does not match.\n");
	}

	/* verify SerialNumber */
	if (ret == 1) {
		value_node = plist_dict_get_item(root_node, "SerialNumber");
		node = plist_dict_get_item(info, "Serial Number");

		if(plist_compare_node_value(value_node, node))
			ret = 1;
		else {
			printf("Info.plist: SerialNumber does not match.\n");
			ret = 0;
		}
	}

	/* verify ProductVersion to prevent using backup with different OS version */
	if (ret == 1) {
		value_node = plist_dict_get_item(root_node, "ProductVersion");
		node = plist_dict_get_item(info, "Product Version");

		if(plist_compare_node_value(value_node, node))
			ret = 1;
		else {
			printf("Info.plist: ProductVersion does not match.\n");
			ret = 0;
		}
	}

	plist_free(root_node);
	root_node = NULL;

	value_node = NULL;
	node = NULL;

	return ret;
}

static void do_post_notification(const char *notification)
{
	uint16_t nport = 0;
	np_client_t np;

	if (!client) {
		if (lockdownd_client_new_with_handshake(phone, &client, "idevicebackup") != LOCKDOWN_E_SUCCESS) {
			return;
		}
	}

	lockdownd_start_service(client, NP_SERVICE_NAME, &nport);
	if (nport) {
		np_client_new(phone, nport, &np);
		if (np) {
			np_post_notification(np, notification);
			np_client_free(np);
		}
	} else {
		printf("Could not start %s\n", NP_SERVICE_NAME);
	}
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
	gchar *format_size = NULL;
	double progress = ((double)current/(double)total)*100;
	if (progress < 0)
		return;

	if (progress > 100)
		progress = 100;

	print_progress_real((double)progress, 0);

	format_size = g_format_size_for_display(current);
	PRINT_VERBOSE(1, " (%s", format_size);
	g_free(format_size);
	format_size = g_format_size_for_display(total);
	PRINT_VERBOSE(1, "/%s)     ", format_size);
	g_free(format_size);

	fflush(stdout);
	if (progress == 100)
		PRINT_VERBOSE(1, "\n");
}

static void mb2_multi_status_add_file_error(plist_t status_dict, const char *path, int error_code, const char *error_message)
{
	if (!status_dict) return;
	plist_t filedict = plist_new_dict();
	plist_dict_insert_item(filedict, "DLFileErrorString", plist_new_string(error_message));
	plist_dict_insert_item(filedict, "DLFileErrorCode", plist_new_uint(error_code));
	plist_dict_insert_item(status_dict, path, filedict);
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

static int mb2_handle_send_file(const char *backup_dir, const char *path, plist_t *errplist)
{
	uint32_t nlen = 0;
	uint32_t pathlen = strlen(path);
	uint32_t bytes = 0;
	gchar *localfile = g_build_path(G_DIR_SEPARATOR_S, backup_dir, path, NULL);
	char buf[32768];
	struct stat fst;

	FILE *f = NULL;
	uint32_t slen = 0;
	int errcode = -1;
	int result = -1;
	uint32_t length;
	off_t total;
	off_t sent;

	mobilebackup2_error_t err;

	/* send path length */
	nlen = GUINT32_TO_BE(pathlen);
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

	if (stat(localfile, &fst) < 0) {
		if (errno != ENOENT)
			printf("%s: stat failed on '%s': %d\n", __func__, localfile, errno);
		errcode = errno;
		goto leave;
	}

	total = fst.st_size;

	gchar *format_size = g_format_size_for_display(total);
	PRINT_VERBOSE(1, "Sending '%s' (%s)\n", path, format_size);
	g_free(format_size);

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
		length = ((total-sent) < (off_t)sizeof(buf)) ? (uint32_t)total-sent : (uint32_t)sizeof(buf);
		/* send data size (file size + 1) */
		nlen = GUINT32_TO_BE(length+1);
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
		nlen = GUINT32_TO_BE(nlen);
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
		nlen = GUINT32_TO_BE(length+1);
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
	g_free(localfile);
	return result;
}

static void mb2_handle_send_files(plist_t message, const char *backup_dir)
{
	uint32_t cnt; 
	uint32_t i = 0;
	uint32_t sent;
	plist_t errplist = NULL;

	if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || (plist_array_get_size(message) < 2) || !backup_dir) return;

	plist_t files = plist_array_get_item(message, 1);
	cnt = plist_array_get_size(files);
	if (cnt == 0) return;

	for (i = 0; i < cnt; i++) {
		plist_t val = plist_array_get_item(files, i);
		if (plist_get_node_type(val) != PLIST_STRING) {
			continue;
		}
		char *str = NULL;
		plist_get_string_val(val, &str);
		if (!str)
			continue;

		if (mb2_handle_send_file(backup_dir, str, &errplist) < 0) {
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

static int mb2_handle_receive_files(plist_t message, const char *backup_dir)
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
	gchar *bname = NULL;
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
		r = 0;
		mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &r);
		nlen = GUINT32_FROM_BE(nlen);
		if (nlen == 0) {
			// we're done here
			break;
		} else if (nlen > 4096) {
			// too very long path
			printf("ERROR: %s: too long device filename (%d)!\n", __func__, nlen);
			break;
		}
		if (dname != NULL)
			free(dname);
		dname = (char*)malloc(nlen+1);
		r = 0;
		mobilebackup2_receive_raw(mobilebackup2, dname, nlen, &r);
		if (r != nlen) {
			printf("ERROR: %s: could not read device filename\n", __func__);
			break;
		}
		dname[r] = 0;
		nlen = 0;
		mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &r);
		nlen = GUINT32_FROM_BE(nlen);
		if (nlen == 0) {
			printf("ERROR: %s: zero-length backup filename!\n", __func__);
			break;
		} else if (nlen > 4096) {
			printf("ERROR: %s: too long backup filename (%d)!\n", __func__, nlen);
			break;
		}
		fname = (char*)malloc(nlen+1);
		mobilebackup2_receive_raw(mobilebackup2, fname, nlen, &r);
		if (r != nlen) {
			printf("ERROR: %s: could not receive backup filename!\n", __func__);
			break;
		}
		fname[r] = 0;
		if (bname != NULL)
			g_free(bname);
		bname = g_build_path(G_DIR_SEPARATOR_S, backup_dir, fname, NULL);
		free(fname);
		nlen = 0;
		mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &r);
		if (r != 4) {
			printf("ERROR: %s: could not receive code length!\n", __func__);
			break;
		}
		nlen = GUINT32_FROM_BE(nlen);
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
			nlen = GUINT32_FROM_BE(nlen);
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
		g_free(bname);

	if (dname != NULL)
		free(dname);

	// TODO error handling?!
	mobilebackup2_send_status_response(mobilebackup2, 0, NULL, plist_new_dict());
	return file_count;
}

static void mb2_handle_list_directory(plist_t message, const char *backup_dir)
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

	gchar *path = g_build_path(G_DIR_SEPARATOR_S, backup_dir, str, NULL);
	free(str);

	plist_t dirlist = plist_new_dict();

	GDir *cur_dir = g_dir_open(path, 0, NULL);
	if (cur_dir) {
		gchar *dir_file;
		while ((dir_file = (gchar *)g_dir_read_name(cur_dir))) {
			gchar *fpath = g_build_filename(path, dir_file, NULL);
			if (fpath) {
				plist_t fdict = plist_new_dict();
				GStatBuf st;
				g_stat(fpath, &st);
				const char *ftype = "DLFileTypeUnknown";
				if (g_file_test(fpath, G_FILE_TEST_IS_DIR)) {
					ftype = "DLFileTypeDirectory";
				} else if (g_file_test(fpath, G_FILE_TEST_IS_REGULAR)) {
					ftype = "DLFileTypeRegular";
				}
				plist_dict_insert_item(fdict, "DLFileType", plist_new_string(ftype));
				plist_dict_insert_item(fdict, "DLFileSize", plist_new_uint(st.st_size));
				plist_dict_insert_item(fdict, "DLFileModificationDate", plist_new_date(st.st_mtime, 0));

				plist_dict_insert_item(dirlist, dir_file, fdict);
				g_free(fpath);
			}
		}
		g_dir_close(cur_dir);
	}
	g_free(path);

	/* TODO error handling */
	mobilebackup2_error_t err = mobilebackup2_send_status_response(mobilebackup2, 0, NULL, dirlist);
	plist_free(dirlist);
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		printf("Could not send status response, error %d\n", err);
	}
}

static void mb2_handle_make_directory(plist_t message, const char *backup_dir)
{
	if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || plist_array_get_size(message) < 2 || !backup_dir) return;

	plist_t dir = plist_array_get_item(message, 1);
	char *str = NULL;
	int errcode = 0;
	char *errdesc = NULL;
	plist_get_string_val(dir, &str);

	gchar *newpath = g_build_path(G_DIR_SEPARATOR_S, backup_dir, str, NULL);
	g_free(str);

	if (g_mkdir_with_parents(newpath, 0755) < 0) {
		errdesc = strerror(errno);
		if (errno != EEXIST) {
			printf("mkdir: %s (%d)\n", errdesc, errno);
		}
		errcode = errno_to_device_error(errno);
	}
	g_free(newpath);
	mobilebackup2_error_t err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, NULL);
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		printf("Could not send status response, error %d\n", err);
	}
}

static void mb2_copy_file_by_path(const gchar *src, const gchar *dst)
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

static void mb2_copy_directory_by_path(const gchar *src, const gchar *dst)
{
	if (!src || !dst) {
		return;
	}

	/* if src does not exist */
	if (!g_file_test(src, G_FILE_TEST_EXISTS)) {
		printf("ERROR: Source directory does not exist '%s': %s (%d)\n", src, strerror(errno), errno);
		return;
	}

	/* if dst directory does not exist */
	if (!g_file_test(dst, G_FILE_TEST_IS_DIR)) {
		/* create it */
		if (g_mkdir_with_parents(dst, 0755) < 0) {
			printf("ERROR: Unable to create destination directory '%s': %s (%d)\n", dst, strerror(errno), errno);
			return;
		}
	}

	/* loop over src directory contents */
	GDir *cur_dir = g_dir_open(src, 0, NULL);
	if (cur_dir) {
		gchar *dir_file;
		while ((dir_file = (gchar *)g_dir_read_name(cur_dir))) {
			gchar *srcpath = g_build_filename(src, dir_file, NULL);
			gchar *dstpath = g_build_filename(dst, dir_file, NULL);
			if (srcpath && dstpath) {
				/* copy file */
				mb2_copy_file_by_path(srcpath, dstpath);

				g_free(srcpath);
				g_free(dstpath);
			}
		}
		g_dir_close(cur_dir);
	}
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
	printf("  restore\trestore last backup to the device\n");
	printf("    --system\trestore system files, too.\n");
	printf("    --reboot\treboot the system when done.\n");
	printf("    --copy\tcreate a copy of backup folder before restoring.\n");
	printf("    --settings\trestore device settings from the backup.\n");
	printf("  info\t\tshow details about last completed backup of device\n");
	printf("  list\t\tlist files of last completed backup in CSV format\n");
	printf("  unback\tunpack a completed backup in DIRECTORY/_unback_/\n\n");
	printf("options:\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --uuid UUID\ttarget specific device by its 40-digit device UUID\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	int i;
	char uuid[41];
	uint16_t port = 0;
	uuid[0] = 0;
	int cmd = -1;
	int cmd_flags = 0;
	int is_full_backup = 0;
	char *backup_directory = NULL;
	struct stat st;
	plist_t node_tmp = NULL;
	plist_t info_plist = NULL;
	plist_t opts = NULL;
	mobilebackup2_error_t err;

	/* we need to exit cleanly on running backups and restores or we cause havok */
	signal(SIGINT, clean_exit);
	signal(SIGQUIT, clean_exit);
	signal(SIGTERM, clean_exit);
	signal(SIGPIPE, SIG_IGN);

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--uuid")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) != 40)) {
				print_usage(argc, argv);
				return 0;
			}
			strcpy(uuid, argv[i]);
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
		else if (backup_directory == NULL) {
			backup_directory = argv[i];
		}
		else {
			print_usage(argc, argv);
			return 0;
		}
	}

	/* verify options */
	if (cmd == -1) {
		printf("No command specified.\n");
		print_usage(argc, argv);
		return -1;
	}

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

	if (uuid[0] != 0) {
		ret = idevice_new(&phone, uuid);
		if (ret != IDEVICE_E_SUCCESS) {
			printf("No device found with uuid %s, is it plugged in?\n", uuid);
			return -1;
		}
	}
	else
	{
		ret = idevice_new(&phone, NULL);
		if (ret != IDEVICE_E_SUCCESS) {
			printf("No device found, is it plugged in?\n");
			return -1;
		}
		char *newuuid = NULL;
		idevice_get_uuid(phone, &newuuid);
		strcpy(uuid, newuuid);
		free(newuuid);
	}

	/* backup directory must contain an Info.plist */
	gchar *info_path = g_build_path(G_DIR_SEPARATOR_S, backup_directory, uuid, "Info.plist", NULL);
	if (cmd == CMD_RESTORE) {
		if (stat(info_path, &st) != 0) {
			g_free(info_path);
			printf("ERROR: Backup directory \"%s\" is invalid. No Info.plist found for UUID %s.\n", backup_directory, uuid);
			return -1;
		}
	}

	PRINT_VERBOSE(1, "Backup directory is \"%s\"\n", backup_directory);

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(phone, &client, "idevicebackup")) {
		idevice_free(phone);
		return -1;
	}

	/* start notification_proxy */
	np_client_t np = NULL;
	ret = lockdownd_start_service(client, NP_SERVICE_NAME, &port);
	if ((ret == LOCKDOWN_E_SUCCESS) && port) {
		np_client_new(phone, port, &np);
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

	afc = NULL;
	if (cmd == CMD_BACKUP) {
		/* start AFC, we need this for the lock file */
		port = 0;
		ret = lockdownd_start_service(client, "com.apple.afc", &port);
		if ((ret == LOCKDOWN_E_SUCCESS) && port) {
			afc_client_new(phone, port, &afc);
		}
	}

	/* start mobilebackup service and retrieve port */
	port = 0;
	ret = lockdownd_start_service(client, MOBILEBACKUP2_SERVICE_NAME, &port);
	if ((ret == LOCKDOWN_E_SUCCESS) && port) {
		PRINT_VERBOSE(1, "Started \"%s\" service on port %d.\n", MOBILEBACKUP2_SERVICE_NAME, port);
		mobilebackup2_client_new(phone, port, &mobilebackup2);

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
		if (stat(info_path, &st) == 0) {
			PRINT_VERBOSE(1, "Reading Info.plist from backup.\n");
			plist_read_from_filename(&info_plist, info_path);

			if (!info_plist) {
				printf("Could not read Info.plist\n");
				is_full_backup = 1;
			}
			if (info_plist && ((cmd == CMD_BACKUP) || (cmd == CMD_RESTORE))) {
				if (!mobilebackup_info_is_current_device(info_plist)) {
					printf("Aborting. Backup data is not compatible with the current device.\n");
					cmd = CMD_LEAVE;
				}
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
			do_post_notification(NP_SYNC_WILL_START);
			afc_file_open(afc, "/com.apple.itunes.lock_sync", AFC_FOPEN_RW, &lockfile);
		}
		if (lockfile) {
			afc_error_t aerr;
			do_post_notification(NP_SYNC_LOCK_REQUEST);
			for (i = 0; i < LOCK_ATTEMPTS; i++) {
				aerr = afc_file_lock(afc, lockfile, AFC_LOCK_EX);
				if (aerr == AFC_E_SUCCESS) {
					do_post_notification(NP_SYNC_DID_START);
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

checkpoint:

		switch(cmd) {
			case CMD_BACKUP:
			PRINT_VERBOSE(1, "Starting backup...\n");

			/* make sure backup device sub-directory exists */
			gchar *devbackupdir = g_build_path(G_DIR_SEPARATOR_S, backup_directory, uuid, NULL);
			g_mkdir(devbackupdir, 0755);
			g_free(devbackupdir);

			/* TODO: check domain com.apple.mobile.backup key RequiresEncrypt and WillEncrypt with lockdown */
			/* TODO: verify battery on AC enough battery remaining */	

			/* re-create Info.plist (Device infos, IC-Info.sidb, photos, app_ids, iTunesPrefs) */
			if (info_plist) {
				plist_free(info_plist);
				info_plist = NULL;
			}
			info_plist = mobilebackup_factory_info_plist_new();
			remove(info_path);
			plist_write_to_filename(info_plist, info_path, PLIST_FORMAT_XML);
			g_free(info_path);

			plist_free(info_plist);
			info_plist = NULL;

			/* request backup from device with manifest from last backup */
			PRINT_VERBOSE(1, "Requesting backup from device...\n");

			err = mobilebackup2_send_request(mobilebackup2, "Backup", uuid, NULL, NULL);
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
			if (!mb2_status_check_snapshot_state(backup_directory, uuid, "finished")) {
				printf("ERROR: Cannot ensure we restore from a successful backup. Aborting.\n");
				cmd = CMD_LEAVE;
				break;
			}

			PRINT_VERBOSE(1, "Starting Restore...\n");

			opts = plist_new_dict();
			plist_dict_insert_item(opts, "RestoreSystemFiles", plist_new_bool(cmd_flags & CMD_FLAG_RESTORE_SYSTEM_FILES));
			PRINT_VERBOSE(1, "Restoring system files: %s\n", (cmd_flags & CMD_FLAG_RESTORE_SYSTEM_FILES ? "Yes":"No"));
			if ((cmd_flags & CMD_FLAG_RESTORE_REBOOT) == 0)
				plist_dict_insert_item(opts, "RestoreShouldReboot", plist_new_bool(0));
			PRINT_VERBOSE(1, "Rebooting after restore: %s\n", (cmd_flags & CMD_FLAG_RESTORE_REBOOT ? "Yes":"No"));
			if ((cmd_flags & CMD_FLAG_RESTORE_COPY_BACKUP) == 0)
				plist_dict_insert_item(opts, "RestoreDontCopyBackup", plist_new_bool(1));
			PRINT_VERBOSE(1, "Don't copy backup: %s\n", ((cmd_flags & CMD_FLAG_RESTORE_COPY_BACKUP) == 0 ? "Yes":"No"));
			plist_dict_insert_item(opts, "RestorePreserveSettings", plist_new_bool((cmd_flags & CMD_FLAG_RESTORE_SETTINGS) == 0));
			PRINT_VERBOSE(1, "Preserve settings of device: %s\n", ((cmd_flags & CMD_FLAG_RESTORE_SETTINGS) == 0  ? "Yes":"No"));

			err = mobilebackup2_send_request(mobilebackup2, "Restore", uuid, uuid, opts);
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
			err = mobilebackup2_send_request(mobilebackup2, "Info", uuid, NULL, NULL);
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				printf("Error requesting backup info from device, error code %d\n", err);
				cmd = CMD_LEAVE;
			}
			break;
			case CMD_LIST:
			PRINT_VERBOSE(1, "Requesting backup list from device...\n");
			err = mobilebackup2_send_request(mobilebackup2, "List", uuid, NULL, NULL);
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				printf("Error requesting backup list from device, error code %d\n", err);
				cmd = CMD_LEAVE;
			}
			break;
			case CMD_UNBACK:
			PRINT_VERBOSE(1, "Starting to unpack backup...\n");
			err = mobilebackup2_send_request(mobilebackup2, "Unback", uuid, NULL, NULL);
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				printf("Error requesting unback operation from device, error code %d\n", err);
				cmd = CMD_LEAVE;
			}
			break;
			default:
			break;
		}

		/* close down the lockdown connection as it is no longer needed */
		if (client) {
			lockdownd_client_free(client);
			client = NULL;
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
					mb2_handle_send_files(message, backup_directory);
				} else if (!strcmp(dlmsg, "DLMessageUploadFiles")) {
					/* device wants to send files to the computer */
					file_count += mb2_handle_receive_files(message, backup_directory);
				} else if (!strcmp(dlmsg, "DLContentsOfDirectory")) {
					/* list directory contents */
					mb2_handle_list_directory(message, backup_directory);
				} else if (!strcmp(dlmsg, "DLMessageCreateDirectory")) {
					/* make a directory */
					mb2_handle_make_directory(message, backup_directory);
				} else if (!strcmp(dlmsg, "DLMessageMoveFiles")) {
					/* perform a series of rename operations */
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
									gchar *newpath = g_build_path(G_DIR_SEPARATOR_S, backup_directory, str, NULL);
									g_free(str);
									gchar *oldpath = g_build_path(G_DIR_SEPARATOR_S, backup_directory, key, NULL);

									remove(newpath);
									if (rename(oldpath, newpath) < 0) {
										printf("Renameing '%s' to '%s' failed: %s (%d)\n", oldpath, newpath, strerror(errno), errno);
										errcode = errno_to_device_error(errno);
										errdesc = strerror(errno);
										break;
									}
									g_free(oldpath);
									g_free(newpath);
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
					err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, plist_new_dict());
					if (err != MOBILEBACKUP2_E_SUCCESS) {
						printf("Could not send status response, error %d\n", err);
					}
				} else if (!strcmp(dlmsg, "DLMessageRemoveFiles")) {
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
								gchar *newpath = g_build_path(G_DIR_SEPARATOR_S, backup_directory, str, NULL);
								g_free(str);
								if (remove(newpath) < 0) {
									printf("Could not remove '%s': %s (%d)\n", newpath, strerror(errno), errno);
									errcode = errno_to_device_error(errno);
									errdesc = strerror(errno);
								}
								g_free(newpath);
							}
						}
					}
					err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, plist_new_dict());
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
							gchar *oldpath = g_build_path(G_DIR_SEPARATOR_S, backup_directory, src, NULL);
							gchar *newpath = g_build_path(G_DIR_SEPARATOR_S, backup_directory, dst, NULL);

							PRINT_VERBOSE(1, "Copying '%s' to '%s'\n", src, dst);

							/* check that src exists */
							if (g_file_test(oldpath, G_FILE_TEST_IS_DIR)) {
								mb2_copy_directory_by_path(oldpath, newpath);
							} else if (g_file_test(oldpath, G_FILE_TEST_IS_REGULAR)) {
								mb2_copy_file_by_path(oldpath, newpath);
							}

							g_free(newpath);
							g_free(oldpath);
						}
						g_free(src);
						g_free(dst);
					}

					err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, plist_new_dict());
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
				if (plist_array_get_size(message) >= 3) {
					plist_t pnode = plist_array_get_item(message, 3);
					if (pnode && (plist_get_node_type(pnode) == PLIST_REAL)) {
						double progress = 0.0;
						plist_get_real_val(pnode, &progress);
						if (progress > 0) {
							print_progress_real(progress, 0);
							PRINT_VERBOSE(1, " Finished\n");
						}
					}
				}

				if (message)
					plist_free(message);
				message = NULL;

files_out:
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
				case CMD_BACKUP:
					PRINT_VERBOSE(1, "Received %d files from device.\n", file_count);
					if (mb2_status_check_snapshot_state(backup_directory, uuid, "finished")) {
						PRINT_VERBOSE(1, "Backup Successful.\n");
					} else {
						if (quit_flag) {
							PRINT_VERBOSE(1, "Backup Aborted.\n");
						} else {
							PRINT_VERBOSE(1, "Backup Failed.\n");
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
				case CMD_RESTORE:
				if (cmd_flags & CMD_FLAG_RESTORE_REBOOT)
					PRINT_VERBOSE(1, "The device should reboot now.\n");
				if (operation_ok) {
					PRINT_VERBOSE(1, "Restore Successful.\n");
				} else {
					PRINT_VERBOSE(1, "Restore Failed.\n");
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
				do_post_notification(NP_SYNC_DID_FINISH);
		}
	} else {
		printf("ERROR: Could not start service %s.\n", MOBILEBACKUP2_SERVICE_NAME);
		lockdownd_client_free(client);
		client = NULL;
	}

	if (client) {
		lockdownd_client_free(client);
		client = NULL;
	}

	if (mobilebackup2)
		mobilebackup2_client_free(mobilebackup2);

	if (afc)
		afc_client_free(afc);

	if (np)
		np_client_free(np);

	idevice_free(phone);

	return 0;
}

