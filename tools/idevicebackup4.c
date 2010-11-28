/*
 * idevicebackup4.c
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
#include <gcrypt.h>
#include <unistd.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/mobilebackup2.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/afc.h>

#define MOBILEBACKUP2_SERVICE_NAME "com.apple.mobilebackup2"
#define NP_SERVICE_NAME "com.apple.mobile.notification_proxy"

#define LOCK_ATTEMPTS 50
#define LOCK_WAIT 200000

#define CODE_NULL 0x00
#define CODE_ERROR_MSG 0x0b
#define CODE_FILE_DATA 0x0c

static mobilebackup2_client_t mobilebackup2 = NULL;
static lockdownd_client_t client = NULL;
static afc_client_t afc = NULL;
static idevice_t phone = NULL;

static int quit_flag = 0;

enum cmd_mode {
	CMD_BACKUP,
	CMD_RESTORE,
	CMD_INFO,
	CMD_LIST,
	CMD_LEAVE
};

enum plist_format_t {
	PLIST_FORMAT_XML,
	PLIST_FORMAT_BINARY
};

enum device_link_file_status_t {
	DEVICE_LINK_FILE_STATUS_NONE = 0,
	DEVICE_LINK_FILE_STATUS_HUNK,
	DEVICE_LINK_FILE_STATUS_LAST_HUNK
};

#if 0
static void sha1_of_data(const char *input, uint32_t size, unsigned char *hash_out)
{
	gcry_md_hash_buffer(GCRY_MD_SHA1, hash_out, input, size);
}

static int compare_hash(const unsigned char *hash1, const unsigned char *hash2, int hash_len)
{
	int i;
	for (i = 0; i < hash_len; i++) {
		if (hash1[i] != hash2[i]) {
			return 0;
		}
	}
	return 1;
}

static void compute_datahash(const char *path, const char *destpath, uint8_t greylist, const char *domain, const char *appid, const char *version, unsigned char *hash_out)
{
	gcry_md_hd_t hd = NULL;
	gcry_md_open(&hd, GCRY_MD_SHA1, 0);
	if (!hd) {
		printf("ERROR: Could not initialize libgcrypt/SHA1\n");
		return;
	}
	gcry_md_reset(hd);

	FILE *f = fopen(path, "rb");
	if (f) {
		unsigned char buf[16384];
		size_t len;
		while ((len = fread(buf, 1, 16384, f)) > 0) {
			gcry_md_write(hd, buf, len);
		}
		fclose(f);
		gcry_md_write(hd, destpath, strlen(destpath));
		gcry_md_write(hd, ";", 1);
		if (greylist == 1) {
			gcry_md_write(hd, "true", 4);
		} else {
			gcry_md_write(hd, "false", 5);
		}
		gcry_md_write(hd, ";", 1);
		if (domain) {
			gcry_md_write(hd, domain, strlen(domain));
		} else {
			gcry_md_write(hd, "(null)", 6);
		}
		gcry_md_write(hd, ";", 1);
		if (appid) {
			gcry_md_write(hd, appid, strlen(appid));
		} else {
			gcry_md_write(hd, "(null)", 6);
		}
		gcry_md_write(hd, ";", 1);
		if (version) {
			gcry_md_write(hd, version, strlen(version));
		} else {
			gcry_md_write(hd, "(null)", 6);
		}
		unsigned char *newhash = gcry_md_read(hd, GCRY_MD_SHA1);
		memcpy(hash_out, newhash, 20);
	}
	gcry_md_close(hd);
}

static void print_hash(const unsigned char *hash, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02x", hash[i]);
	}
}
#endif

static void notify_cb(const char *notification, void *userdata)
{
	if (!strcmp(notification, NP_SYNC_CANCEL_REQUEST)) {
		printf("User has aborted on-device\n");
		quit_flag++;
	} else {
		printf("unhandled notification '%s' (TODO: implement)\n", notification);
	}
}

static void debug_buf(const char *data, const int length)
{
	int i;
	int j;
	unsigned char c;

	for (i = 0; i < length; i += 16) {
		fprintf(stdout, "%04x: ", i);
		for (j = 0; j < 16; j++) {
			if (i + j >= length) {
				fprintf(stdout, "   ");
				continue;
			}
			fprintf(stdout, "%02hhx ", *(data + i + j));
		}
		fprintf(stdout, "  | ");
		for (j = 0; j < 16; j++) {
			if (i + j >= length)
				break;
			c = *(data + i + j);
			if ((c < 32) || (c > 127)) {
				fprintf(stdout, ".");
				continue;
			}
			fprintf(stdout, "%c", c);
		}
		fprintf(stdout, "\n");
	}
	fprintf(stdout, "\n");
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
	plist_dict_insert_item(ret, "Last Backup Date", plist_new_date(tv.tv_sec, tv.tv_usec));

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

#if 0
static void mobilebackup_info_update_last_backup_date(plist_t info_plist)
{
	GTimeVal tv = {0, 0};
	plist_t node = NULL;

	if (!info_plist)
		return;

	g_get_current_time(&tv);
	node = plist_dict_get_item(info_plist, "Last Backup Date");
	plist_set_date_val(node, tv.tv_sec, tv.tv_usec);

	node = NULL;
}
#endif

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

static int plist_strcmp(plist_t node, const char *str)
{
	char *buffer = NULL;
	int ret = 0;

	if (plist_get_node_type(node) != PLIST_STRING)
		return ret;

	plist_get_string_val(node, &buffer);
	ret = strcmp(buffer, str);
	free(buffer);

	return ret;
}

static gchar *mobilebackup_build_path(const char *backup_directory, const char *name, const char *extension)
{
	gchar *filename = g_strconcat(name, extension, NULL);
	gchar *path = g_build_path(G_DIR_SEPARATOR_S, backup_directory, filename, NULL);
	g_free(filename);
	return path;
}

/*static void mobilebackup_write_status(const char *path, int status)
{
	struct stat st;
	plist_t status_plist = plist_new_dict();
	plist_dict_insert_item(status_plist, "Backup Success", plist_new_bool(status));
	gchar *file_path = mobilebackup_build_path(path, "Status", ".plist");

	if (stat(file_path, &st) == 0)
		remove(file_path);

	plist_write_to_filename(status_plist, file_path, PLIST_FORMAT_XML);

	plist_free(status_plist);
	status_plist = NULL;

	g_free(file_path);
}*/

static int mobilebackup_read_status(const char *path)
{
	int ret = -1;
	plist_t status_plist = NULL;
	gchar *file_path = mobilebackup_build_path(path, "Status", ".plist");

	plist_read_from_filename(&status_plist, file_path);
	g_free(file_path);
	if (!status_plist) {
		printf("Could not read Status.plist!\n");
		return ret;
	}
	plist_t node = plist_dict_get_item(status_plist, "SnapshotState");
	if (node && (plist_get_node_type(node) == PLIST_STRING)) {
		char *str = NULL;
		plist_get_string_val(node, &str);
		if (!strcmp(str, "finished")) {
			ret = 1;
		} else {
			ret = 0;
		}
		g_free(str);
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

/*static int mobilebackup_delete_backup_file_by_hash(const char *backup_directory, const char *hash)
{
	int ret = 0;
	gchar *path = mobilebackup_build_path(backup_directory, hash, ".mddata");
	printf("Removing \"%s\" ", path);
	if (!remove( path ))
		ret = 1;
	else
		ret = 0;

	g_free(path);

	if (!ret)
		return ret;

	path = mobilebackup_build_path(backup_directory, hash, ".mdinfo");
	printf("and \"%s\"... ", path);
	if (!remove( path ))
		ret = 1;
	else
		ret = 0;

	g_free(path);

	return ret;
}*/

#if 0
static int mobilebackup_check_file_integrity(const char *backup_directory, const char *hash, plist_t filedata)
{
	char *datapath;
	char *infopath;
	plist_t mdinfo = NULL;
	struct stat st;
	unsigned char file_hash[20];

	datapath = mobilebackup_build_path(backup_directory, hash, ".mddata");
	if (stat(datapath, &st) != 0) {
		printf("\r\n");
		printf("ERROR: '%s.mddata' is missing!\n", hash);
		free(datapath);
		return 0;
	}

	infopath = mobilebackup_build_path(backup_directory, hash, ".mdinfo");
	plist_read_from_filename(&mdinfo, infopath);
	free(infopath);
	if (!mdinfo) {
		printf("\r\n");
		printf("ERROR: '%s.mdinfo' is missing or corrupted!\n", hash);
		free(datapath);
		return 0;
	}

	/* sha1 hash verification */
	plist_t node = plist_dict_get_item(filedata, "DataHash");
	if (!node || (plist_get_node_type(node) != PLIST_DATA)) {
		printf("\r\n");
		printf("ERROR: Could not get DataHash for file entry '%s'\n", hash);
		plist_free(mdinfo);
		free(datapath);
		return 0;
	}

	node = plist_dict_get_item(mdinfo, "Metadata");
	if (!node && (plist_get_node_type(node) != PLIST_DATA)) {
		printf("\r\n");
		printf("ERROR: Could not find Metadata in plist '%s.mdinfo'\n", hash);
		plist_free(mdinfo);
		free(datapath);
		return 0;
	}

	char *meta_bin = NULL;
	uint64_t meta_bin_size = 0;
	plist_get_data_val(node, &meta_bin, &meta_bin_size);
	plist_t metadata = NULL;
	if (meta_bin) {
		plist_from_bin(meta_bin, (uint32_t)meta_bin_size, &metadata);
	}
	if (!metadata) {
		printf("\r\n");
		printf("ERROR: Could not get Metadata from plist '%s.mdinfo'\n", hash);
		plist_free(mdinfo);
		free(datapath);
		return 0;
	}

	char *version = NULL;
	node = plist_dict_get_item(metadata, "Version");
	if (node && (plist_get_node_type(node) == PLIST_STRING)) { 
		plist_get_string_val(node, &version);
	}

	char *destpath = NULL;
	node = plist_dict_get_item(metadata, "Path");
	if (node && (plist_get_node_type(node) == PLIST_STRING)) { 
		plist_get_string_val(node, &destpath);
	}

	uint8_t greylist = 0;
	node = plist_dict_get_item(metadata, "Greylist");
	if (node && (plist_get_node_type(node) == PLIST_BOOLEAN)) {
		plist_get_bool_val(node, &greylist);
	}

	char *domain = NULL;
	node = plist_dict_get_item(metadata, "Domain");
	if (node && (plist_get_node_type(node) == PLIST_STRING)) { 
		plist_get_string_val(node, &domain);
	}

	char *fnstr = malloc(strlen(domain) + 1 + strlen(destpath) + 1);
	strcpy(fnstr, domain);
	strcat(fnstr, "-");
	strcat(fnstr, destpath);
	unsigned char fnhash[20];
	char fnamehash[41];
	char *p = fnamehash;
	sha1_of_data(fnstr, strlen(fnstr), fnhash);
	free(fnstr);
	int i;
	for ( i = 0; i < 20; i++, p += 2 ) {
		snprintf (p, 3, "%02x", (unsigned char)fnhash[i] );
	}
	if (strcmp(fnamehash, hash)) {
		printf("\r\n"); 
		printf("WARNING: filename hash does not match for entry '%s'\n", hash);
	}

	char *auth_version = NULL;
	node = plist_dict_get_item(mdinfo, "AuthVersion");
	if (node && (plist_get_node_type(node) == PLIST_STRING)) {
		plist_get_string_val(node, &auth_version);
	}

	if (strcmp(auth_version, "1.0")) {
		printf("\r\n");
		printf("WARNING: Unknown AuthVersion '%s', DataHash cannot be verified!\n", auth_version);
	}

	node = plist_dict_get_item(filedata, "DataHash");
	if (!node || (plist_get_node_type(node) != PLIST_DATA)) {
		printf("\r\n");
		printf("WARNING: Could not get DataHash key from file info data for entry '%s'\n", hash);
	}

	int res = 1;
	unsigned char *data_hash = NULL;
	uint64_t data_hash_len = 0;
	plist_get_data_val(node, (char**)&data_hash, &data_hash_len);
	int hash_ok = 0;
	if (data_hash && (data_hash_len == 20)) {
		compute_datahash(datapath, destpath, greylist, domain, NULL, version, file_hash);
		hash_ok = compare_hash(data_hash, file_hash, 20);
	} else if (data_hash_len == 0) {
		/* no datahash present */
		hash_ok = 1;
	}

	g_free(domain);
	g_free(version);
	g_free(destpath);

	if (!hash_ok) {
		printf("\r\n");
		printf("ERROR: The hash for '%s.mddata' does not match DataHash entry in Manifest\n", hash);
		printf("datahash: ");
		print_hash(data_hash, 20);
		printf("\nfilehash: ");
		print_hash(file_hash, 20);
		printf("\n");
		res = 0;
	}
	g_free(data_hash);
	plist_free(mdinfo);
	return res;
}
#endif

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

static void print_progress(double progress)
{
	int i = 0;
	if (progress < 0)
		return;

	if (progress > 100)
		progress = 100;

	printf("\r[");
	for(i = 0; i < 50; i++) {
		if(i < progress / 2) {
			printf("=");
		} else {
			printf(" ");
		}
	}
	printf("] %3.0f%%", progress);
	fflush(stdout);
	if (progress == 100)
		printf("\n");
}

static void multi_status_add_file_error(plist_t status_dict, const char *path, int error_code, const char *error_message)
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

static int handle_send_file(const char *backup_dir, const char *path, plist_t *errplist)
{
	uint32_t nlen = 0;
	uint32_t pathlen = strlen(path);
	int bytes = 0;
	gchar *localfile = g_build_path(G_DIR_SEPARATOR_S, backup_dir, path, NULL);
	char buf[16384];
	struct stat fst;

	FILE *f = NULL;
	uint32_t slen = 0;
	int errcode = -1;
	int e = -1;

	mobilebackup2_error_t err;

	/* send path length */
	nlen = GUINT32_TO_BE(pathlen);
	err = mobilebackup2_send_raw(mobilebackup2, (const char*)&nlen, sizeof(nlen), (uint32_t*)&bytes);
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		goto leave_proto_err;
	}
	if (bytes != sizeof(nlen)) {
		err = MOBILEBACKUP2_E_MUX_ERROR;
		goto leave_proto_err;
	}

	/* send path */
	err = mobilebackup2_send_raw(mobilebackup2, path, pathlen, (uint32_t*)&bytes);
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		goto leave_proto_err;
	}
	if ((uint32_t)bytes != pathlen) {
		err = MOBILEBACKUP2_E_MUX_ERROR;
		goto leave_proto_err;
	}

	if (stat(localfile, &fst) < 0) {
		printf("%s: stat failed on '%s': %d\n", __func__, localfile, errno);
		errcode = errno;
		goto leave;
	}

	f = fopen(localfile, "rb");
	if (!f) {
		printf("%s: Error opening local file '%s': %d\n", __func__, localfile, errno);
		errcode = errno;
		goto leave;
	}

	printf("Sending file '%s'\n", path);

	/* send data size (file size + 1) */
	uint32_t length = (uint32_t)fst.st_size;
	nlen = GUINT32_TO_BE(length+1);
	memcpy(buf, &nlen, sizeof(nlen));
	/* unknown special byte */
	buf[4] = 0x0C;
	err = mobilebackup2_send_raw(mobilebackup2, (const char*)buf, 5, (uint32_t*)&bytes);
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		goto leave_proto_err;
	}
	if (bytes != 5) {
		goto leave_proto_err;
	}

	/* send file contents */
	uint32_t sent = 0;
	while (sent < length) {
		size_t r = fread(buf, 1, sizeof(buf), f);
		if (r <= 0) {
			printf("%s: read error\n", __func__);
			errcode = errno;
			goto leave;
		}
		err = mobilebackup2_send_raw(mobilebackup2, buf, r, (uint32_t*)&bytes);
		if (err != MOBILEBACKUP2_E_SUCCESS) {
			goto leave_proto_err;
		}
		if ((uint32_t)bytes != r) {
			printf("sent only %d from %d\n", bytes, r);
			goto leave_proto_err;
		}
		sent += r;
	}
	fclose(f);
	f = NULL;
	errcode = 0;

leave:
	if (errcode == 0) {
		e = 0;
		nlen = 1;
		nlen = GUINT32_TO_BE(nlen);
		memcpy(buf, &nlen, 4);
		buf[4] = 0;
		mobilebackup2_send_raw(mobilebackup2, buf, 5, &sent);
	} else {
		if (!*errplist) {
			*errplist = plist_new_dict();
		}
		char *errdesc = strerror(errcode);
		multi_status_add_file_error(*errplist, path, errno_to_device_error(errcode), errdesc);
		
		length = strlen(errdesc);
		nlen = GUINT32_TO_BE(length+1);
		memcpy(buf, &nlen, 4);
		buf[4] = 0x06;
		slen = 5;
		memcpy(buf+slen, errdesc, length);
		slen += length;
		err = mobilebackup2_send_raw(mobilebackup2, (const char*)buf, slen, (uint32_t*)&bytes);
		if (err != MOBILEBACKUP2_E_SUCCESS) {
			printf("could not send message\n");
		}
		if ((uint32_t)bytes != slen) {
			printf("could only send %d from %d\n", bytes, slen);
		}
	}

leave_proto_err:
	if (f)
		fclose(f);
	g_free(localfile);
	return e;
}

static void handle_send_files(plist_t message, const char *backup_dir)
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

		if (handle_send_file(backup_dir, str, &errplist) < 0) {
			//printf("Error when sending file '%s' to device\n", str);
			// TODO: perhaps we can continue, we've got a multi status response?!
			break;
		}
	}

	/* send terminating 0 dword */
	uint32_t zero = 0;
	mobilebackup2_send_raw(mobilebackup2, (char*)&zero, 4, &sent);

	if (!errplist) {
		mobilebackup2_send_status_response(mobilebackup2, 0, NULL, plist_new_dict());
	} else {
		mobilebackup2_send_status_response(mobilebackup2, -13, "Multi status", errplist);
		plist_free(errplist);
	}
}

static int handle_receive_files(plist_t message, const char *backup_dir)
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
	gchar *bname = NULL;
	char code = 0;
	plist_t node = NULL;
	FILE *f = NULL;
	unsigned int file_count = 0;

	if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || plist_array_get_size(message) < 4 || !backup_dir) return 0;

	node = plist_array_get_item(message, 3);
	if (plist_get_node_type(node) == PLIST_UINT) {
		plist_get_uint_val(node, &backup_total_size);
	}
	if (backup_total_size > 0) {
		gchar *format_size = g_format_size_for_display(backup_total_size);
		printf("Receiving backup data (%s)\n", format_size);
		g_free(format_size);
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
		}
		fname = (char*)malloc(nlen+1);
		r = 0;
		mobilebackup2_receive_raw(mobilebackup2, fname, nlen, &r);
		fname[r] = 0;
		// we don't need this name
		//printf("\n%s\n", fname);
		free(fname);
		nlen = 0;
		mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &r);
		nlen = GUINT32_FROM_BE(nlen);
		fname = (char*)malloc(nlen+1);
		mobilebackup2_receive_raw(mobilebackup2, fname, nlen, &r);
		if (r != nlen) {
			fprintf(stderr, "hmmm.... received %d from %d\n", r, nlen);
		}
		fname[r] = 0;
		bname = g_build_path(G_DIR_SEPARATOR_S, backup_dir, fname, NULL);
		free(fname);
		nlen = 0;
		mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &r);
		nlen = GUINT32_FROM_BE(nlen);
		code = 0;
		mobilebackup2_receive_raw(mobilebackup2, &code, 1, &r);

		/* TODO remove this */
		if ((code != 0) && (code != CODE_FILE_DATA) && (code != CODE_ERROR_MSG)) {
			printf("Found new flag %02x\n", code);
		}

		remove(bname);
		f = fopen(bname, "wb");
		while (code == CODE_FILE_DATA) {
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
			if (quit_flag)
				break;
			nlen = 0;
			mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &r);
			nlen = GUINT32_FROM_BE(nlen);
			if (nlen > 0) {
				mobilebackup2_receive_raw(mobilebackup2, &code, 1, &r);
			} else {
				break;
			}
		}
		fclose(f);

		file_count++;
		if (backup_total_size > 0)
			print_progress(((double)backup_real_size/(double)backup_total_size)*100);
		if (nlen == 0) {
			break;
		}

		/* check if an error message was received */
		if (code == CODE_ERROR_MSG) {
			/* error message */
			char *msg = (char*)malloc(nlen);
			mobilebackup2_receive_raw(mobilebackup2, msg, nlen-1, &r);
			msg[r] = 0;
			fprintf(stdout, "\nReceived an error message from device: %s\n", msg);
			free(msg);
		}
	} while (1);
	if ((int)nlen-1 > 0) {
		printf("trashing padding\n");
		fname = (char*)malloc(nlen-1);
		mobilebackup2_receive_raw(mobilebackup2, fname, nlen-1, &r);
		debug_buf(fname, r);
		free(fname);
	}
	// TODO error handling?!
	mobilebackup2_send_status_response(mobilebackup2, 0, NULL, plist_new_dict());
	return file_count;
}

static void handle_list_directory(plist_t message, const char *backup_dir)
{
	if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || plist_array_get_size(message) < 2 || !backup_dir) return;

	/* TODO implement, for now we just return an empty listing */
	mobilebackup2_error_t err = mobilebackup2_send_status_response(mobilebackup2, 0, NULL, plist_new_dict());
	if (err != MOBILEBACKUP2_E_SUCCESS) {
		printf("Could not send status response, error %d\n", err);
	}
}

static void handle_make_directory(plist_t message, const char *backup_dir)
{
	if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || plist_array_get_size(message) < 2 || !backup_dir) return;

	plist_t dir = plist_array_get_item(message, 1);
	char *str = NULL;
	int errcode = 0;
	char *errdesc = NULL;
	plist_get_string_val(dir, &str);

	gchar *newpath = g_build_path(G_DIR_SEPARATOR_S, backup_dir, str, NULL);
	g_free(str);

	if (mkdir(newpath, 0755) < 0) {
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
	printf("Usage: %s [OPTIONS] CMD [DIRECTORY]\n", (name ? name + 1: argv[0]));
	printf("Create or restore backup from the current or specified directory.\n\n");
	printf("commands:\n");
	printf("  backup\tSaves a device backup into DIRECTORY\n");
	printf("  restore\tRestores a device backup from DIRECTORY.\n\n");
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
	int is_full_backup = 0;
	char *backup_directory = NULL;
	struct stat st;
	//plist_t node = NULL;
	plist_t node_tmp = NULL;
	//plist_t manifest_plist = NULL;
	plist_t info_plist = NULL;
	//char *buffer = NULL;
	//char *file_path = NULL;
	//uint64_t length = 0;
	//uint64_t backup_total_size = 0;
	//enum device_link_file_status_t file_status = DEVICE_LINK_FILE_STATUS_NONE;
//	uint64_t c = 0;
	mobilebackup2_error_t err;
	char *manifest_path = NULL;

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
		else if (!strcmp(argv[i], "info")) {
			cmd = CMD_INFO;
		}
		else if (!strcmp(argv[i], "list")) {
			cmd = CMD_LIST;
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
			printf("ERROR: Backup directory \"%s\" is invalid. No Info.plist found.\n", backup_directory);
			return -1;
		}
	}

	printf("Backup directory is \"%s\"\n", backup_directory);

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
		printf("Started \"%s\" service on port %d.\n", MOBILEBACKUP2_SERVICE_NAME, port);
		mobilebackup2_client_new(phone, port, &mobilebackup2);

		/* send Hello message */
		err = mobilebackup2_version_exchange(mobilebackup2);
		if (err != MOBILEBACKUP2_E_SUCCESS) {
			printf("Could not perform backup protocol version exchange, error code %d\n", err);
			cmd = CMD_LEAVE;
			goto checkpoint;
		}

		/* check abort conditions */
		if (quit_flag > 0) {
			printf("Aborting backup. Cancelled by user.\n");
			cmd = CMD_LEAVE;
			goto checkpoint;
		}

		/* verify existing Info.plist */
		if (stat(info_path, &st) == 0) {
			printf("Reading Info.plist from backup.\n");
			plist_read_from_filename(&info_plist, info_path);

			if (!info_plist) {
				printf("Could not read Info.plist\n");
				is_full_backup = 1;
			}
			if (info_plist && (cmd == CMD_BACKUP)) {
				if (mobilebackup_info_is_current_device(info_plist)) {
					/* update the last backup time within Info.plist */
					//mobilebackup_info_update_last_backup_date(info_plist);
					//remove(info_path);
					//plist_write_to_filename(info_plist, info_path, PLIST_FORMAT_XML);
				} else {
					printf("Aborting backup. Backup is not compatible with the current device.\n");
					cmd = CMD_LEAVE;
				}
			} else if (info_plist && (cmd == CMD_RESTORE)) {
				if (!mobilebackup_info_is_current_device(info_plist)) {
					printf("Aborting restore. Backup data is not compatible with the current device.\n");
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

		/* Manifest.plist (backup manifest (backup state)) */
		manifest_path = g_build_path(G_DIR_SEPARATOR_S, backup_directory, uuid, "Manifest.plist", NULL);

checkpoint:

		switch(cmd) {
			case CMD_BACKUP:
			printf("Starting backup...\n");
			/* TODO: check domain com.apple.mobile.backup key RequiresEncrypt and WillEncrypt with lockdown */
			/* TODO: verify battery on AC enough battery remaining */	
			gchar *device_backup_dir = g_build_path(G_DIR_SEPARATOR_S, backup_directory, uuid, NULL);
			if (mobilebackup_read_status(device_backup_dir) <= 0) {
				gchar *status_plist = g_build_path(G_DIR_SEPARATOR_S, backup_directory, uuid, "Status.plist", NULL);
				remove(status_plist);
				g_free(status_plist);
			}
			g_free(device_backup_dir);

			/* read the last Manifest.plist */
			/*
			if (!is_full_backup) {
				printf("Reading existing Manifest.\n");
				plist_read_from_filename(&manifest_plist, manifest_path);
				if (!manifest_plist) {
					printf("Could not read Manifest.plist, switching to full backup mode.\n");
					is_full_backup = 1;
				}
			}*/

			/* Info.plist (Device infos, IC-Info.sidb, photos, app_ids, iTunesPrefs) */

			/* re-create Info.plist */
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

			/* create Status.plist with failed status for now */
			//mobilebackup_write_status(backup_directory, 0);

			/* request backup from device with manifest from last backup */
			printf("Requesting backup from device...\n");

			err = mobilebackup2_send_request(mobilebackup2, "Backup", uuid, NULL, NULL);
			if (err == MOBILEBACKUP2_E_SUCCESS) {
				if (is_full_backup)
					printf("Full backup mode.\n");
				else
					printf("Incremental backup mode.\n");
				//printf("Please wait. Device is preparing backup data...\n");
			} else {
				if (err == MOBILEBACKUP2_E_BAD_VERSION) {
					printf("ERROR: Could not start backup process: backup protocol version mismatch!\n");
				} else if (err == MOBILEBACKUP2_E_REPLY_NOT_OK) {
					printf("ERROR: Could not start backup process: device refused to start the backup process.\n");
				} else {
					printf("ERROR: Could not start backup process: unspecified error occured\n");
				}
				break;
			}
			break;
			case CMD_RESTORE:
			/* TODO: verify battery on AC enough battery remaining */
			printf("Starting Restore...\n");

			plist_t opts = plist_new_dict();
			plist_dict_insert_item(opts, "shouldRestoreSystemFiles", plist_new_bool(0));
			err = mobilebackup2_send_request(mobilebackup2, "Restore", uuid, uuid, opts);
			plist_free(opts);
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				cmd = CMD_LEAVE;
			}
			break;
			case CMD_INFO:
			printf("Requesting backup info from device...\n");
			err = mobilebackup2_send_request(mobilebackup2, "Info", uuid, NULL, NULL);
			if (err != MOBILEBACKUP2_E_SUCCESS) {
				cmd = CMD_LEAVE;
			}
			break;
			case CMD_LIST:
			printf("Requesting backup list from device...\n");
			err = mobilebackup2_send_request(mobilebackup2, "List", uuid, NULL, NULL);
			if (err != MOBILEBACKUP2_E_SUCCESS) {
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
			/* reset backup status */
			int backup_ok = 0;
			plist_t message = NULL;

			/* TODO receive and save DLSendFile files and metadata, ACK each */
			char *dlmsg = NULL;
			/*uint64_t file_size = 0;
			uint64_t file_size_current = 0;*/
			int file_count = 0;
			/*int hunk_index = 0;
			uint64_t backup_real_size = 0;
			char *file_ext = NULL;
			char *filename_mdinfo = NULL;
			char *filename_mddata = NULL;
			char *filename_source = NULL;
			char *format_size = NULL;
			gboolean is_manifest = FALSE;
			uint8_t b = 0;*/
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
					printf("Device is not ready yet. Going to try again in 2 seconds...\n");
					sleep(2);
					goto files_out;
				}
				
				//node = plist_array_get_item(message, 0);

				if (!strcmp(dlmsg, "DLMessageDownloadFiles")) {
					/* device wants to download files from the computer */
					handle_send_files(message, backup_directory);
				} else if (!strcmp(dlmsg, "DLMessageUploadFiles")) {
					/* device wants to send files to the computer */
					file_count += handle_receive_files(message, backup_directory);
				} else if (!strcmp(dlmsg, "DLContentsOfDirectory")) {
					/* list directory contents */
					handle_list_directory(message, backup_directory);
				} else if (!strcmp(dlmsg, "DLMessageCreateDirectory")) {
					/* make a directory */
					handle_make_directory(message, backup_directory);
				} else if (!strcmp(dlmsg, "DLMessageMoveFiles")) {
					/* perform a series of rename operations */
					plist_t moves = plist_array_get_item(message, 1);
					uint32_t cnt = plist_dict_get_size(moves);
					printf("Moving %d file%s\n", cnt, (cnt == 1) ? "" : "s");
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
									//fprintf(stderr, "Moving '%s' to '%s'\n", oldpath, newpath);
									if (rename(oldpath, newpath) < 0) {
										printf("Renameing '%s' to '%s' failed: %s (%d)\n", oldpath, newpath, strerror(errno), errno);
										errcode = -errno;
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
					printf("Removing %d file%s\n", cnt, (cnt == 1) ? "" : "s");
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
									//errcode = -errno;
									//errdesc = strerror(errno);
								}
								g_free(newpath);
							}
						}
					}
					err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, plist_new_dict());
					if (err != MOBILEBACKUP2_E_SUCCESS) {
						printf("Could not send status response, error %d\n", err);
					}
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
							backup_ok = 1;
						}
					}
					nn = plist_dict_get_item(node_tmp, "ErrorDescription");
					char *str = NULL;
					if (nn && (plist_get_node_type(nn) == PLIST_STRING)) {
						plist_get_string_val(nn, &str);
					}
					if (error_code != 0) {
						if (str) {
							printf("ErrorCode %d: Description: %s\n", error_code, str);
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
						printf("Content:\n%s\n", str);
						free(str);
					}
					break;
				}

				/* print status */
				/*if (plist_array_get_size(message) >= 4) {
					plist_t pnode = plist_array_get_item(message, 4);
					if (pnode && (plist_get_node_type(pnode) == PLIST_REAL)) {
						double progress = 0.0;
						plist_get_real_val(pnode, &progress);
						printf("Progress: %f\n", progress);
					}
				}*/

#if 0
				/* get out if we don't get a DLSendFile */
				if (plist_strcmp(node, "DLSendFile"))
					break;

				node_tmp = plist_array_get_item(message, 2);

				/* first message hunk contains total backup size */
				if ((hunk_index == 0) && (file_index == 0)) {
					node = plist_dict_get_item(node_tmp, "BackupTotalSizeKey");
					if (node) {
						plist_get_uint_val(node, &backup_total_size);
						format_size = g_format_size_for_display(backup_total_size);
						printf("Backup data requires %s on the disk.\n", format_size);
						g_free(format_size);
					}
				}

				/* check DLFileStatusKey (codes: 1 = Hunk, 2 = Last Hunk) */
				node = plist_dict_get_item(node_tmp, "DLFileStatusKey");
				plist_get_uint_val(node, &c);
				file_status = c;

				/* get source filename */
				node = plist_dict_get_item(node_tmp, "BackupManifestKey");
				b = 0;
				if (node) {
					plist_get_bool_val(node, &b);
				}
				is_manifest = (b == 1) ? TRUE: FALSE;

				if ((hunk_index == 0) && (!is_manifest)) {
					/* get source filename */
					node = plist_dict_get_item(node_tmp, "DLFileSource");
					plist_get_string_val(node, &filename_source);

					/* increase received size */
					node = plist_dict_get_item(node_tmp, "DLFileAttributesKey");
					node = plist_dict_get_item(node, "FileSize");
					plist_get_uint_val(node, &file_size);
					backup_real_size += file_size;

					format_size = g_format_size_for_display(backup_real_size);
					printf("(%s", format_size);
					g_free(format_size);

					format_size = g_format_size_for_display(backup_total_size);
					printf("/%s): ", format_size);
					g_free(format_size);

					format_size = g_format_size_for_display(file_size);
					printf("Receiving file %s (%s)... \n", filename_source, format_size);
					g_free(format_size);

					if (filename_source)
						free(filename_source);
				}

				/* check if we completed a file */
				if ((file_status == DEVICE_LINK_FILE_STATUS_LAST_HUNK) && (!is_manifest)) {
					/* save <hash>.mdinfo */
					node = plist_dict_get_item(node_tmp, "BackupFileInfo");
					if (node) {
						node = plist_dict_get_item(node_tmp, "DLFileDest");
						plist_get_string_val(node, &file_path);

						filename_mdinfo = mobilebackup_build_path(backup_directory, file_path, ".mdinfo");

						/* remove any existing file */
						if (stat(filename_mdinfo, &st) == 0)
							remove(filename_mdinfo);

						node = plist_dict_get_item(node_tmp, "BackupFileInfo");
						plist_write_to_filename(node, filename_mdinfo, PLIST_FORMAT_BINARY);

						g_free(filename_mdinfo);
					}

					file_index++;
				}

				/* save <hash>.mddata */
				node = plist_dict_get_item(node_tmp, "BackupFileInfo");
				if (node_tmp) {
					node = plist_dict_get_item(node_tmp, "DLFileDest");
					plist_get_string_val(node, &file_path);

					filename_mddata = mobilebackup_build_path(backup_directory, file_path, is_manifest ? NULL: ".mddata");

					/* if this is the first hunk, remove any existing file */
					if ((hunk_index == 0) && (stat(filename_mddata, &st) == 0))
						remove(filename_mddata);

					/* get file data hunk */
					node_tmp = plist_array_get_item(message, 1);
					plist_get_data_val(node_tmp, &buffer, &length);

					buffer_write_to_filename(filename_mddata, buffer, length);
					if (!is_manifest)
						file_size_current += length;

					/* activate currently sent manifest */
					if ((file_status == DEVICE_LINK_FILE_STATUS_LAST_HUNK) && (is_manifest)) {
						rename(filename_mddata, manifest_path);
					}

					free(buffer);
					buffer = NULL;

					g_free(filename_mddata);
				}

				if ((!is_manifest)) {
					if (hunk_index == 0 && file_status == DEVICE_LINK_FILE_STATUS_LAST_HUNK) {
							print_progress(100);
					} else {
						if (file_size > 0)
							print_progress((double)((file_size_current*100)/file_size));
					}
				}

				hunk_index++;

				if (file_ext)
					free(file_ext);
#endif
				if (message)
					plist_free(message);
				message = NULL;

#if 0
				if (file_status == DEVICE_LINK_FILE_STATUS_LAST_HUNK) {
					/* acknowlegdge that we received the file */
					mobilebackup_send_backup_file_received(mobilebackup);
					/* reset hunk_index */
					hunk_index = 0;
					if (!is_manifest) {
						file_size_current = 0;
						file_size = 0;
					}
				}
#endif

files_out:
				if (quit_flag > 0) {
					/* need to cancel the backup here */
					//mobilebackup_send_error(mobilebackup, "Cancelling DLSendFile");

					/* remove any atomic Manifest.plist.tmp */
					if (manifest_path)
						g_free(manifest_path);

					/*manifest_path = mobilebackup_build_path(backup_directory, "Manifest", ".plist.tmp");
					if (stat(manifest_path, &st) == 0)
						remove(manifest_path);*/
					break;
				}
			} while (1);

			printf("Received %d files from device.\n", file_count);
#if 0
			if (!quit_flag && !plist_strcmp(node, "DLMessageProcessMessage")) {
				node_tmp = plist_array_get_item(message, 1);
				node = plist_dict_get_item(node_tmp, "BackupMessageTypeKey");
				/* check if we received the final "backup finished" message */
				if (node && !plist_strcmp(node, "BackupMessageBackupFinished")) {
					/* backup finished */

					/* process BackupFilesToDeleteKey */
					node = plist_dict_get_item(node_tmp, "BackupFilesToDeleteKey");
					if (node) {
						length = plist_array_get_size(node);
						i = 0;
						while ((node_tmp = plist_array_get_item(node, i++)) != NULL) {
							plist_get_string_val(node_tmp, &file_path);

							if (mobilebackup_delete_backup_file_by_hash(backup_directory, file_path)) {
								printf("DONE\n");
							} else
								printf("FAILED\n");
						}
					}

					/* save last valid Manifest.plist */
					node_tmp = plist_array_get_item(message, 1);
					manifest_plist = plist_dict_get_item(node_tmp, "BackupManifestKey");
					if (manifest_plist) {
						remove(manifest_path);
						printf("Storing Manifest.plist...\n");
						plist_write_to_filename(manifest_plist, manifest_path, PLIST_FORMAT_XML);
					}

					backup_ok = 1;
				}
			}
#endif
			if (backup_ok) {
				// /* Status.plist (Info on how the backup process turned out) */
				printf("Backup Successful.\n");
				//mobilebackup_write_status(backup_directory, 1);
			} else {
				printf("Backup Failed.\n");
			}
		}
		if (lockfile) {
			afc_file_lock(afc, lockfile, AFC_LOCK_UN);
			afc_file_close(afc, lockfile);
			lockfile = 0;
			do_post_notification(NP_SYNC_DID_FINISH);
		}
		if (manifest_path)
			g_free(manifest_path);
	} else {
		printf("ERROR: Could not start service %s.\n", MOBILEBACKUP2_SERVICE_NAME);
		lockdownd_client_free(client);
		client = NULL;
	}

	if (client) {
		lockdownd_client_free(client);
		client = NULL;
	}

	if (afc)
		afc_client_free(afc);

	if (np)
		np_client_free(np);

	if (mobilebackup2)
		mobilebackup2_client_free(mobilebackup2);

	idevice_free(phone);

	return 0;
}

