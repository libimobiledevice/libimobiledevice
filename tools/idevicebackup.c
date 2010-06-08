/*
 * idevicebackup.c
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

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/mobilebackup.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/afc.h>

#define MOBILEBACKUP_SERVICE_NAME "com.apple.mobilebackup"
#define NP_SERVICE_NAME "com.apple.mobile.notification_proxy"

static mobilebackup_client_t mobilebackup = NULL;
static lockdownd_client_t client = NULL;
static idevice_t phone = NULL;

static int quit_flag = 0;

enum cmd_mode {
	CMD_BACKUP,
	CMD_RESTORE,
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

static void notify_cb(const char *notification, void *userdata)
{
	if (!strcmp(notification, NP_SYNC_CANCEL_REQUEST)) {
		printf("User has aborted on-device\n");
		quit_flag++;
	} else {
		printf("unhandled notification '%s' (TODO: implement)\n", notification);
	}
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

	value_node = plist_dict_get_item(root_node, "InternationalMobileEquipmentIdentity");
	if (value_node)
		plist_dict_insert_item(ret, "IMEI", plist_copy(value_node));

	g_get_current_time(&tv);
	plist_dict_insert_item(ret, "Last Backup Date", plist_new_date(tv.tv_sec, tv.tv_usec));

	value_node = plist_dict_get_item(root_node, "ProductType");
	plist_dict_insert_item(ret, "Product Type", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "ProductVersion");
	plist_dict_insert_item(ret, "Product Version", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "SerialNumber");
	plist_dict_insert_item(ret, "Serial Number", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "UniqueDeviceID");
	idevice_get_uuid(phone, &uuid);
	plist_dict_insert_item(ret, "Target Identifier", plist_new_string(uuid));

	/* uppercase */
	uuid_uppercase = g_ascii_strup(uuid, -1);
	plist_dict_insert_item(ret, "Unique Identifier", plist_new_string(uuid_uppercase));
	free(uuid_uppercase);
	free(uuid);

	/* FIXME: Embed files as <data> nodes */
	plist_t files = plist_new_dict();
	plist_dict_insert_item(ret, "iTunes Files", files);
	plist_dict_insert_item(ret, "iTunes Version", plist_new_string("9.0.2"));

	plist_free(root_node);

	return ret;
}

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

static void buffer_read_from_filename(const char *filename, char **buffer, uint32_t *length)
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

	*length = (uint32_t)size;
}

static void buffer_write_to_filename(const char *filename, const char *buffer, uint32_t length)
{
	FILE *f;

	f = fopen(filename, "ab");
	fwrite(buffer, sizeof(char), length, f);
	fclose(f);
}

static int plist_read_from_filename(plist_t *plist, const char *filename)
{
	char *buffer = NULL;
	uint32_t length;

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

static void mobilebackup_write_status(const char *path, int status)
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
}

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
	plist_t node = plist_dict_get_item(status_plist, "Backup Success");
	if (node && (plist_get_node_type(node) == PLIST_BOOLEAN)) {
		uint8_t bval = 0;
		plist_get_bool_val(node, &bval);
		ret = bval;
	} else {
		printf("%s: ERROR could not get Backup Success key from Status.plist!\n", __func__);
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

static int mobilebackup_delete_backup_file_by_hash(const char *backup_directory, const char *hash)
{
	int ret = 0;
	gchar *path = mobilebackup_build_path(backup_directory, hash, ".mddata");
	printf("Removing \"%s\"... ", path);
	if (!remove( path ))
		ret = 1;
	else
		ret = 0;

	g_free(path);

	if (!ret)
		return ret;

	path = mobilebackup_build_path(backup_directory, hash, ".mdinfo");
	printf("Removing \"%s\"... ", path);
	if (!remove( path ))
		ret = 1;
	else
		ret = 0;

	g_free(path);

	return ret;
}

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
	plist_t node = NULL;
	plist_t node_tmp = NULL;
	plist_t manifest_plist = NULL;
	plist_t info_plist = NULL;
	char *buffer = NULL;
	uint64_t length = 0;
	uint64_t backup_total_size = 0;
	enum device_link_file_status_t file_status;
	uint64_t c = 0;

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

	/* restore directory must contain an Info.plist */
	char *info_path = mobilebackup_build_path(backup_directory, "Info", ".plist");
	if (cmd == CMD_RESTORE) {
		if (stat(info_path, &st) != 0) {
			g_free(info_path);
			printf("ERROR: Backup directory \"%s\" is invalid. No Info.plist found.\n", backup_directory);
			return -1;
		}
	}

	printf("Backup directory is \"%s\"\n", backup_directory);

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
	}

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

	afc_client_t afc = NULL;
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
	ret = lockdownd_start_service(client, MOBILEBACKUP_SERVICE_NAME, &port);
	if ((ret == LOCKDOWN_E_SUCCESS) && port) {
		printf("Started \"%s\" service on port %d.\n", MOBILEBACKUP_SERVICE_NAME, port);
		mobilebackup_client_new(phone, port, &mobilebackup);

		/* check abort conditions */
		if (quit_flag > 0) {
			printf("Aborting backup. Cancelled by user.\n");
			cmd = CMD_LEAVE;
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
					mobilebackup_info_update_last_backup_date(info_plist);
					remove(info_path);
					plist_write_to_filename(info_plist, info_path, PLIST_FORMAT_XML);
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
			do_post_notification(NP_SYNC_LOCK_REQUEST);
			if (afc_file_lock(afc, lockfile, AFC_LOCK_EX) == AFC_E_SUCCESS) {
				do_post_notification(NP_SYNC_DID_START);
			} else {
				afc_file_close(afc, lockfile);
				lockfile = 0;
			}
		}

		mobilebackup_error_t err;

		/* Manifest.plist (backup manifest (backup state)) */
		char *manifest_path = mobilebackup_build_path(backup_directory, "Manifest", ".plist");

		switch(cmd) {
			case CMD_BACKUP:
			printf("Starting backup...\n");
			/* TODO: check domain com.apple.mobile.backup key RequiresEncrypt and WillEncrypt with lockdown */
			/* TODO: verify battery on AC enough battery remaining */	

			/* read the last Manifest.plist */
			if (!is_full_backup) {
				printf("Reading existing Manifest.\n");
				plist_read_from_filename(&manifest_plist, manifest_path);
				if (!manifest_plist) {
					printf("Could not read Manifest.plist, switching to full backup mode.\n");
					is_full_backup = 1;
				}
			}

			/* Info.plist (Device infos, IC-Info.sidb, photos, app_ids, iTunesPrefs) */

			/* create new Info.plist on new backups */
			if (is_full_backup) {
				if (info_plist) {
					plist_free(info_plist);
					info_plist = NULL;
				}
				remove(info_path);
				printf("Creating Info.plist for new backup.\n");
				info_plist = mobilebackup_factory_info_plist_new();
				plist_write_to_filename(info_plist, info_path, PLIST_FORMAT_XML);
			}
			g_free(info_path);

			plist_free(info_plist);
			info_plist = NULL;

			/* close down the lockdown connection as it is no longer needed */
			if (client) {
				lockdownd_client_free(client);
				client = NULL;
			}

			/* create Status.plist with failed status for now */
			mobilebackup_write_status(backup_directory, 0);

			/* request backup from device with manifest from last backup */
			printf("Requesting backup from device...\n");

			err = mobilebackup_request_backup(mobilebackup, manifest_plist, "/", "1.6");
			if (err == MOBILEBACKUP_E_SUCCESS) {
				if (is_full_backup)
					printf("Full backup mode.\n");
				else
					printf("Incremental backup mode.\n");
				printf("Please wait. Device is preparing backup data...\n");
			} else {
				if (err == MOBILEBACKUP_E_BAD_VERSION) {
					printf("ERROR: Could not start backup process: backup protocol version mismatch!\n");
				} else if (err == MOBILEBACKUP_E_REPLY_NOT_OK) {
					printf("ERROR: Could not start backup process: device refused to start the backup process.\n");
				} else {
					printf("ERROR: Could not start backup process: unspecified error occured\n");
				}
				break;
			}

			/* reset backup status */
			int backup_ok = 0;
			plist_t message = NULL;

			/* receive and save DLSendFile files and metadata, ACK each */
			int file_index = 0;
			int hunk_index = 0;
			uint64_t backup_real_size = 0;
			char *file_path = NULL;
			char *file_ext = NULL;
			char *filename_mdinfo = NULL;
			char *filename_mddata = NULL;
			char *filename_source = NULL;
			char *format_size = NULL;
			gboolean is_manifest = FALSE;
			uint8_t b = 0;

			/* process series of DLSendFile messages */
			do {
				mobilebackup_receive(mobilebackup, &message);
				node = plist_array_get_item(message, 0);

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

				/* check if we completed a file */
				if ((file_status == DEVICE_LINK_FILE_STATUS_LAST_HUNK) && (!is_manifest)) {
					/* get source filename */
					node = plist_dict_get_item(node_tmp, "DLFileSource");
					plist_get_string_val(node, &filename_source);

					/* increase received size */
					node = plist_dict_get_item(node_tmp, "DLFileAttributesKey");
					node = plist_dict_get_item(node, "FileSize");
					plist_get_uint_val(node, &length);
					backup_real_size += length;

					format_size = g_format_size_for_display(backup_real_size);
					printf("(%s", format_size);
					g_free(format_size);

					format_size = g_format_size_for_display(backup_total_size);
					printf("/%s): ", format_size);
					g_free(format_size);

					printf("Received file %s... ", filename_source);

					if (filename_source)
						free(filename_source);

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
				if (node_tmp && file_path) {
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

					/* activate currently sent manifest */
					if ((file_status == DEVICE_LINK_FILE_STATUS_LAST_HUNK) && (is_manifest)) {
						rename(filename_mddata, manifest_path);
					}

					free(buffer);
					buffer = NULL;

					g_free(filename_mddata);
				}

				hunk_index++;

				if (file_ext)
					free(file_ext);

				if (message)
					plist_free(message);
				message = NULL;

				if (file_status == DEVICE_LINK_FILE_STATUS_LAST_HUNK) {
					if (!is_manifest)
						printf("DONE\n");

					/* acknowlegdge that we received the file */
					mobilebackup_send_backup_file_received(mobilebackup);
					/* reset hunk_index */
					hunk_index = 0;
				}

				if (quit_flag > 0) {
					/* need to cancel the backup here */
					mobilebackup_send_error(mobilebackup, "Cancelling DLSendFile");

					/* remove any atomic Manifest.plist.tmp */
					if (manifest_path)
						g_free(manifest_path);

					manifest_path = mobilebackup_build_path(backup_directory, "Manifest", ".plist.tmp");
					if (stat(manifest_path, &st) == 0)
						remove(manifest_path);
					break;
				}
			} while (1);

			printf("Received %d files from device.\n", file_index);

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

			if (backup_ok) {
				/* Status.plist (Info on how the backup process turned out) */
				printf("Backup Successful.\n");
				mobilebackup_write_status(backup_directory, 1);
			} else {
				printf("Backup Failed.\n");
			}
			break;
			case CMD_RESTORE:
			/* TODO: verify battery on AC enough battery remaining */
			/* verify if Status.plist says we read from an successful backup */
			if (mobilebackup_read_status(backup_directory) <= 0) {
				printf("ERROR: Cannot ensure we restore from a successful backup. Aborting.\n");
				break;
			}
			/* now make sure backup integrity is ok! verify all files */
			printf("Reading existing Manifest.\n");
			plist_read_from_filename(&manifest_plist, manifest_path);
			if (!manifest_plist) {
				printf("Could not read Manifest.plist. Aborting.\n");
				break;
			}

			printf("Verifying backup integrity, please wait.\n");
			char *bin = NULL;
			uint64_t binsize = 0;
			node = plist_dict_get_item(manifest_plist, "Data");
			if (!node || (plist_get_node_type(node) != PLIST_DATA)) {
				printf("Could not read Data key from Manifest.plist!\n");
				break;
			}
			plist_get_data_val(node, &bin, &binsize);
			plist_t backup_data = NULL;
			if (bin) {
				char *auth_ver = NULL;
				unsigned char *auth_sig = NULL;
				uint64_t auth_sig_len = 0;
				/* verify AuthSignature */
				node = plist_dict_get_item(manifest_plist, "AuthVersion");
				plist_get_string_val(node, &auth_ver);
				if (auth_ver && (strcmp(auth_ver, "2.0") == 0)) {
					node = plist_dict_get_item(manifest_plist, "AuthSignature");
					if (node && (plist_get_node_type(node) == PLIST_DATA)) {
						plist_get_data_val(node, (char**)&auth_sig, &auth_sig_len);
					}
					if (auth_sig && (auth_sig_len == 20)) {
						/* calculate the sha1, then compare */
						unsigned char data_sha1[20];
						sha1_of_data(bin, binsize, data_sha1);
						if (compare_hash(auth_sig, data_sha1, 20)) {
							printf("AuthSignature is valid\n");
						} else {
							printf("ERROR: AuthSignature is NOT VALID\n");
						}
					} else {
						printf("Could not get AuthSignature from manifest!\n");
					}
					g_free(auth_sig);
				} else if (auth_ver) {
					printf("Unknown AuthVersion '%s', cannot verify AuthSignature\n", auth_ver); 
				}
				plist_from_bin(bin, (uint32_t)binsize, &backup_data);
				g_free(bin);
			}
			if (!backup_data) {
				printf("Could not read plist from Manifest.plist Data key!\n");
				break;
			}
			plist_t files = plist_dict_get_item(backup_data, "Files");
			if (files && (plist_get_node_type(files) == PLIST_DICT)) {
				plist_dict_iter iter = NULL;
				plist_dict_new_iter(files, &iter);
				if (iter) {
					/* loop over Files entries in Manifest data plist */
					char *hash = NULL;
					int file_ok = 0;
					int total_files = plist_dict_get_size(files);
					int cur_file = 1;
					node = NULL;
					plist_dict_next_item(files, iter, &hash, &node);
					while (node) {
						printf("Verifying files %d/%d (%d%%) \r", cur_file, total_files, (cur_file*100/total_files));
						cur_file++;
						/* make sure both .mddata/.mdinfo files are available for each entry */
						file_ok = mobilebackup_check_file_integrity(backup_directory, hash, node);
						node = NULL;
						free(hash);
						hash = NULL;
						if (!file_ok) {
							break;
						}
						plist_dict_next_item(files, iter, &hash, &node);
					}
					printf("\n");
					free(iter);
					if (!file_ok) {
						plist_free(backup_data);
						break;
					}
					printf("All backup files appear to be valid\n");
				}
			}
			/* request restore from device with manifest (BackupMessageRestoreMigrate) */
			int restore_flags = MB_RESTORE_NOTIFY_SPRINGBOARD | MB_RESTORE_PRESERVE_SETTINGS | MB_RESTORE_PRESERVE_CAMERA_ROLL;
			err = mobilebackup_request_restore(mobilebackup, manifest_plist, restore_flags, "1.6");
			if (err != MOBILEBACKUP_E_SUCCESS) {
				if (err == MOBILEBACKUP_E_BAD_VERSION) {
					printf("ERROR: Could not start restore process: backup protocol version mismatch!\n");
				} else if (err == MOBILEBACKUP_E_REPLY_NOT_OK) {
					printf("ERROR: Could not start restore process: device refused to start the restore process.\n");
				} else {
					printf("ERROR: Could not start restore process: unspecified error occured (%d)\n", err);
				}
				plist_free(backup_data);
				break;
			}

			if (files && (plist_get_node_type(files) == PLIST_DICT)) {
				plist_dict_iter iter = NULL;
				plist_dict_new_iter(files, &iter);
				if (iter) {
					/* loop over Files entries in Manifest data plist */
					char *hash = NULL;
					int file_ok = 0;
					int total_files = plist_dict_get_size(files);
					int cur_file = 1;
					node = NULL;
					plist_dict_next_item(files, iter, &hash, &node);
					while (node) {
						printf("Sending files %d/%d (%d%%) \r", cur_file, total_files, (cur_file*100/total_files));
						cur_file++;
						
						/* TODO: read mddata/mdinfo files and send to device using DLSendFile */
						/* TODO: if all hunks of a file are sent, device must send ack */
						/* err = mobilebackup_receive_restore_file_received(mobilebackup, &result); */
						node = NULL;
						free(hash);
						hash = NULL;
						if (!file_ok) {
							break;
						}
						plist_dict_next_item(files, iter, &hash, &node);
					}
					printf("\n");
					free(iter);
					if (!file_ok) {
						plist_free(backup_data);
						break;
					}
				}
			}
			/* TODO: observe notification_proxy id com.apple.mobile.application_installed */
			/* TODO: loop over Applications entries in Manifest data plist */
				/* send AppInfo entries */
				/* receive com.apple.mobile.application_installed notification */
				/* receive BackupMessageRestoreApplicationReceived from device */
			plist_free(backup_data);

			/* signal restore finished message to device; BackupMessageRestoreComplete */
			err = mobilebackup_send_restore_complete(mobilebackup);
			if (err != MOBILEBACKUP_E_SUCCESS) {
				printf("ERROR: Could not send BackupMessageRestoreComplete, error code %d\n", err);
			}
			/* TODO: close down notification_proxy connection */
			/* close down lockdown connection as it is no longer needed */
			lockdownd_client_free(client);
			client = NULL;
			break;
			case CMD_LEAVE:
			default:
			break;
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
		printf("ERROR: Could not start service %s.\n", MOBILEBACKUP_SERVICE_NAME);
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

	if (mobilebackup)
		mobilebackup_client_free(mobilebackup);

	idevice_free(phone);

	return 0;
}

