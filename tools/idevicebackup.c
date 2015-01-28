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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
#else
#include <gcrypt.h>
#endif
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/mobilebackup.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/afc.h>
#include "common/utils.h"

#define MOBILEBACKUP_SERVICE_NAME "com.apple.mobilebackup"
#define NP_SERVICE_NAME "com.apple.mobile.notification_proxy"

#define LOCK_ATTEMPTS 50
#define LOCK_WAIT 200000

#ifdef WIN32
#include <windows.h>
#define sleep(x) Sleep(x*1000)
#endif

static mobilebackup_client_t mobilebackup = NULL;
static lockdownd_client_t client = NULL;
static idevice_t device = NULL;

static int quit_flag = 0;

enum cmd_mode {
	CMD_BACKUP,
	CMD_RESTORE,
	CMD_LEAVE
};

enum device_link_file_status_t {
	DEVICE_LINK_FILE_STATUS_NONE = 0,
	DEVICE_LINK_FILE_STATUS_HUNK,
	DEVICE_LINK_FILE_STATUS_LAST_HUNK
};

static void sha1_of_data(const char *input, uint32_t size, unsigned char *hash_out)
{
#ifdef HAVE_OPENSSL
	SHA1((const unsigned char*)input, size, hash_out);
#else
	gcry_md_hash_buffer(GCRY_MD_SHA1, hash_out, input, size);
#endif
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
#ifdef HAVE_OPENSSL
	SHA_CTX sha1;
	SHA1_Init(&sha1);
#else
	gcry_md_hd_t hd = NULL;
	gcry_md_open(&hd, GCRY_MD_SHA1, 0);
	if (!hd) {
		printf("ERROR: Could not initialize libgcrypt/SHA1\n");
		return;
	}
	gcry_md_reset(hd);
#endif
	FILE *f = fopen(path, "rb");
	if (f) {
		unsigned char buf[16384];
		size_t len;
		while ((len = fread(buf, 1, 16384, f)) > 0) {
#ifdef HAVE_OPENSSL
			SHA1_Update(&sha1, buf, len);
#else
			gcry_md_write(hd, buf, len);
#endif
		}
		fclose(f);
#ifdef HAVE_OPENSSL
		SHA1_Update(&sha1, destpath, strlen(destpath));
		SHA1_Update(&sha1, ";", 1);
#else
		gcry_md_write(hd, destpath, strlen(destpath));
		gcry_md_write(hd, ";", 1);
#endif
		if (greylist == 1) {
#ifdef HAVE_OPENSSL
			SHA1_Update(&sha1, "true", 4);
#else
			gcry_md_write(hd, "true", 4);
#endif
		} else {
#ifdef HAVE_OPENSSL
			SHA1_Update(&sha1, "false", 5);
#else
			gcry_md_write(hd, "false", 5);
#endif
		}
#ifdef HAVE_OPENSSL
		SHA1_Update(&sha1, ";", 1);
#else
		gcry_md_write(hd, ";", 1);
#endif
		if (domain) {
#ifdef HAVE_OPENSSL
			SHA1_Update(&sha1, domain, strlen(domain));
#else
			gcry_md_write(hd, domain, strlen(domain));
#endif
		} else {
#ifdef HAVE_OPENSSL
			SHA1_Update(&sha1, "(null)", 6);
#else
			gcry_md_write(hd, "(null)", 6);
#endif
		}
#ifdef HAVE_OPENSSL
		SHA1_Update(&sha1, ";", 1);
#else
		gcry_md_write(hd, ";", 1);
#endif
		if (appid) {
#ifdef HAVE_OPENSSL
			SHA1_Update(&sha1, appid, strlen(appid));
#else
			gcry_md_write(hd, appid, strlen(appid));
#endif
		} else {
#ifdef HAVE_OPENSSL
			SHA1_Update(&sha1, "(null)", 6);
#else
			gcry_md_write(hd, "(null)", 6);
#endif
		}
#ifdef HAVE_OPENSSL
		SHA1_Update(&sha1, ";", 1);
#else
		gcry_md_write(hd, ";", 1);
#endif
		if (version) {
#ifdef HAVE_OPENSSL
			SHA1_Update(&sha1, version, strlen(version));
#else
			gcry_md_write(hd, version, strlen(version));
#endif
		} else {
#ifdef HAVE_OPENSSL
			SHA1_Update(&sha1, "(null)", 6);
#else
			gcry_md_write(hd, "(null)", 6);
#endif
		}
#ifdef HAVE_OPENSSL
		SHA1_Final(hash_out, &sha1);
#else
		unsigned char *newhash = gcry_md_read(hd, GCRY_MD_SHA1);
		memcpy(hash_out, newhash, 20);
#endif
	}
#ifndef HAVE_OPENSSL
	gcry_md_close(hd);
#endif
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

static plist_t mobilebackup_factory_info_plist_new(const char* udid)
{
	/* gather data from lockdown */
	plist_t value_node = NULL;
	plist_t root_node = NULL;
	char *udid_uppercase = NULL;

	plist_t ret = plist_new_dict();

	/* get basic device information in one go */
	lockdownd_get_value(client, NULL, NULL, &root_node);

	/* set fields we understand */
	value_node = plist_dict_get_item(root_node, "BuildVersion");
	plist_dict_set_item(ret, "Build Version", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "DeviceName");
	plist_dict_set_item(ret, "Device Name", plist_copy(value_node));
	plist_dict_set_item(ret, "Display Name", plist_copy(value_node));

	/* FIXME: How is the GUID generated? */
	plist_dict_set_item(ret, "GUID", plist_new_string("---"));

	value_node = plist_dict_get_item(root_node, "InternationalMobileEquipmentIdentity");
	if (value_node)
		plist_dict_set_item(ret, "IMEI", plist_copy(value_node));

	plist_dict_set_item(ret, "Last Backup Date", plist_new_date(time(NULL), 0));

	value_node = plist_dict_get_item(root_node, "ProductType");
	plist_dict_set_item(ret, "Product Type", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "ProductVersion");
	plist_dict_set_item(ret, "Product Version", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "SerialNumber");
	plist_dict_set_item(ret, "Serial Number", plist_copy(value_node));

	value_node = plist_dict_get_item(root_node, "UniqueDeviceID");
	plist_dict_set_item(ret, "Target Identifier", plist_new_string(udid));

	/* uppercase */
	udid_uppercase = string_toupper((char*)udid);
	plist_dict_set_item(ret, "Unique Identifier", plist_new_string(udid_uppercase));
	free(udid_uppercase);

	/* FIXME: Embed files as <data> nodes */
	plist_t files = plist_new_dict();
	plist_dict_set_item(ret, "iTunes Files", files);
	plist_dict_set_item(ret, "iTunes Version", plist_new_string("9.0.2"));

	plist_free(root_node);

	return ret;
}

static void mobilebackup_info_update_last_backup_date(plist_t info_plist)
{
	plist_t node = NULL;

	if (!info_plist)
		return;

	node = plist_dict_get_item(info_plist, "Last Backup Date");
	plist_set_date_val(node, time(NULL), 0);

	node = NULL;
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

static char *mobilebackup_build_path(const char *backup_directory, const char *name, const char *extension)
{
	char* filename = (char*)malloc(strlen(name)+(extension == NULL ? 0: strlen(extension))+1);
	strcpy(filename, name);
	if (extension != NULL)
		strcat(filename, extension);
	char *path = string_build_path(backup_directory, filename, NULL);
	free(filename);
	return path;
}

static void mobilebackup_write_status(const char *path, int status)
{
	struct stat st;
	plist_t status_plist = plist_new_dict();
	plist_dict_set_item(status_plist, "Backup Success", plist_new_bool(status));
	char *file_path = mobilebackup_build_path(path, "Status", ".plist");

	if (stat(file_path, &st) == 0)
		remove(file_path);

	plist_write_to_filename(status_plist, file_path, PLIST_FORMAT_XML);

	plist_free(status_plist);
	status_plist = NULL;

	free(file_path);
}

static int mobilebackup_read_status(const char *path)
{
	int ret = -1;
	plist_t status_plist = NULL;
	char *file_path = mobilebackup_build_path(path, "Status", ".plist");

	plist_read_from_filename(&status_plist, file_path);
	free(file_path);
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

	/* verify UDID */
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
	char *path = mobilebackup_build_path(backup_directory, hash, ".mddata");
	printf("Removing \"%s\" ", path);
	if (!remove( path ))
		ret = 1;
	else
		ret = 0;

	free(path);

	if (!ret)
		return ret;

	path = mobilebackup_build_path(backup_directory, hash, ".mdinfo");
	printf("and \"%s\"... ", path);
	if (!remove( path ))
		ret = 1;
	else
		ret = 0;

	free(path);

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

	free(domain);
	free(version);
	free(destpath);

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
	free(data_hash);
	plist_free(mdinfo);
	return res;
}

static void do_post_notification(const char *notification)
{
	lockdownd_service_descriptor_t service = NULL;
	np_client_t np;

	if (!client) {
		if (lockdownd_client_new_with_handshake(device, &client, "idevicebackup") != LOCKDOWN_E_SUCCESS) {
			return;
		}
	}

	lockdownd_start_service(client, NP_SERVICE_NAME, &service);
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
	printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
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
	lockdownd_service_descriptor_t service = NULL;
	int cmd = -1;
	int is_full_backup = 0;
	char *backup_directory = NULL;
	struct stat st;
	plist_t node = NULL;
	plist_t node_tmp = NULL;
	plist_t manifest_plist = NULL;
	plist_t info_plist = NULL;
	char *buffer = NULL;
	char *file_path = NULL;
	uint64_t length = 0;
	uint64_t backup_total_size = 0;
	enum device_link_file_status_t file_status = DEVICE_LINK_FILE_STATUS_NONE;
	uint64_t c = 0;

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
				return 0;
			}
			udid = strdup(argv[i]);
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
			free(info_path);
			printf("ERROR: Backup directory \"%s\" is invalid. No Info.plist found.\n", backup_directory);
			return -1;
		}
	}

	printf("Backup directory is \"%s\"\n", backup_directory);

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
	}

	if (LOCKDOWN_E_SUCCESS != (ldret = lockdownd_client_new_with_handshake(device, &client, "idevicebackup"))) {
		printf("ERROR: Could not connect to lockdownd, error code %d\n", ldret);
		idevice_free(device);
		return -1;
	}

	node = NULL;
	lockdownd_get_value(client, NULL, "ProductVersion", &node);
	if (node) {
		char* str = NULL;
		if (plist_get_node_type(node) == PLIST_STRING) {
			plist_get_string_val(node, &str);
		}
		plist_free(node);
		node = NULL;
		if (str) {
			int maj = strtol(str, NULL, 10);
			free(str);
			if (maj > 3) {
				printf("ERROR: This tool is only compatible with iOS 3 or below. For newer iOS versions please use the idevicebackup2 tool.\n");
				lockdownd_client_free(client);
				idevice_free(device);
				return -1;
			}
		}
	}

	/* start notification_proxy */
	np_client_t np = NULL;
	ldret = lockdownd_start_service(client, NP_SERVICE_NAME, &service);
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
		ldret = lockdownd_start_service(client, "com.apple.afc", &service);
		if ((ldret == LOCKDOWN_E_SUCCESS) && service->port) {
			afc_client_new(device, service, &afc);
		}
	}

	if (service) {
		lockdownd_service_descriptor_free(service);
		service = NULL;
	}

	/* start mobilebackup service and retrieve port */
	ldret = lockdownd_start_service(client, MOBILEBACKUP_SERVICE_NAME, &service);
	if ((ldret == LOCKDOWN_E_SUCCESS) && service && service->port) {
		printf("Started \"%s\" service on port %d.\n", MOBILEBACKUP_SERVICE_NAME, service->port);
		mobilebackup_client_new(device, service, &mobilebackup);

		if (service) {
			lockdownd_service_descriptor_free(service);
			service = NULL;
		}

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
				info_plist = mobilebackup_factory_info_plist_new(udid);
				plist_write_to_filename(info_plist, info_path, PLIST_FORMAT_XML);
			}
			free(info_path);

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
			uint64_t file_size = 0;
			uint64_t file_size_current = 0;
			int file_index = 0;
			int hunk_index = 0;
			uint64_t backup_real_size = 0;
			char *file_ext = NULL;
			char *filename_mdinfo = NULL;
			char *filename_mddata = NULL;
			char *filename_source = NULL;
			char *format_size = NULL;
			int is_manifest = 0;
			uint8_t b = 0;

			/* process series of DLSendFile messages */
			do {
				mobilebackup_receive(mobilebackup, &message);
				if (!message) {
					printf("Device is not ready yet. Going to try again in 2 seconds...\n");
					sleep(2);
					goto files_out;
				}

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
						format_size = string_format_size(backup_total_size);
						printf("Backup data requires %s on the disk.\n", format_size);
						free(format_size);
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
				is_manifest = (b == 1) ? 1 : 0;

				if ((hunk_index == 0) && (!is_manifest)) {
					/* get source filename */
					node = plist_dict_get_item(node_tmp, "DLFileSource");
					plist_get_string_val(node, &filename_source);

					/* increase received size */
					node = plist_dict_get_item(node_tmp, "DLFileAttributesKey");
					node = plist_dict_get_item(node, "FileSize");
					plist_get_uint_val(node, &file_size);
					backup_real_size += file_size;

					format_size = string_format_size(backup_real_size);
					printf("(%s", format_size);
					free(format_size);

					format_size = string_format_size(backup_total_size);
					printf("/%s): ", format_size);
					free(format_size);

					format_size = string_format_size(file_size);
					printf("Receiving file %s (%s)... \n", filename_source, format_size);
					free(format_size);

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

						free(filename_mdinfo);
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

					free(filename_mddata);
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

				if (message)
					plist_free(message);
				message = NULL;

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
files_out:
				if (quit_flag > 0) {
					/* need to cancel the backup here */
					mobilebackup_send_error(mobilebackup, "Cancelling DLSendFile");

					/* remove any atomic Manifest.plist.tmp */
					if (manifest_path)
						free(manifest_path);

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
			/* close down the lockdown connection as it is no longer needed */
			if (client) {
				lockdownd_client_free(client);
				client = NULL;
			}

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
					free(auth_sig);
				} else if (auth_ver) {
					printf("Unknown AuthVersion '%s', cannot verify AuthSignature\n", auth_ver);
				}
				plist_from_bin(bin, (uint32_t)binsize, &backup_data);
				free(bin);
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
						printf("Verifying file %d/%d (%d%%) \r", cur_file, total_files, (cur_file*100/total_files));
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

			printf("Requesting restore from device...\n");

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

			printf("Entered restore mode.\n");

			int restore_ok = 0;

			if (files && (plist_get_node_type(files) == PLIST_DICT)) {
				plist_dict_iter iter = NULL;
				plist_dict_new_iter(files, &iter);
				if (iter) {
					/* loop over Files entries in Manifest data plist */
					char *hash = NULL;
					plist_t file_info = NULL;
					char *file_info_path = NULL;
					int total_files = plist_dict_get_size(files);
					int cur_file = 0;
					uint64_t file_offset = 0;
					uint8_t is_encrypted = 0;
					plist_t tmp_node = NULL;
					plist_t file_path_node = NULL;
					plist_t send_file_node = NULL;
					node = NULL;
					plist_dict_next_item(files, iter, &hash, &node);
					while (node) {
						/* TODO: read mddata/mdinfo files and send to device using DLSendFile */
						file_info_path = mobilebackup_build_path(backup_directory, hash, ".mdinfo");
						plist_read_from_filename(&file_info, file_info_path);

						/* get encryption state */
						tmp_node = plist_dict_get_item(file_info, "IsEncrypted");
						plist_get_bool_val(tmp_node, &is_encrypted);
						tmp_node = NULL;

						/* get real file path from metadata */
						tmp_node = plist_dict_get_item(file_info, "Metadata");
						plist_get_data_val(tmp_node, &buffer, &length);
						tmp_node = NULL;
						plist_from_bin(buffer, length, &tmp_node);
						file_path_node = plist_dict_get_item(tmp_node, "Path");
						plist_get_string_val(file_path_node, &file_path);

						printf("Restoring file %s %d/%d (%d%%)... ", file_path, cur_file, total_files, (cur_file*100/total_files));

						/* add additional device link file information keys */
						plist_dict_set_item(file_info, "DLFileAttributesKey", plist_copy(node));
						plist_dict_set_item(file_info, "DLFileSource", plist_new_string(file_info_path));
						plist_dict_set_item(file_info, "DLFileDest", plist_new_string("/tmp/RestoreFile.plist"));
						plist_dict_set_item(file_info, "DLFileIsEncrypted", plist_new_bool(is_encrypted));
						plist_dict_set_item(file_info, "DLFileOffsetKey", plist_new_uint(file_offset));
						plist_dict_set_item(file_info, "DLFileStatusKey", plist_new_uint(file_status));

						/* read data from file */
						free(file_info_path);
						file_info_path = mobilebackup_build_path(backup_directory, hash, ".mddata");

						/* determine file size */
#ifdef WIN32
						struct _stati64 fst;
						if (_stati64(file_info_path, &fst) != 0)
#else
						struct stat fst;
						if (stat(file_info_path, &fst) != 0)
#endif
						{
							printf("ERROR: stat() failed for '%s': %s\n", file_info_path, strerror(errno));
							free(file_info_path);
							break;
						}
						length = fst.st_size;

						FILE *f = fopen(file_info_path, "rb");
						if (!f) {
							printf("ERROR: could not open local file '%s': %s\n", file_info_path, strerror(errno));
							free(file_info_path);
							break;
						}
						free(file_info_path);

						/* send DLSendFile messages */
						file_offset = 0;
						do {
							char buf[8192];
							size_t len = fread(buf, 1, sizeof(buf), f);

							if ((length-file_offset) <= sizeof(buf))
								file_status = DEVICE_LINK_FILE_STATUS_LAST_HUNK;
							else
								file_status = DEVICE_LINK_FILE_STATUS_HUNK;

							plist_dict_remove_item(file_info, "DLFileOffsetKey");
							plist_dict_set_item(file_info, "DLFileOffsetKey", plist_new_uint(file_offset));

							plist_dict_remove_item(file_info, "DLFileStatusKey");
							plist_dict_set_item(file_info, "DLFileStatusKey", plist_new_uint(file_status));

							send_file_node = plist_new_array();

							plist_array_append_item(send_file_node, plist_new_string("DLSendFile"));

							plist_array_append_item(send_file_node, plist_new_data(buf, len));
							plist_array_append_item(send_file_node, plist_copy(file_info));

							err = mobilebackup_send(mobilebackup, send_file_node);
							if (err != MOBILEBACKUP_E_SUCCESS) {
								printf("ERROR: Unable to send file hunk due to error %d. Aborting...\n", err);
								file_status = DEVICE_LINK_FILE_STATUS_NONE;
							}

							if (file_status == DEVICE_LINK_FILE_STATUS_LAST_HUNK) {
								/* TODO: if all hunks of a file are sent, device must send ack */
								err = mobilebackup_receive_restore_file_received(mobilebackup, NULL);
								if (err != MOBILEBACKUP_E_SUCCESS) {
									printf("ERROR: Did not receive an ack for the sent file due to error %d. Aborting...\n", err);
									file_status = DEVICE_LINK_FILE_STATUS_NONE;
								}
							}

							file_offset += len;

							if (file_status == DEVICE_LINK_FILE_STATUS_LAST_HUNK)
								printf("DONE\n");

							plist_free(send_file_node);

							if (file_status == DEVICE_LINK_FILE_STATUS_NONE)
								break;

						} while((file_offset < length));

						free(hash);
						node = NULL;
						hash = NULL;

						restore_ok = 1;
						if (file_status == DEVICE_LINK_FILE_STATUS_NONE) {
							restore_ok = 0;
							break;
						}

						cur_file++;
						plist_dict_next_item(files, iter, &hash, &node);
					}
					free(iter);

					printf("Restored %d files on device.\n", cur_file);
				}
			}
			/* TODO: observe notification_proxy id com.apple.mobile.application_installed */
			/* TODO: loop over Applications entries in Manifest data plist */
			plist_t applications = plist_dict_get_item(backup_data, "Applications");
			if (applications && (plist_get_node_type(applications) == PLIST_DICT) && restore_ok) {
				plist_dict_iter iter = NULL;
				plist_dict_new_iter(applications, &iter);
				if (iter) {
					/* loop over Application entries in Manifest data plist */
					char *hash = NULL;
					int total_files = plist_dict_get_size(applications);
					int cur_file = 1;
					plist_t tmp_node = NULL;
					plist_t dict = NULL;
					plist_t array = NULL;
					node = NULL;
					plist_dict_next_item(applications, iter, &hash, &node);
					while (node) {
						printf("Restoring Application %s %d/%d (%d%%)...", hash, cur_file, total_files, (cur_file*100/total_files));
						/* FIXME: receive com.apple.mobile.application_installed notification */
						/* send AppInfo entry */
						tmp_node = plist_dict_get_item(node, "AppInfo");

						dict = plist_new_dict();
						plist_dict_set_item(dict, "AppInfo", plist_copy(tmp_node));
						plist_dict_set_item(dict, "BackupMessageTypeKey", plist_new_string("BackupMessageRestoreApplicationSent"));

						array = plist_new_array();
						plist_array_append_item(array, plist_new_string("DLMessageProcessMessage"));
						plist_array_append_item(array, dict);

						err = mobilebackup_send(mobilebackup, array);
						if (err != MOBILEBACKUP_E_SUCCESS) {
							printf("ERROR: Unable to restore application %s due to error %d. Aborting...\n", hash, err);
							restore_ok = 0;
						}

						plist_free(array);
						array = NULL;
						dict = NULL;

						/* receive BackupMessageRestoreApplicationReceived from device */
						if (restore_ok) {
							err = mobilebackup_receive_restore_application_received(mobilebackup, NULL);
							if (err != MOBILEBACKUP_E_SUCCESS) {
								printf("ERROR: Failed to receive an ack from the device for this application due to error %d. Aborting...\n", err);
								restore_ok = 0;
							}
						}

						tmp_node = NULL;
						node = NULL;
						free(hash);
						hash = NULL;

						if (restore_ok) {
							printf("DONE\n");
							cur_file++;
							plist_dict_next_item(applications, iter, &hash, &node);
						} else
							break;
					}
					free(iter);

					if (restore_ok)
						printf("All applications restored.\n");
					else
						printf("Failed to restore applications.\n");
				}
			}

			plist_free(backup_data);

			/* signal restore finished message to device; BackupMessageRestoreComplete */
			if (restore_ok) {
				err = mobilebackup_send_restore_complete(mobilebackup);
				if (err != MOBILEBACKUP_E_SUCCESS) {
					printf("ERROR: Could not send BackupMessageRestoreComplete, error code %d\n", err);
					}
			}

			if (restore_ok) {
				printf("Restore Successful.\n");
			} else {
				printf("Restore Failed.\n");
			}
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
			free(manifest_path);
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

	idevice_free(device);

	if (udid) {
		free(udid);
	}

	return 0;
}

