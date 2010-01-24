/*
 * iphonebackup.c
 * Command line interface to use the device's backup and restore service
 *
 * Copyright (c) 2009 Martin Szulecki All Rights Reserved.
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

#include <libiphone/libiphone.h>
#include <libiphone/lockdown.h>
#include <libiphone/mobilebackup.h>

#define MOBILEBACKUP_SERVICE_NAME "com.apple.mobilebackup"

static mobilebackup_client_t mobilebackup = NULL;
static lockdownd_client_t client = NULL;
static iphone_device_t phone = NULL;

static int quit_flag = 0;

enum cmd_mode {
	CMD_BACKUP,
	CMD_RESTORE
};

static plist_t mobilebackup_factory_info_plist()
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
	iphone_device_get_uuid(phone, &uuid);
	plist_dict_insert_item(ret, "Target Identifier", plist_new_string(uuid));

	/* uppercase */
	uuid_uppercase = g_ascii_strup(uuid, -1);
	plist_dict_insert_item(ret, "Unique Identifier", plist_new_string(uuid_uppercase));
	free(uuid_uppercase);
	free(uuid);

	plist_t files = plist_new_dict();
	/* FIXME: Embed files as <data> nodes */
	plist_dict_insert_item(ret, "iTunes Files", files);
	plist_dict_insert_item(ret, "iTunes Version", plist_new_string("9.0.2"));

	return ret;
}

static plist_t mobilebackup_factory_metadata_plist()
{
	plist_t ret = NULL;
/*
Metadata key is:
<dict>
	<key>Path</key>
	<string>Library/SMS/sms.db</string>
	<key>Version</key>
	<string>3.0</string>
	<key>Greylist</key>
	<false/>
	<key>Domain</key>
	<string>HomeDomain</string>
</dict>
*/
/*
<dict>
	<key>Metadata</key>
	<data><!-- binary plist -->
	YnBsaXN0MDDUAQIDBAUGBwhUUGF0aFdWZXJzaW9uWEdyZXlsaXN0VkRvbWFp
	bl8QEkxpYnJhcnkvU01TL3Ntcy5kYlMzLjAIWkhvbWVEb21haW4IERYeJy5D
	R0gAAAAAAAABAQAAAAAAAAAJAAAAAAAAAAAAAAAAAAAAUw==
	</data>
	<key>StorageVersion</key>
	<string>1.0</string>
	<key>Version</key>
	<string>3.0</string>
	<key>AuthVersion</key>
	<string>1.0</string>
	<key>IsEncrypted</key>
	<false/>
</dict>
*/
	return ret;
}

/**
 * Generates a manifest data plist with all files and corresponding hashes
 */
static plist_t mobilebackup_factory_manifest_data_plist()
{
	plist_t ret = NULL;
	plist_t value_node = NULL;
	char *uuid = NULL;
	GTimeVal tv = {0, 0};

	ret = plist_new_dict();

	/* get basic device information in one go */
	lockdownd_get_value(client, NULL, "IntegratedCircuitCardIdentity", &value_node);

	iphone_device_get_uuid(phone, &uuid);
	plist_dict_insert_item(ret, "DeviceId", plist_new_string(uuid));
	free(uuid);

	plist_dict_insert_item(ret, "Version", plist_new_string("6.2"));

	/* TODO: add all Applications */

	/* TODO: add all Files */
	plist_t files = plist_new_dict();

	/* single file entry */
	plist_t info_node = plist_new_dict();
	g_get_current_time(&tv);
	plist_dict_insert_item(info_node, "ModificationTime", plist_new_date(tv.tv_sec, tv.tv_usec));
	plist_dict_insert_item(info_node, "FileLength", plist_new_uint(131072));
	plist_dict_insert_item(info_node, "Domain", plist_new_string("HomeDomain"));

	/* FIXME: calculate correct data hash */
	/* Data hash is: sha1(<file>) */
	plist_dict_insert_item(info_node, "DataHash", plist_new_data(NULL, 0));
	plist_dict_insert_item(info_node, "Group ID", plist_new_uint(501));
	plist_dict_insert_item(info_node, "User ID", plist_new_uint(501));
	plist_dict_insert_item(info_node, "Mode ID", plist_new_uint(420));

	/* FIXME: calculate correct file hash */
	/* File hash is: sha1(<Domain>-<Relative File Path>) */
	plist_dict_insert_item(files, "3d0d7e5fb2ce288813306e4d4636395e047a3d28", info_node);
	plist_dict_insert_item(ret, "Files", files);

	/* last node with ICCID */
	if (value_node)
		plist_dict_insert_item(ret, "DeviceICCID", &value_node);

	return ret;
}

/**
 * Generates a manifest plist with all needed information and hashes
 */
static plist_t mobilebackup_factory_manifest_plist(plist_t manifest_data)
{
	char *buffer = NULL;
	char *s = NULL;
	uint32_t length;
	unsigned char sha1[20];
	gsize sha1_len;
	GChecksum *checksum;
	plist_t ret = NULL;

	if (!manifest_data)
		return ret;

	ret = plist_new_dict();
	plist_dict_insert_item(ret, "AuthVersion", plist_new_string("2.0"));

	/* AuthSignature Hash is: sha1(<manifest_data>) */
	plist_to_bin(manifest_data, &buffer, &length);

	sha1_len = g_checksum_type_get_length(G_CHECKSUM_SHA1);
	checksum = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(checksum, (guchar *)buffer, length);
	g_checksum_get_digest(checksum, sha1, &sha1_len);
	s = (char *)g_checksum_get_string(checksum);
	printf("SHA1 AuthSignature: %s\n", s);
	plist_dict_insert_item(ret, "AuthSignature", plist_new_data((char*)sha1, sha1_len));
	g_checksum_free(checksum);


	plist_dict_insert_item(ret, "IsEncrypted", plist_new_uint(0));
	plist_dict_insert_item(ret, "Data", plist_new_data(buffer, length));

	free(buffer);

	return ret;
}

enum plist_format_t {
	PLIST_FORMAT_XML,
	PLIST_FORMAT_BINARY
};

static int plist_read_from_filename(char *filename, plist_t *plist)
{
	return 1;
}

static int plist_write_to_filename(plist_t plist, char *filename, enum plist_format_t format)
{
	char *buffer = NULL;
	uint32_t length;
	FILE *f;

	if (!plist || !filename)
		return 0;

	if (format == PLIST_FORMAT_XML)
		plist_to_xml(plist, &buffer, &length);
	else if (format == PLIST_FORMAT_BINARY)
		plist_to_bin(plist, &buffer, &length);
	else
		return 0;

	f = fopen(filename, "wb");
	fwrite(buffer, sizeof(char), length, f);
	fclose(f);

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

static void mobilebackup_write_status(char *path, int status)
{
	plist_t status_plist = plist_new_dict();
	plist_dict_insert_item(status_plist, "Backup Success", plist_new_bool(status));
	char *file_path = g_build_path(G_DIR_SEPARATOR_S, path, "Status.plist", NULL);
	plist_write_to_filename(status_plist, file_path, PLIST_FORMAT_XML);
	g_free(file_path);
	plist_free(status_plist);
}

static void debug_plist(plist_t plist)
{
	char *buffer = NULL;
	uint32_t length = 0;

	if (!plist)
		return;

	plist_to_xml(plist, &buffer, &length);

	printf("Printing %i bytes plist:\n%s\n", length, buffer);
	free(buffer);
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
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	int i;
	char uuid[41];
	uint16_t port = 0;
	uuid[0] = 0;
	int cmd = -1;
	char *backup_directory = NULL;
	struct stat st;
	plist_t node = NULL;

	/* we need to exit cleanly on running backups and restores or we cause havok */
	signal(SIGINT, clean_exit);
	signal(SIGQUIT, clean_exit);
	signal(SIGTERM, clean_exit);
	signal(SIGPIPE, SIG_IGN);

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			iphone_set_debug_level(1);
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
	char *info_path = g_build_path(G_DIR_SEPARATOR_S, backup_directory, "Info.plist", NULL);
	if (cmd == CMD_RESTORE) {
		if (stat(info_path, &st) != 0) {
			g_free(info_path);
			printf("ERROR: Backup directory \"%s\" is invalid. No Info.plist found.\n", backup_directory);
			return -1;
		}
	}

	printf("Backup directory is \"%s\"\n", backup_directory);

	if (uuid[0] != 0) {
		ret = iphone_device_new(&phone, uuid);
		if (ret != IPHONE_E_SUCCESS) {
			printf("No device found with uuid %s, is it plugged in?\n", uuid);
			return -1;
		}
	}
	else
	{
		ret = iphone_device_new(&phone, NULL);
		if (ret != IPHONE_E_SUCCESS) {
			printf("No device found, is it plugged in?\n");
			return -1;
		}
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(phone, &client, "iphonebackup")) {
		iphone_device_free(phone);
		return -1;
	}

	/* start syslog_relay service and retrieve port */
	ret = lockdownd_start_service(client, MOBILEBACKUP_SERVICE_NAME, &port);
	if ((ret == LOCKDOWN_E_SUCCESS) && port) {
		printf("Started \"%s\" service on port %d.\n", MOBILEBACKUP_SERVICE_NAME, port);
		mobilebackup_client_new(phone, port, &mobilebackup);

		switch(cmd) {
			case CMD_BACKUP:
			printf("Starting backup...\n");
			/* TODO: check domain com.apple.mobile.backup key RequiresEncrypt and WillEncrypt with lockdown */
			/* TODO: verify battery on AC enough battery remaining */

			/* ????: create target directory: MobileSync/Backup/<uuid>-YYYYMMDD-HHMMSS/ */

			/* create Info.plist (Device infos, IC-Info.sidb, photos, app_ids, iTunesPrefs) */
			printf("Creating \"%s/Info.plist\".\n", backup_directory);
			plist_t info_plist = mobilebackup_factory_info_plist();
			plist_write_to_filename(info_plist, info_path, PLIST_FORMAT_XML);
			g_free(info_path);

			/* create Manifest.plist (backup manifest (backup state)) */
			printf("Creating \"%s/Manifest.plist\".\n", backup_directory);
			char *manifest_path = g_build_path(G_DIR_SEPARATOR_S, backup_directory, "Manifest.plist", NULL);
			plist_t manifest_data = mobilebackup_factory_manifest_data_plist();
			plist_t manifest_plist = mobilebackup_factory_manifest_plist(manifest_data);
			plist_write_to_filename(manifest_plist, manifest_path, PLIST_FORMAT_XML);
			g_free(manifest_path);

			/* create Status.plist with failed status for now */
			mobilebackup_write_status(backup_directory, 0);

			/* close down lockdown connection as it is no longer needed */
			lockdownd_client_free(client);
			client = NULL;

			/* request backup from device with manifest */
			printf("Sending manifest and requesting backup.\n");

			node = plist_new_dict();
			plist_dict_insert_item(node, "BackupManifestKey", manifest_plist);
			plist_dict_insert_item(node, "BackupComputerBasePathKey", plist_new_string("/"));
			plist_dict_insert_item(node, "BackupMessageTypeKey", plist_new_string("BackupMessageBackupRequest"));
			plist_dict_insert_item(node, "BackupProtocolVersion", plist_new_string("1.6"));

			plist_t message = plist_new_array();
			plist_array_append_item(message, plist_new_string("DLMessageProcessMessage"));
			plist_array_append_item(message, node);

			mobilebackup_send(mobilebackup, message);
			plist_free(message);
			message = NULL;

			/* get response */
			int backup_ok = 0;
			mobilebackup_receive(mobilebackup, &message);
			node = plist_array_get_item(message, 0);
			if (!plist_strcmp(node, "DLMessageProcessMessage")) {
				node = plist_array_get_item(message, 1);
				node = plist_dict_get_item(node, "BackupMessageTypeKey");
				if (node && !plist_strcmp(node, "BackupMessageBackupReplyOK")) {
					printf("Device accepts manifest and will send backup data now...\n");
					backup_ok = 1;
					printf("Acknowledging...\n");
					/* send it back for ACK */
					mobilebackup_send(mobilebackup, message);
				}
			} else {
				printf("Unhandled message received!\n");
				debug_plist(message);
			}
			plist_free(message);
			message = NULL;

			if (!backup_ok) {
				printf("ERROR: Device rejected to start the backup process.\n");
				break;
			}

			/* receive and save DLSendFile files and metadata, ACK each */
			int file_index = 0;
			do {
				mobilebackup_receive(mobilebackup, &message);
				node = plist_array_get_item(message, 0);
				if (plist_strcmp(node, "DLSendFile"))
					break;

				printf("Receiving file %d...\n", file_index);
				/* TODO: save <hash>.mdinfo */
				/* TODO: save <hash>.mddata */
				debug_plist(message);
				plist_free(message);
				message = NULL;

				if (quit_flag) {
					/* FIXME: need to cancel the backup here */
					break;
				}

				/* acknowlegdge that we received the file */
				node = plist_new_dict();
				plist_dict_insert_item(node, "BackupMessageTypeKey", plist_new_string("kBackupMessageBackupFileReceived"));

				message = plist_new_array();
				plist_array_append_item(message, plist_new_string("DLMessageProcessMessage"));
				plist_array_append_item(message, node);
				mobilebackup_send(mobilebackup, message);

				plist_free(message);
				message = NULL;

				file_index++;
			} while (!plist_strcmp(node, "DLSendFile"));

			printf("Received %d files from device.\n", file_index);

			if (!plist_strcmp(node, "DLMessageProcessMessage")) {
				node = plist_array_get_item(message, 1);
				node = plist_dict_get_item(node, "BackupMessageTypeKey");
				/* wait until received final backup finished message */
				if (node && !plist_strcmp(node, "BackupMessageBackupFinished")) {
					/* backup finished */
					/* create: Status.plist (Info on how the backup process turned out) */
					printf("Backup Successful.\n");
					mobilebackup_write_status(backup_directory, 1);
				}
			}

			if (node)
				plist_free(node);

			break;
			case CMD_RESTORE:
			printf("Restoring backup...\n");
			/* verify battery on AC enough battery remaining */
			/* request restore from device (BackupMessageRestoreMigrate) */
			/* read mddata files and send to devices using DLSendFile */
			/* signal restore finished message to device */
			/* close down lockdown connection as it is no longer needed */
			lockdownd_client_free(client);
			client = NULL;
			break;
			default:
			break;
		}
	} else {
		printf("ERROR: Could not start service %s.\n", MOBILEBACKUP_SERVICE_NAME);
		lockdownd_client_free(client);
		client = NULL;
	}

	if (client)
		lockdownd_client_free(client);

	if (mobilebackup)
		mobilebackup_client_free(mobilebackup);
	iphone_device_free(phone);

	return 0;
}

