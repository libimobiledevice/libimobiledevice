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
	CMD_RESTORE,
	CMD_LEAVE
};

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

enum plist_format_t {
	PLIST_FORMAT_XML,
	PLIST_FORMAT_BINARY
};

static void buffer_to_filename(char *filename, char *buffer, uint32_t length)
{
	FILE *f;

	f = fopen(filename, "ab");
	fwrite(buffer, sizeof(char), length, f);
	fclose(f);
}

static int plist_write_to_filename(plist_t plist, char *filename, enum plist_format_t format)
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

	buffer_to_filename(filename, buffer, length);

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

static plist_t device_link_message_factory_process_message_new(plist_t content)
{
	plist_t ret = plist_new_array();
	plist_array_append_item(ret, plist_new_string("DLMessageProcessMessage"));
	plist_array_append_item(ret, content);
	return ret;
}

static void mobilebackup_cancel_backup_with_error(const char *reason)
{
	plist_t node = plist_new_dict();
	plist_dict_insert_item(node, "BackupMessageTypeKey", plist_new_string("BackupMessageError"));
	plist_dict_insert_item(node, "BackupErrorReasonKey", plist_new_string(reason));

	plist_t message = device_link_message_factory_process_message_new(node);

	mobilebackup_send(mobilebackup, message);

	plist_free(message);
	message = NULL;
}

static void mobilebackup_write_status(char *path, int status)
{
	struct stat st;
	plist_t status_plist = plist_new_dict();
	plist_dict_insert_item(status_plist, "Backup Success", plist_new_bool(status));
	char *file_path = g_build_path(G_DIR_SEPARATOR_S, path, "Status.plist", NULL);
	if (stat(file_path, &st) == 0)
		remove(file_path);
	plist_write_to_filename(status_plist, file_path, PLIST_FORMAT_XML);
	g_free(file_path);
	plist_free(status_plist);
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
	plist_t node_tmp = NULL;
	char *buffer = NULL;
	uint64_t length = 0;
	uint64_t backup_total_size = 0;
	uint64_t c = 0;

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

		if (quit_flag > 0) {
			printf("Aborting backup. Cancelled by user.\n");
			cmd = CMD_LEAVE;
		}

		switch(cmd) {
			case CMD_BACKUP:
			printf("Starting backup...\n");
			/* TODO: check domain com.apple.mobile.backup key RequiresEncrypt and WillEncrypt with lockdown */
			/* TODO: verify battery on AC enough battery remaining */

			/* create Info.plist (Device infos, IC-Info.sidb, photos, app_ids, iTunesPrefs) */
			printf("Creating Info.plist.\n");
			plist_t info_plist = mobilebackup_factory_info_plist_new();
			if (stat(info_path, &st) == 0)
				remove(info_path);
			plist_write_to_filename(info_plist, info_path, PLIST_FORMAT_XML);
			g_free(info_path);

			/* close down the lockdown connection as it is no longer needed */
			if (client) {
				lockdownd_client_free(client);
				client = NULL;
			}

			/* create Manifest.plist (backup manifest (backup state)) */
			char *manifest_path = g_build_path(G_DIR_SEPARATOR_S, backup_directory, "Manifest.plist", NULL);
			/* FIXME: We should read the last Manifest.plist and send it to the device */
			plist_t manifest_plist = NULL;
			if (stat(manifest_path, &st) == 0)
				remove(manifest_path);

			/* create Status.plist with failed status for now */
			mobilebackup_write_status(backup_directory, 0);

			/* request backup from device with manifest from last backup */
			printf("Requesting backup from device...\n");

			node = plist_new_dict();
			if (manifest_plist)
				plist_dict_insert_item(node, "BackupManifestKey", manifest_plist);
			plist_dict_insert_item(node, "BackupComputerBasePathKey", plist_new_string("/"));
			plist_dict_insert_item(node, "BackupMessageTypeKey", plist_new_string("BackupMessageBackupRequest"));
			plist_dict_insert_item(node, "BackupProtocolVersion", plist_new_string("1.6"));

			plist_t message = device_link_message_factory_process_message_new(node);
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
					printf("Please wait. Device prepares backup data...\n");
					/* send it back for ACK */
					mobilebackup_send(mobilebackup, message);
				}
			} else {
				printf("ERROR: Unhandled message received!\n");
			}
			plist_free(message);
			message = NULL;

			if (!backup_ok) {
				printf("ERROR: Device rejected to start the backup process.\n");
				break;
			}

			/* reset backup status */
			backup_ok = 0;

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
			do {
				mobilebackup_receive(mobilebackup, &message);
				node = plist_array_get_item(message, 0);
				if (plist_strcmp(node, "DLSendFile"))
					break;

				node_tmp = plist_array_get_item(message, 2);

				/* first message hunk contains total backup size */
				if (hunk_index == 0) {
					node = plist_dict_get_item(node_tmp, "BackupTotalSizeKey");
					if (node) {
						plist_get_uint_val(node, &backup_total_size);
						format_size = g_format_size_for_display(backup_total_size);
						printf("Backup data requires %s on the disk.\n", format_size);
						g_free(format_size);
					}
				}

				/* print out "received" if DLFileStatusKey is 2 (last file piece) */
				node = plist_dict_get_item(node_tmp, "DLFileStatusKey");
				plist_get_uint_val(node, &c);

				/* get source filename */
				node = plist_dict_get_item(node_tmp, "BackupManifestKey");
				b = 0;
				if (node) {
					plist_get_bool_val(node, &b);
				}
				is_manifest = (b == 1) ? TRUE: FALSE;

				/* increased received size for each completed file */
				if ((c == 2) && (!is_manifest)) {
					/* get source filename */
					node = plist_dict_get_item(node_tmp, "DLFileSource");
					plist_get_string_val(node, &filename_source);

					node = plist_dict_get_item(node_tmp, "DLFileAttributesKey");
					node = plist_dict_get_item(node, "FileSize");
					plist_get_uint_val(node, &length);

					backup_real_size += length;
					file_index++;

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
						file_ext = (char *)g_strconcat(file_path, ".mdinfo", NULL);
						filename_mdinfo = g_build_path(G_DIR_SEPARATOR_S, backup_directory, file_ext, NULL);
						node = plist_dict_get_item(node_tmp, "BackupFileInfo");
						plist_write_to_filename(node, filename_mdinfo, PLIST_FORMAT_BINARY);
						g_free(file_ext);
						g_free(filename_mdinfo);
					}
				}

				/* save <hash>.mddata */
				node = plist_dict_get_item(node_tmp, "BackupFileInfo");
				if (node_tmp && file_path) {
					node = plist_dict_get_item(node_tmp, "DLFileDest");
					plist_get_string_val(node, &file_path);

					if (!is_manifest)
						file_ext = (char *)g_strconcat(file_path, ".mddata", NULL);
					else
						file_ext = g_strdup(file_path);

					filename_mddata = g_build_path(G_DIR_SEPARATOR_S, backup_directory, file_ext, NULL);
					node_tmp = plist_array_get_item(message, 1);
					plist_get_data_val(node_tmp, &buffer, &length);

					buffer_to_filename(filename_mddata, buffer, length);

					/* activate currently sent manifest */
					if ((c == 2) && (is_manifest)) {
						rename(filename_mddata, manifest_path);
					}
					free(buffer);
					buffer = NULL;
					g_free(filename_mddata);
				}

				if ((c == 2) && (!is_manifest)) {
					printf("DONE\n");
				}

				hunk_index++;

				if (file_ext)
					free(file_ext);

				plist_free(message);
				message = NULL;

				if (quit_flag > 0) {
					/* need to cancel the backup here */
					mobilebackup_cancel_backup_with_error("Cancelling DLSendFile");

					plist_free(message);
					message = NULL;
					break;
				}

				/* acknowlegdge that we received the file */
				node = plist_new_dict();
				plist_dict_insert_item(node, "BackupMessageTypeKey", plist_new_string("kBackupMessageBackupFileReceived"));

				message = device_link_message_factory_process_message_new(node);
				mobilebackup_send(mobilebackup, message);

				plist_free(message);
				message = NULL;
			} while (1);

			printf("Received %d files from device.\n", file_index);

			if (!plist_strcmp(node, "DLMessageProcessMessage")) {
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

							file_ext = (char *)g_strconcat(file_path, ".mddata", NULL);
							filename_mddata = g_build_path(G_DIR_SEPARATOR_S, backup_directory, file_ext, NULL);
							g_free(file_ext);
							printf("Removing \"%s\"... ", filename_mddata);
							if (!remove( filename_mddata )) {
								printf("DONE\n");
							} else
								printf("FAILED\n");

							file_ext = (char *)g_strconcat(file_path, ".mdinfo", NULL);
							filename_mdinfo = g_build_path(G_DIR_SEPARATOR_S, backup_directory, file_ext, NULL);
							g_free(file_ext);
							printf("Removing \"%s\"... ", filename_mdinfo);
							if (!remove( filename_mdinfo )) {
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
				/* create: Status.plist (Info on how the backup process turned out) */
				printf("Backup Successful.\n");
				mobilebackup_write_status(backup_directory, 1);
			} else {
				printf("Backup Failed.\n");
			}

			if (manifest_path)
				g_free(manifest_path);

			if (node)
				plist_free(node);

			break;
			case CMD_RESTORE:
			printf("Restoring backup is NOT IMPLEMENTED.\n");
			/* verify battery on AC enough battery remaining */
			/* request restore from device with manifest (BackupMessageRestoreMigrate) */
			/* read mddata/mdinfo files and send to devices using DLSendFile */
			/* signal restore finished message to device */
			/* close down lockdown connection as it is no longer needed */
			lockdownd_client_free(client);
			client = NULL;
			break;
			case CMD_LEAVE:
			default:
			break;
		}
	} else {
		printf("ERROR: Could not start service %s.\n", MOBILEBACKUP_SERVICE_NAME);
		lockdownd_client_free(client);
		client = NULL;
	}

	if (client) {
		lockdownd_client_free(client);
		client = NULL;
	}

	if (mobilebackup)
		mobilebackup_client_free(mobilebackup);

	iphone_device_free(phone);

	return 0;
}

