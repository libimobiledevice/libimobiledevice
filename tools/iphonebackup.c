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

#include <libiphone/libiphone.h>
#include <libiphone/lockdown.h>
#include <libiphone/mobilebackup.h>

#define MOBILEBACKUP_SERVICE_NAME "com.apple.mobilebackup"

static int quit_flag = 0;

enum cmd_mode {
	CMD_BACKUP,
	CMD_RESTORE
};

/*
Backup Process Communication:
--------------------------------------------------------------------------------
* Check lockdown value for domain com.apple.mobile.backup key RequiresEncrypt and WillEncrypt
* Verify battery on AC enough battery remaining
* ValidatePair with device for TrustedHost ability
> DLMessageVersionExchange
< DLMessageVersionExchange - DLVersionsOk
> DLMessageDeviceReady
< DLMessageProcessMessage: BackupMessageTypeKey: BackupMessageBackupRequest
> DLMessageProcessMessage: BackupMessageTypeKey: BackupMessageBackupReplyOK
...
> DLSendFile
< DLMessageProcessMessage: BackupMessageTypeKey: BackupMessageBackupFileReceived
...
> DLMessageProcessMessage: BackupMessageTypeKey: BackupMessageBackupFinished


*/

/*
Restore Process Communication:
--------------------------------------------------------------------------------
* Verify battery on AC enough battery remaining
* ValidatePair with device for TrustedHost ability
> DLMessageVersionExchange
< DLMessageVersionExchange - DLVersionsOk
> DLMessageDeviceReady
< DLMessageProcessMessage - BackupMessageTypeKey: BackupMessageRestoreMigrate
...
DLSendFile
...
< DLMessageProcessMessage - BackupMessageTypeKey: BackupMessageRestoreReplyOK
*/

static plist_t mobilebackup_factory_metadata()
{
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
}

/**
 * Generates a manifest data plist with all files and corresponding hashes
 */
static plist_t mobilebackup_factory_manifest_data_plist()
{
	plist_t manifest_data = plist_dict_new();
	/*
	File hash is:
	sha1(<Domain>-<Relative File Path>)
	*/
	/*
	Data hash is:
	sha1(<file>)
	*/

/*
<dict>
	<key>DeviceId</key>
	<string>7a7b570ee169f02c43d3893f0d661cf7a32e1cf5</string>
	<key>Version</key>
	<string>6.2</string>
	<key>Files</key>
	<dict>
		<key>3d0d7e5fb2ce288813306e4d4636395e047a3d28</key>
		<dict>
			<key>ModificationTime</key>
			<date>2009-12-29T02:12:17Z</date>
			<key>FileLength</key>
			<integer>131072</integer>
			<key>Domain</key>
			<string>HomeDomain</string>
			<key>DataHash</key>
			<data>
			MfpSk+qw+RAJqLNTJI81tntvrwc=
			</data>
			<key>Group ID</key>
			<integer>501</integer>
			<key>User ID</key>
			<integer>501</integer>
			<key>Mode</key>
			<integer>420</integer>
		</dict>
	</dict>
	<key>DeviceICCID</key>
	<string>89492060399209300736</string>
</dict>
*/

	return manifest_data;
}

/**
 * Generates a manifest plist with all needed information and hashes
 */
static plist_t mobilebackup_factory_manifest_plist()
{
	plist_t manifest_data = mobilebackup_factory_manifest_data_plist();
	plist_t manifest = plist_dict_new();

	/*
	AuthSignature Hash is:
	sha1(<manifest_data>)
	*/

/*
<dict>
		<key>BackupManifestKey</key>
		<dict>
			<key>AuthVersion</key>
			<string>2.0</string>
			<key>AuthSignature</key>
			<data>
			WBdfjcZWg/u/Bpn7aKDJC68UZF4=
			</data>
			<key>IsEncrypted</key>
			<integer>0</integer>
			<key>Data</key>
			<data><!-- binary plist -->
			...
			</data>
		</dict>
		<key>BackupComputerBasePathKey</key>
		<string>/</string>
		<key>BackupMessageTypeKey</key>
		<string>BackupMessageBackupRequest</string>
		<key>BackupProtocolVersion</key>
		<string>1.6</string>
</dict>
*/

	return manifest;
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

static mobilebackup_client_t mobilebackup = NULL;
static lockdownd_client_t client = NULL;
static iphone_device_t phone = NULL;

int main(int argc, char *argv[])
{
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	int i;
	char uuid[41];
	uint16_t port = 0;
	uuid[0] = 0;
	int cmd = -1;
	char *backup_directory = NULL;

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

		/* TODO: Command implementations */
		switch(cmd) {
			case CMD_BACKUP:
			printf("TODO: Creating backup...\n");
/*
Create target directory:
MobileSync/Backup/<uuid>-YYYYMMDD-HHMMSS/
*/

/*
Create: Info.plist (Device infos, IC-Info.sidb, photos, app_ids, iTunesPrefs)
Create:Manifest.plist (backup manifest (backup state))
*/
			lockdownd_client_free(client);
/*
Receive:
...
<hash>.mddata (Raw filedata)
<hash>.mdinfo (backup file information)
...
Create: Status.plist (Info on how the backup process turned out)
*/

/*
- Check lockdown value for domain com.apple.mobile.backup key RequiresEncrypt and WillEncrypt
- Verify battery on AC enough battery remaining
- Request backup from device with manifest (BackupMessageBackupRequest)
- Receive and save DLSendFile files and metadata, ACK each
- Wait until received final backup finished message
*/
			break;
			case CMD_RESTORE:
			printf("TODO: Restoring backup...\n");
/*
- Verify battery on AC enough battery remaining
- Request restore from device (BackupMessageRestoreMigrate)
- Read mddata files and send to devices using DLSendFile
- Signal restore finished message to device
*/
			lockdownd_client_free(client);
			break;
			default:
			break;
		}
	} else {
		printf("ERROR: Could not start service %s.\n", MOBILEBACKUP_SERVICE_NAME);
		lockdownd_client_free(client);
	}

	if (mobilebackup)
		mobilebackup_client_free(mobilebackup);
	iphone_device_free(phone);

	return 0;
}

