/*
 * idevicebackup2.c
 * Command line interface to use the device's backup and restore service
 *
 * Copyright (c) 2010-2019 Nikias Bassen, All Rights Reserved.
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

#include <sys/stat.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/devicebackup2.h>

static int verbose = 1;

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
	printf("    --no-reboot\t\tdo NOT reboot the device when done (default: yes).\n");
	printf("    --copy\t\tcreate a copy of backup folder before restoring.\n");
	printf("    --settings\t\trestore device settings from the backup.\n");
	printf("    --remove\t\tremove items which are not being restored\n");
	printf("    --skip-apps\t\tdo not trigger re-installation of apps after restore\n");
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
	printf("  -u, --udid UDID\ttarget specific device by UDID\n");
	printf("  -s, --source UDID\tuse backup data from device specified by UDID\n");
	printf("  -i, --interactive\trequest passwords interactively\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
	printf("Homepage: <" PACKAGE_URL ">\n");
}

int main(int argc, char *argv[])
{
	char* udid = NULL;
	char* source_udid = NULL;
	
	int cmd = -1;
	int cmd_flags = 0;
	
	char* backup_directory = NULL;
	int interactive_mode = 0;
	char* backup_password = NULL;
	char* newpw = NULL;
	struct stat st;

	int i;

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udid")) {
			i++;
			if (!argv[i] || !*argv[i]) {
				print_usage(argc, argv);
				return -1;
			}
			udid = strdup(argv[i]);
			continue;
		}
		else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--source")) {
			i++;
			if (!argv[i] || !*argv[i]) {
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
			cmd_flags &= ~CMD_FLAG_RESTORE_NO_REBOOT;
		}
		else if (!strcmp(argv[i], "--no-reboot")) {
			cmd_flags |= CMD_FLAG_RESTORE_NO_REBOOT;
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
		else if (!strcmp(argv[i], "--skip-apps")) {
			cmd_flags |= CMD_FLAG_RESTORE_SKIP_APPS;
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

	return run_cmd(cmd, cmd_flags, udid, source_udid, backup_directory, interactive_mode, backup_password, newpw);
}

