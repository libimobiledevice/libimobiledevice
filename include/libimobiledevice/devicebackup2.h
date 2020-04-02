/*
 * devicebackup2.h
 * Wraps idevicebackup2 CLI into a library
 *
 * Copyright (c) 2020 Cody Hatfield <cody.hatfield@me.com>
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

#ifndef DEVICEBACKUP2_H
#define DEVICEBACKUP2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/devicebackup2.h>

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

/**
 * Wraps idevicebackup2 CLI to be used as a library
 **/
int run_cmd(int cmd, int cmd_flags, char* udid, char* source_udid, char* backup_directory, int interactive_mode, char* backup_password, char* newpw);

#ifdef __cplusplus
}
#endif

#endif