/*
 * afc.h
 * Defines and structs and the like for the built-in AFC client
 *
 * Copyright (c) 2014 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2008 Zach C. All Rights Reserved.
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

#ifndef __AFC_H
#define __AFC_H

#include <stdint.h>

#include "libimobiledevice/afc.h"
#include "service.h"
#include "endianness.h"
#include "common/thread.h"

#define AFC_MAGIC "CFA6LPAA"
#define AFC_MAGIC_LEN (8)

typedef struct {
	char magic[AFC_MAGIC_LEN];
	uint64_t entire_length, this_length, packet_num, operation;
} AFCPacket;

#define AFCPacket_to_LE(x) \
 	(x)->entire_length = htole64((x)->entire_length); \
	(x)->this_length   = htole64((x)->this_length); \
	(x)->packet_num    = htole64((x)->packet_num); \
	(x)->operation     = htole64((x)->operation);

#define AFCPacket_from_LE(x) \
	(x)->entire_length = le64toh((x)->entire_length); \
	(x)->this_length   = le64toh((x)->this_length); \
	(x)->packet_num    = le64toh((x)->packet_num); \
	(x)->operation     = le64toh((x)->operation);

struct afc_client_private {
	service_client_t parent;
	AFCPacket *afc_packet;
	int file_handle;
	int lock;
	mutex_t mutex;
	int free_parent;
};

/* AFC Operations */
enum {
	AFC_OP_INVALID                   = 0x00000000,	/* Invalid */
	AFC_OP_STATUS                    = 0x00000001,	/* Status */
	AFC_OP_DATA                      = 0x00000002,	/* Data */
	AFC_OP_READ_DIR                  = 0x00000003,	/* ReadDir */
	AFC_OP_READ_FILE                 = 0x00000004,	/* ReadFile */
	AFC_OP_WRITE_FILE                = 0x00000005,	/* WriteFile */
	AFC_OP_WRITE_PART                = 0x00000006,	/* WritePart */
	AFC_OP_TRUNCATE                  = 0x00000007,	/* TruncateFile */
	AFC_OP_REMOVE_PATH               = 0x00000008,	/* RemovePath */
	AFC_OP_MAKE_DIR                  = 0x00000009,	/* MakeDir */
	AFC_OP_GET_FILE_INFO             = 0x0000000A,	/* GetFileInfo */
	AFC_OP_GET_DEVINFO               = 0x0000000B,	/* GetDeviceInfo */
	AFC_OP_WRITE_FILE_ATOM           = 0x0000000C,	/* WriteFileAtomic (tmp file+rename) */
	AFC_OP_FILE_OPEN                 = 0x0000000D,	/* FileRefOpen */
	AFC_OP_FILE_OPEN_RES             = 0x0000000E,	/* FileRefOpenResult */
	AFC_OP_FILE_READ                 = 0x0000000F,	/* FileRefRead */
	AFC_OP_FILE_WRITE                = 0x00000010,	/* FileRefWrite */
	AFC_OP_FILE_SEEK                 = 0x00000011,	/* FileRefSeek */
	AFC_OP_FILE_TELL                 = 0x00000012,	/* FileRefTell */
	AFC_OP_FILE_TELL_RES             = 0x00000013,	/* FileRefTellResult */
	AFC_OP_FILE_CLOSE                = 0x00000014,	/* FileRefClose */
	AFC_OP_FILE_SET_SIZE             = 0x00000015,	/* FileRefSetFileSize (ftruncate) */
	AFC_OP_GET_CON_INFO              = 0x00000016,	/* GetConnectionInfo */
	AFC_OP_SET_CON_OPTIONS           = 0x00000017,	/* SetConnectionOptions */
	AFC_OP_RENAME_PATH               = 0x00000018,	/* RenamePath */
	AFC_OP_SET_FS_BS                 = 0x00000019,	/* SetFSBlockSize (0x800000) */
	AFC_OP_SET_SOCKET_BS             = 0x0000001A,	/* SetSocketBlockSize (0x800000) */
	AFC_OP_FILE_LOCK                 = 0x0000001B,	/* FileRefLock */
	AFC_OP_MAKE_LINK                 = 0x0000001C,	/* MakeLink */
	AFC_OP_GET_FILE_HASH             = 0x0000001D,	/* GetFileHash */
	AFC_OP_SET_FILE_MOD_TIME         = 0x0000001E,	/* SetModTime */
	AFC_OP_GET_FILE_HASH_RANGE       = 0x0000001F,	/* GetFileHashWithRange */
	/* iOS 6+ */
	AFC_OP_FILE_SET_IMMUTABLE_HINT   = 0x00000020,	/* FileRefSetImmutableHint */
	AFC_OP_GET_SIZE_OF_PATH_CONTENTS = 0x00000021,	/* GetSizeOfPathContents */
	AFC_OP_REMOVE_PATH_AND_CONTENTS  = 0x00000022,	/* RemovePathAndContents */
	AFC_OP_DIR_OPEN                  = 0x00000023,	/* DirectoryEnumeratorRefOpen */
	AFC_OP_DIR_OPEN_RESULT           = 0x00000024,	/* DirectoryEnumeratorRefOpenResult */
	AFC_OP_DIR_READ                  = 0x00000025,	/* DirectoryEnumeratorRefRead */
	AFC_OP_DIR_CLOSE                 = 0x00000026,	/* DirectoryEnumeratorRefClose */
	/* iOS 7+ */
	AFC_OP_FILE_READ_OFFSET          = 0x00000027,	/* FileRefReadWithOffset */
	AFC_OP_FILE_WRITE_OFFSET         = 0x00000028	/* FileRefWriteWithOffset */
};

afc_error_t afc_client_new_with_service_client(service_client_t service_client, afc_client_t *client);

#endif
