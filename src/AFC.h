/* 
 * AFC.h
 * Defines and structs and the like for the built-in AFC client
 * 
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

#include "usbmux.h"
#include "iphone.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <glib.h>

typedef struct {
	uint32_t header1, header2;
	uint32_t entire_length, unknown1, this_length, unknown2, packet_num, unknown3, operation, unknown4;
} AFCPacket;

typedef struct {
	uint32_t filehandle, unknown1, size, unknown2;
} AFCFilePacket;

typedef struct __AFCToken {
	struct __AFCToken *last, *next;
	char *token;
} AFCToken;

struct iphone_afc_client_int {
	iphone_umux_client_t connection;
	AFCPacket *afc_packet;
	int file_handle;
	int lock;
	GMutex *mutex;
};

struct iphone_afc_file_int {
	uint32_t filehandle, blocks, size, type;
};



enum {
	AFC_ERROR = 0x00000001,
	AFC_SUCCESS_RESPONSE = 0x00000002,
	AFC_LIST_DIR = 0x00000003,      // ReadDir
	// 0x00000004                   // ReadFile
	// 0x00000005                   // WriteFile
	// 0x00000006                   // WritePart
	AFC_TRUNCATE = 0x00000007,      // Truncate
	AFC_DELETE = 0x00000008,        // RemovePath
	AFC_MAKE_DIR = 0x00000009,      // MakeDir
	AFC_GET_INFO = 0x0000000a,      // GetFileInfo
	AFC_GET_DEVINFO = 0x0000000b,   // GetDeviceInfo
	// 0x0000000c  // same as 5, but writes to temp file, then renames it.
	AFC_FILE_OPEN = 0x0000000d,     // FileRefOpen
	AFC_FILE_HANDLE = 0x0000000e,   // _unknownPacket
	AFC_READ = 0x0000000f,          // FileRefRead
	AFC_WRITE = 0x00000010,         // FileRefWrite
	AFC_FILE_SEEK = 0x00000011,     // FileRefSeek
	AFC_FILE_TELL = 0x00000012,     // FileRefTell
	// 0x00000013                   // _unknownPacket
	AFC_FILE_CLOSE = 0x00000014,    // FileRefClose
	AFC_FILE_TRUNCATE = 0x00000015, // FileRefSetFileSize (ftruncate)
	// 0x00000016                   // SetFatalError
	// 0x00000017                   // SetConnectionOptions
	AFC_RENAME = 0x00000018,        // RenamePath
	// 0x00000019                   // SetFSBlockSize (0x800000)
	// 0x0000001A                   // SetBlockSize (0x800000)
	AFC_FILE_LOCK = 0x0000001B,     // FileRefLock
	AFC_MAKE_LINK = 0x0000001C      // MakeLink
};


uint32_t iphone_afc_get_file_handle(iphone_afc_file_t file);
