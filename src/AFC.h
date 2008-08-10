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

typedef struct {
	//const uint32 header1 = 0x36414643; // '6AFC' or 'CFA6' when sent ;)
	uint32 header1, header2;
	//const uint32 header2 = 0x4141504C; // 'AAPL' or 'LPAA' when sent ;)
	uint32 entire_length, unknown1, this_length, unknown2, packet_num, unknown3, operation, unknown4;
} AFCPacket;

typedef struct {
	usbmux_connection *connection;
	AFCPacket *afc_packet;
	int file_handle;
	int lock;
} AFClient;

typedef struct {
	uint32 filehandle, unknown1, size, unknown2;
} AFCFilePacket;

typedef struct {
	uint32 filehandle, blocks, size, type;
} AFCFile;

typedef struct __AFCToken {
	struct __AFCToken *last, *next;
	char *token;
} AFCToken;


enum {
	AFC_FILE_READ = 0x00000002, // seems to be able to read and write files
	AFC_FILE_WRITE = 0x00000003, // writes and creates a file, blanks it out, etc.
	AFC_FILE_RW = 0x00000005, // seems to do the same as 2. Might even create the file. 
	AFC_FILE_OP4 = 0x00000004, // no idea -- appears to be "write" -- clears file beforehand like 3
	AFC_FILE_OP6 = 0x00000006, // no idea yet -- appears to be the same as 5.
	AFC_FILE_OP1 = 0x00000001, // no idea juuust yet... probably read.
	AFC_FILE_OP0 = 0x00000000,
	AFC_FILE_OP10 = 0x0000000a
};

enum {
	AFC_ERROR = 0x00000001,
	AFC_GET_INFO = 0x0000000a,
	AFC_GET_DEVINFO = 0x0000000b,
	AFC_LIST_DIR = 0x00000003,
	AFC_MAKE_DIR = 0x00000009,
	AFC_DELETE = 0x00000008,
	AFC_RENAME = 0x00000018,
	AFC_SUCCESS_RESPONSE = 0x00000002,
	AFC_FILE_OPEN = 0x0000000d,
	AFC_FILE_CLOSE = 0x00000014,
	AFC_FILE_SEEK = 0x00000011,
	AFC_FILE_TRUNCATE = 0x00000015,
	AFC_FILE_HANDLE = 0x0000000e,
	AFC_READ = 0x0000000f,
	AFC_WRITE = 0x00000010
};

AFClient *afc_connect(iPhone *phone, int s_port, int d_port);
void afc_disconnect(AFClient *client);

char **afc_get_devinfo(AFClient *client);
char **afc_get_dir_list(AFClient *client, const char *dir);
AFCFile *afc_get_file_info(AFClient *client, const char *path);
AFCFile *afc_open_file(AFClient *client, const char *filename, uint32 file_mode);
void afc_close_file(AFClient *client, AFCFile *file);
int afc_read_file(AFClient *client, AFCFile *file, char *data, int length);
int afc_write_file(AFClient *client, AFCFile *file, const char *data, int length);
int afc_seek_file(AFClient *client, AFCFile *file, int seekpos);
int afc_truncate_file(AFClient *client, AFCFile *file, uint32 newsize);
int afc_delete_file(AFClient *client, const char *path);
int afc_rename_file(AFClient *client, const char *from, const char *to);
int afc_mkdir(AFClient *client, const char *dir);
