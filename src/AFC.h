/* 
 * AFC.h
 * Defines and structs and the like for the built-in AFC client
 * 
 * Copyright (c) 2008 Zack C. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. 
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
	usbmux_tcp_header *connection;
	iPhone *phone;
	AFCPacket *afc_packet;
	int file_handle;
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
	AFC_FILE_READ = 0x00000002,
	AFC_FILE_WRITE = 0x00000003
};

enum {
	AFC_ERROR = 0x00000001,
	AFC_GET_INFO = 0x0000000a,
	AFC_GET_DEVINFO = 0x0000000b,
	AFC_LIST_DIR = 0x00000003,
	AFC_DELETE = 0x00000008,
	AFC_RENAME = 0x00000018,
	AFC_SUCCESS_RESPONSE = 0x00000002,
	AFC_FILE_OPEN = 0x0000000d,
	AFC_FILE_CLOSE = 0x00000014,
	AFC_FILE_HANDLE = 0x0000000e,
	AFC_READ = 0x0000000f,
	AFC_WRITE = 0x00000010
};

AFClient *afc_connect(iPhone *phone, int s_port, int d_port);
void afc_disconnect(AFClient *client);
int count_nullspaces(char *string, int number);
char **make_strings_list(char *tokens, int true_length);
int dispatch_AFC_packet(AFClient *client, char *data, int length);
int receive_AFC_data(AFClient *client, char **dump_here);

char **afc_get_dir_list(AFClient *client, char *dir);
AFCFile *afc_get_file_info(AFClient *client, char *path);
AFCFile *afc_open_file(AFClient *client, const char *filename, uint32 file_mode);
void afc_close_file(AFClient *client, AFCFile *file);
int afc_read_file(AFClient *client, AFCFile *file, char *data, int length);
int afc_write_file(AFClient *client, AFCFile *file, char *data, int length);
int afc_delete_file(AFClient *client, const char *path);
int afc_rename_file(AFClient *client, const char *from, const char *to);
