/* 
 * AFC.h
 * Defines and structs and the like for the built-in AFC client
 * Written by FxChiP
 */

#include "usbmux.h"
#include "iphone.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
	S_IFREG = 0,
	S_IFDIR = 1
};

enum {
	AFC_FILE_READ = 0x00000002,
	AFC_FILE_WRITE = 0x00000003
};

enum {
	AFC_ERROR = 0x00000001,
	AFC_GET_INFO = 0x0000000a,
	AFC_GET_DEVINFO = 0x0000000b,
	AFC_LIST_DIR = 0x00000003,
	AFC_SUCCESS_RESPONSE = 0x00000002,
	AFC_FILE_OPEN = 0x0000000d,
	AFC_FILE_CLOSE = 0x00000014,
	AFC_FILE_HANDLE = 0x0000000e,
	AFC_READ = 0x0000000f
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
