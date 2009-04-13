/*
 * libiphone.h
 * Main include of libiphone
 *
 * Copyright (c) 2008 Jonathan Beck All Rights Reserved.
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

#ifndef LIBIPHONE_H
#define LIBIPHONE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <plist/plist.h>

//general errors
#define IPHONE_E_SUCCESS          0
#define IPHONE_E_INVALID_ARG     -1
#define IPHONE_E_UNKNOWN_ERROR   -2
#define IPHONE_E_NO_DEVICE       -3
#define IPHONE_E_TIMEOUT         -4
#define IPHONE_E_NOT_ENOUGH_DATA -5
#define IPHONE_E_BAD_HEADER      -6

//lockdownd specific error
#define IPHONE_E_INVALID_CONF    -7
#define IPHONE_E_PAIRING_FAILED  -8
#define IPHONE_E_SSL_ERROR       -9
#define IPHONE_E_PLIST_ERROR    -10
#define IPHONE_E_DICT_ERROR     -11

//afc specific error
#define IPHONE_E_NO_SUCH_FILE   -12

typedef int16_t iphone_error_t;

typedef enum {
	IPHONE_AFC_FILE_READ = 0x00000001, // seems to be able to read and write files
	IPHONE_AFC_FILE_WRITE = 0x00000002, // writes and creates a file, blanks it out, etc.
	IPHONE_AFC_FILE_RW = 0x00000003, // seems to do the same as 2. Might even create the file. 
	IPHONE_AFC_FILE_CREAT = 0x00000004, // no idea -- appears to be "write" -- clears file beforehand like 3
	IPHONE_AFC_FILE_OP6 = 0x00000006, // no idea yet -- appears to be the same as 5.
	IPHONE_AFC_FILE_OP1 = 0x00000001, // no idea juuust yet... probably read.
	IPHONE_AFC_FILE_OP0 = 0x00000000,
	IPHONE_AFC_FILE_OP10 = 0x0000000a
} iphone_afc_file_mode_t;

struct iphone_device_int;
typedef struct iphone_device_int *iphone_device_t;

struct iphone_lckd_client_int;
typedef struct iphone_lckd_client_int *iphone_lckd_client_t;

struct iphone_umux_client_int;
typedef struct iphone_umux_client_int *iphone_umux_client_t;

struct iphone_afc_client_int;
typedef struct iphone_afc_client_int *iphone_afc_client_t;

struct iphone_afc_file_int;
typedef struct iphone_afc_file_int *iphone_afc_file_t;

struct iphone_msync_client_int;
typedef struct iphone_msync_client_int *iphone_msync_client_t;

struct iphone_np_client_int;
typedef struct iphone_np_client_int *iphone_np_client_t;

//debug related functions
#define DBGMASK_ALL        0xFFFF
#define DBGMASK_NONE       0x0000
#define DBGMASK_USBMUX     (1 << 1)
#define DBGMASK_LOCKDOWND  (1 << 2)
#define DBGMASK_MOBILESYNC (1 << 3)

void iphone_set_debug_mask(uint16_t mask);
void iphone_set_debug(int level);

//device related functions
iphone_error_t iphone_get_device ( iphone_device_t *device );
iphone_error_t iphone_get_specific_device( unsigned int bus_n, int dev_n, iphone_device_t * device );
iphone_error_t iphone_free_device ( iphone_device_t device );


//lockdownd related functions
iphone_error_t lockdownd_get_device_uid(iphone_lckd_client_t control, char **uid);
iphone_error_t iphone_lckd_new_client ( iphone_device_t device, iphone_lckd_client_t *client );
iphone_error_t iphone_lckd_free_client( iphone_lckd_client_t client );

iphone_error_t iphone_lckd_start_service ( iphone_lckd_client_t client, const char *service, int *port );
iphone_error_t iphone_lckd_recv ( iphone_lckd_client_t client, plist_t* plist);
iphone_error_t iphone_lckd_send ( iphone_lckd_client_t client, plist_t plist);


//usbmux related functions
iphone_error_t iphone_mux_new_client ( iphone_device_t device, uint16_t src_port, uint16_t dst_port, iphone_umux_client_t *client );
iphone_error_t iphone_mux_free_client ( iphone_umux_client_t client );

iphone_error_t iphone_mux_send ( iphone_umux_client_t client, const char *data, uint32_t datalen, uint32_t *sent_bytes );
iphone_error_t iphone_mux_recv ( iphone_umux_client_t client, char *data, uint32_t datalen, uint32_t *recv_bytes  );


//afc related functions
iphone_error_t iphone_afc_new_client ( iphone_device_t device, int src_port, int dst_port, iphone_afc_client_t *client );
iphone_error_t iphone_afc_free_client ( iphone_afc_client_t client );

iphone_error_t iphone_afc_get_devinfo ( iphone_afc_client_t client, char ***infos );
iphone_error_t iphone_afc_get_dir_list ( iphone_afc_client_t client, const char *dir, char ***list);

iphone_error_t iphone_afc_get_file_attr ( iphone_afc_client_t client, const char *filename, struct stat *stbuf );
iphone_error_t iphone_afc_open_file ( iphone_afc_client_t client, const char *filename, iphone_afc_file_mode_t file_mode, iphone_afc_file_t *file );
iphone_error_t iphone_afc_close_file ( iphone_afc_client_t client, iphone_afc_file_t file);
iphone_error_t iphone_afc_lock_file ( iphone_afc_client_t client, iphone_afc_file_t file, int operation);
iphone_error_t iphone_afc_read_file ( iphone_afc_client_t client, iphone_afc_file_t file, char *data, int length, uint32_t *bytes);
iphone_error_t iphone_afc_write_file ( iphone_afc_client_t client, iphone_afc_file_t file, const char *data, int length, uint32_t *bytes);
iphone_error_t iphone_afc_seek_file ( iphone_afc_client_t client, iphone_afc_file_t file, int seekpos);
iphone_error_t iphone_afc_truncate_file ( iphone_afc_client_t client, iphone_afc_file_t file, uint32_t newsize);
iphone_error_t iphone_afc_delete_file ( iphone_afc_client_t client, const char *path);
iphone_error_t iphone_afc_rename_file ( iphone_afc_client_t client, const char *from, const char *to);
iphone_error_t iphone_afc_mkdir ( iphone_afc_client_t client, const char *dir);
iphone_error_t iphone_afc_truncate(iphone_afc_client_t client, const char *path, off_t newsize);



iphone_error_t iphone_msync_new_client(iphone_device_t device, int src_port, int dst_port,
									   iphone_msync_client_t * client);
iphone_error_t iphone_msync_free_client(iphone_msync_client_t client);

iphone_error_t iphone_msync_recv(iphone_msync_client_t client, plist_t * plist);
iphone_error_t iphone_msync_send(iphone_msync_client_t client, plist_t plist);

#ifdef __cplusplus
}
#endif

#endif

