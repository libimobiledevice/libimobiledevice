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

#include <sys/types.h>
#include <sys/stat.h>

//general errors
#define IPHONE_E_SUCCESS          0
#define IPHONE_E_INVALID_ARG     -1
#define IPHONE_E_NO_DEVICE       -2
#define IPHONE_E_TIMEOUT         -3
#define IPHONE_E_NOT_ENOUGH_DATA -4
#define IPHONE_E_BAD_HEADER      -5

//lockdownd specific error
#define IPHONE_E_INVALID_CONF    -6
#define IPHONE_E_PAIRING_FAILED  -7
#define IPHONE_E_SSL_ERROR       -8

//afc specific error
#define IPHONE_E_NO_SUCH_FILE    -9

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

//device related functions
int  iphone_get_device ( iphone_device_t *device );
void iphone_free_device ( iphone_device_t device );


//lockdownd related functions
int iphone_lckd_new_client ( iphone_device_t device, iphone_lckd_client_t *client );
void iphone_lckd_free_client( iphone_lckd_client_t client );

int iphone_lckd_start_service ( iphone_lckd_client_t client, const char *service );
int iphone_lckd_recv ( iphone_lckd_client_t client, char **dump_data );
int iphone_lckd_send ( iphone_lckd_client_t client, char *raw_data, uint32_t length );


//usbmux related functions
int iphone_mux_new_client ( iphone_device_t device, uint16_t src_port, uint16_t dst_port, iphone_umux_client_t *client );
void iphone_mux_free_client ( iphone_umux_client_t client );

int iphone_mux_send ( iphone_umux_client_t client, const char *data, uint32_t datalen );
int iphone_mux_recv ( iphone_umux_client_t client, char *data, uint32_t datalen );


//afc related functions
int iphone_afc_new_client ( iphone_device_t device, int src_port, int dst_port, iphone_afc_client_t *client );
void iphone_afc_free_client ( iphone_afc_client_t client );

char **iphone_afc_get_devinfo ( iphone_afc_client_t client );
char **iphone_afc_get_dir_list ( iphone_afc_client_t client, const char *dir);

int iphone_afc_get_file_attr ( iphone_afc_client_t client, const char *filename, struct stat *stbuf );
int iphone_afc_open_file ( iphone_afc_client_t client, const char *filename, uint32_t file_mode, iphone_afc_file_t *file );
void iphone_afc_close_file ( iphone_afc_client_t client, iphone_afc_file_t file);
int iphone_afc_read_file ( iphone_afc_client_t client, iphone_afc_file_t file, char *data, int length);
int iphone_afc_write_file ( iphone_afc_client_t client, iphone_afc_file_t file, const char *data, int length);
int iphone_afc_seek_file ( iphone_afc_client_t client, iphone_afc_file_t file, int seekpos);
int iphone_afc_truncate_file ( iphone_afc_client_t client, iphone_afc_file_t file, uint32_t newsize);
int iphone_afc_delete_file ( iphone_afc_client_t client, const char *path);
int iphone_afc_rename_file ( iphone_afc_client_t client, const char *from, const char *to);
int iphone_afc_mkdir ( iphone_afc_client_t client, const char *dir);


#ifdef __cplusplus
}
#endif

#endif

