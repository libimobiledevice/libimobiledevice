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

struct iph_device_int;
typedef iph_device_int *iph_device_t;

struct iph_lckd_client_int;
typedef iph_lckd_client_int *iph_lckd_client_t;

struct iph_umux_client_int;
typedef iph_umux_client_int *iph_umux_client_t;

struct iph_afc_client_int;
typedef iph_afc_client_int *iph_afc_client_t;

struct iph_afc_file_int;
typedef iph_afc_file_int *iph_afc_file_t;

//device related functions
int  iph_get_device ( iph_device_t *device );
void iph_free_device ( iph_device_t device );


//lockdownd related functions
int iph_lckd_get_client ( iph_device_t device, iph_lckd_client_t *client );
void iph_lckd_free_client( iph_lckd_client_t client );

int iph_lckd_start_service ( iph_lckd_client_t client, const char *service );
int iph_lckd_recv ( iph_lckd_client_t client, char **dump_data );
int iph_lckd_send ( iph_lckd_client_t client, char *raw_data, uint32_t length );


//usbmux related functions
int iph_mux_get_client ( iph_device_t device, uint16_t src_port, uint16_t dst_port, iph_umux_client_t *client );
void iph_mux_free_client ( iph_umux_client_t client );

int iph_mux_send ( iph_umux_client_t client, const char *data, uint32_t datalen );
int iph_mux_recv ( iph_umux_client_t client, char *data, uint32_t datalen );


//afc related functions
int iph_afc_get_client ( iph_device_t device, int src_port, int dst_port, iph_afc_client_t *client );
void iph_afc_free_client ( iph_afc_client_t client );

char **iph_afc_get_devinfo ( iph_afc_client_t client );
char **iph_afc_get_dir_list ( iph_afc_client_t client, const char *dir);

int iph_afc_get_file_attr ( iph_afc_client_t client, const char *filename, struct stat *stbuf );
int iph_afc_open_file ( iph_afc_client_t client, const char *filename, uint32 file_mode, iph_afc_file_t *file );
void iph_afc_close_file ( iph_afc_client_t client, iph_afc_file_t file);
int iph_afc_read_file ( iph_afc_client_t client, iph_afc_file_t file, char *data, int length);
int iph_afc_write_file ( iph_afc_client_t client, iph_afc_file_t file, const char *data, int length);
int iph_afc_seek_file ( iph_afc_client_t client, iph_afc_file_t file, int seekpos);
int iph_afc_truncate_file ( iph_afc_client_t client, iph_afc_file_t file, uint32 newsize);
int iph_afc_delete_file ( iph_afc_client_t client, const char *path);
int iph_afc_rename_file ( iph_afc_client_t client, const char *from, const char *to);
int iph_afc_mkdir ( iph_afc_client_t client, const char *dir);


#ifdef __cplusplus
}
#endif

#endif

