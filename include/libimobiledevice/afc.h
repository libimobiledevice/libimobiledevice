/**
 * @file libimobiledevice/afc.h
 * @brief Access the filesystem.
 * \internal
 *
 * Copyright (c) 2009 Nikias Bassen All Rights Reserved.
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

#ifndef IAFC_H
#define IAFC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** @name Error Codes */
/*@{*/
#define AFC_E_SUCCESS                 0
#define AFC_E_UNKNOWN_ERROR           1
#define AFC_E_OP_HEADER_INVALID       2
#define AFC_E_NO_RESOURCES            3
#define AFC_E_READ_ERROR              4
#define AFC_E_WRITE_ERROR             5
#define AFC_E_UNKNOWN_PACKET_TYPE     6
#define AFC_E_INVALID_ARG             7
#define AFC_E_OBJECT_NOT_FOUND        8
#define AFC_E_OBJECT_IS_DIR           9
#define AFC_E_PERM_DENIED            10
#define AFC_E_SERVICE_NOT_CONNECTED  11
#define AFC_E_OP_TIMEOUT             12
#define AFC_E_TOO_MUCH_DATA          13
#define AFC_E_END_OF_DATA            14
#define AFC_E_OP_NOT_SUPPORTED       15
#define AFC_E_OBJECT_EXISTS          16
#define AFC_E_OBJECT_BUSY            17
#define AFC_E_NO_SPACE_LEFT          18
#define AFC_E_OP_WOULD_BLOCK         19
#define AFC_E_IO_ERROR               20
#define AFC_E_OP_INTERRUPTED         21
#define AFC_E_OP_IN_PROGRESS         22
#define AFC_E_INTERNAL_ERROR         23

#define AFC_E_MUX_ERROR              30
#define AFC_E_NO_MEM                 31
#define AFC_E_NOT_ENOUGH_DATA        32
#define AFC_E_DIR_NOT_EMPTY          33
/*@}*/

/** Represents an error code. */
typedef int16_t afc_error_t;

/** Flags for afc_file_open */
typedef enum {
	AFC_FOPEN_RDONLY   = 0x00000001, /**< r   O_RDONLY */
	AFC_FOPEN_RW       = 0x00000002, /**< r+  O_RDWR   | O_CREAT */
	AFC_FOPEN_WRONLY   = 0x00000003, /**< w   O_WRONLY | O_CREAT  | O_TRUNC */
	AFC_FOPEN_WR       = 0x00000004, /**< w+  O_RDWR   | O_CREAT  | O_TRUNC */
	AFC_FOPEN_APPEND   = 0x00000005, /**< a   O_WRONLY | O_APPEND | O_CREAT */
	AFC_FOPEN_RDAPPEND = 0x00000006  /**< a+  O_RDWR   | O_APPEND | O_CREAT */
} afc_file_mode_t;

/** Type of link for afc_make_link() calls */
typedef enum {
	AFC_HARDLINK = 1,
	AFC_SYMLINK = 2
} afc_link_type_t;

/** Lock operation flags */
typedef enum {
	AFC_LOCK_SH = 1 | 4, /**< shared lock */
	AFC_LOCK_EX = 2 | 4, /**< exclusive lock */
	AFC_LOCK_UN = 8 | 4  /**< unlock */
} afc_lock_op_t;

typedef struct afc_client_private afc_client_private;
typedef afc_client_private *afc_client_t; /**< The client handle. */

/* Interface */
afc_error_t afc_client_new(idevice_t device, lockdownd_service_descriptor_t service, afc_client_t *client);
afc_error_t afc_client_free(afc_client_t client);
afc_error_t afc_get_device_info(afc_client_t client, char ***infos);
afc_error_t afc_read_directory(afc_client_t client, const char *dir, char ***list);
afc_error_t afc_get_file_info(afc_client_t client, const char *filename, char ***infolist);
afc_error_t afc_file_open(afc_client_t client, const char *filename, afc_file_mode_t file_mode, uint64_t *handle);
afc_error_t afc_file_close(afc_client_t client, uint64_t handle);
afc_error_t afc_file_lock(afc_client_t client, uint64_t handle, afc_lock_op_t operation);
afc_error_t afc_file_read(afc_client_t client, uint64_t handle, char *data, uint32_t length, uint32_t *bytes_read);
afc_error_t afc_file_write(afc_client_t client, uint64_t handle, const char *data, uint32_t length, uint32_t *bytes_written);
afc_error_t afc_file_seek(afc_client_t client, uint64_t handle, int64_t offset, int whence);
afc_error_t afc_file_tell(afc_client_t client, uint64_t handle, uint64_t *position);
afc_error_t afc_file_truncate(afc_client_t client, uint64_t handle, uint64_t newsize);
afc_error_t afc_remove_path(afc_client_t client, const char *path);
afc_error_t afc_rename_path(afc_client_t client, const char *from, const char *to);
afc_error_t afc_make_directory(afc_client_t client, const char *dir);
afc_error_t afc_truncate(afc_client_t client, const char *path, uint64_t newsize);
afc_error_t afc_make_link(afc_client_t client, afc_link_type_t linktype, const char *target, const char *linkname);
afc_error_t afc_set_file_time(afc_client_t client, const char *path, uint64_t mtime);

/* Helper functions */
afc_error_t afc_get_device_info_key(afc_client_t client, const char *key, char **value);

#ifdef __cplusplus
}
#endif

#endif
