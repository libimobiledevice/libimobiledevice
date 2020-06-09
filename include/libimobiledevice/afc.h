/**
 * @file libimobiledevice/afc.h
 * @brief Access the filesystem on the device.
 * \internal
 *
 * Copyright (c) 2010-2014 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2009-2010 Nikias Bassen All Rights Reserved.
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

#define AFC_SERVICE_NAME "com.apple.afc"

/** Error Codes */
typedef enum {
	AFC_E_SUCCESS               =  0,
	AFC_E_UNKNOWN_ERROR         =  1,
	AFC_E_OP_HEADER_INVALID     =  2,
	AFC_E_NO_RESOURCES          =  3,
	AFC_E_READ_ERROR            =  4,
	AFC_E_WRITE_ERROR           =  5,
	AFC_E_UNKNOWN_PACKET_TYPE   =  6,
	AFC_E_INVALID_ARG           =  7,
	AFC_E_OBJECT_NOT_FOUND      =  8,
	AFC_E_OBJECT_IS_DIR         =  9,
	AFC_E_PERM_DENIED           = 10,
	AFC_E_SERVICE_NOT_CONNECTED = 11,
	AFC_E_OP_TIMEOUT            = 12,
	AFC_E_TOO_MUCH_DATA         = 13,
	AFC_E_END_OF_DATA           = 14,
	AFC_E_OP_NOT_SUPPORTED      = 15,
	AFC_E_OBJECT_EXISTS         = 16,
	AFC_E_OBJECT_BUSY           = 17,
	AFC_E_NO_SPACE_LEFT         = 18,
	AFC_E_OP_WOULD_BLOCK        = 19,
	AFC_E_IO_ERROR              = 20,
	AFC_E_OP_INTERRUPTED        = 21,
	AFC_E_OP_IN_PROGRESS        = 22,
	AFC_E_INTERNAL_ERROR        = 23,
	AFC_E_MUX_ERROR             = 30,
	AFC_E_NO_MEM                = 31,
	AFC_E_NOT_ENOUGH_DATA       = 32,
	AFC_E_DIR_NOT_EMPTY         = 33,
	AFC_E_FORCE_SIGNED_TYPE     = -1
} afc_error_t;

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

/**
 * Makes a connection to the AFC service on the device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated afc_client_t
 *        upon successful return.
 *
 * @return AFC_E_SUCCESS on success, AFC_E_INVALID_ARG if device or service is
 *         invalid, AFC_E_MUX_ERROR if the connection cannot be established,
 *         or AFC_E_NO_MEM if there is a memory allocation problem.
 */
afc_error_t afc_client_new(idevice_t device, lockdownd_service_descriptor_t service, afc_client_t *client);

/**
 * Starts a new AFC service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated afc_client_t upon
 *        successful return. Must be freed using afc_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *        Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return AFC_E_SUCCESS on success, or an AFC_E_* error code otherwise.
 */
afc_error_t afc_client_start_service(idevice_t device, afc_client_t* client, const char* label);

/**
 * Frees up an AFC client. If the connection was created by the client itself,
 * the connection will be closed.
 *
 * @param client The client to free.
 */
afc_error_t afc_client_free(afc_client_t client);

/**
 * Get device information for a connected client. The device information
 * returned is the device model as well as the free space, the total capacity
 * and blocksize on the accessed disk partition.
 *
 * @param client The client to get device info for.
 * @param device_information A char list of device information terminated by an
 *        empty string or NULL if there was an error. Free with
 *        afc_dictionary_free().
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_get_device_info(afc_client_t client, char ***device_information);

/**
 * Gets a directory listing of the directory requested.
 *
 * @param client The client to get a directory listing from.
 * @param path The directory for listing. (must be a fully-qualified path)
 * @param directory_information A char list of files in the directory
 *        terminated by an empty string or NULL if there was an error. Free with
 *        afc_dictionary_free().
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_read_directory(afc_client_t client, const char *path, char ***directory_information);

/**
 * Gets information about a specific file.
 *
 * @param client The client to use to get the information of the file.
 * @param path The fully-qualified path to the file.
 * @param file_information Pointer to a buffer that will be filled with a
 *        NULL-terminated list of strings with the file information. Set to NULL
 *        before calling this function. Free with afc_dictionary_free().
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_get_file_info(afc_client_t client, const char *path, char ***file_information);

/**
 * Opens a file on the device.
 *
 * @param client The client to use to open the file.
 * @param filename The file to open. (must be a fully-qualified path)
 * @param file_mode The mode to use to open the file.
 * @param handle Pointer to a uint64_t that will hold the handle of the file
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_file_open(afc_client_t client, const char *filename, afc_file_mode_t file_mode, uint64_t *handle);

/**
 * Closes a file on the device.
 *
 * @param client The client to close the file with.
 * @param handle File handle of a previously opened file.
 */
afc_error_t afc_file_close(afc_client_t client, uint64_t handle);

/**
 * Locks or unlocks a file on the device.
 *
 * Makes use of flock on the device.
 * @see http://developer.apple.com/documentation/Darwin/Reference/ManPages/man2/flock.2.html
 *
 * @param client The client to lock the file with.
 * @param handle File handle of a previously opened file.
 * @param operation the lock or unlock operation to perform, this is one of
 *        AFC_LOCK_SH (shared lock), AFC_LOCK_EX (exclusive lock), or
 *        AFC_LOCK_UN (unlock).
 */
afc_error_t afc_file_lock(afc_client_t client, uint64_t handle, afc_lock_op_t operation);

/**
 * Attempts to the read the given number of bytes from the given file.
 *
 * @param client The relevant AFC client
 * @param handle File handle of a previously opened file
 * @param data The pointer to the memory region to store the read data
 * @param length The number of bytes to read
 * @param bytes_read The number of bytes actually read.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_file_read(afc_client_t client, uint64_t handle, char *data, uint32_t length, uint32_t *bytes_read);

/**
 * Writes a given number of bytes to a file.
 *
 * @param client The client to use to write to the file.
 * @param handle File handle of previously opened file.
 * @param data The data to write to the file.
 * @param length How much data to write.
 * @param bytes_written The number of bytes actually written to the file.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_file_write(afc_client_t client, uint64_t handle, const char *data, uint32_t length, uint32_t *bytes_written);

/**
 * Seeks to a given position of a pre-opened file on the device.
 *
 * @param client The client to use to seek to the position.
 * @param handle File handle of a previously opened.
 * @param offset Seek offset.
 * @param whence Seeking direction, one of SEEK_SET, SEEK_CUR, or SEEK_END.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_file_seek(afc_client_t client, uint64_t handle, int64_t offset, int whence);

/**
 * Returns current position in a pre-opened file on the device.
 *
 * @param client The client to use.
 * @param handle File handle of a previously opened file.
 * @param position Position in bytes of indicator
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_file_tell(afc_client_t client, uint64_t handle, uint64_t *position);

/**
 * Sets the size of a file on the device.
 *
 * @param client The client to use to set the file size.
 * @param handle File handle of a previously opened file.
 * @param newsize The size to set the file to.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 *
 * @note This function is more akin to ftruncate than truncate, and truncate
 *       calls would have to open the file before calling this, sadly.
 */
afc_error_t afc_file_truncate(afc_client_t client, uint64_t handle, uint64_t newsize);

/**
 * Deletes a file or directory.
 *
 * @param client The client to use.
 * @param path The path to delete. (must be a fully-qualified path)
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_remove_path(afc_client_t client, const char *path);

/**
 * Renames a file or directory on the device.
 *
 * @param client The client to have rename.
 * @param from The name to rename from. (must be a fully-qualified path)
 * @param to The new name. (must also be a fully-qualified path)
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_rename_path(afc_client_t client, const char *from, const char *to);

/**
 * Creates a directory on the device.
 *
 * @param client The client to use to make a directory.
 * @param path The directory's path. (must be a fully-qualified path, I assume
 *        all other mkdir restrictions apply as well)
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_make_directory(afc_client_t client, const char *path);

/**
 * Sets the size of a file on the device without prior opening it.
 *
 * @param client The client to use to set the file size.
 * @param path The path of the file to be truncated.
 * @param newsize The size to set the file to.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_truncate(afc_client_t client, const char *path, uint64_t newsize);

/**
 * Creates a hard link or symbolic link on the device.
 *
 * @param client The client to use for making a link
 * @param linktype 1 = hard link, 2 = symlink
 * @param target The file to be linked.
 * @param linkname The name of link.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_make_link(afc_client_t client, afc_link_type_t linktype, const char *target, const char *linkname);

/**
 * Sets the modification time of a file on the device.
 *
 * @param client The client to use to set the file size.
 * @param path Path of the file for which the modification time should be set.
 * @param mtime The modification time to set in nanoseconds since epoch.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_set_file_time(afc_client_t client, const char *path, uint64_t mtime);

/**
 * Deletes a file or directory including possible contents.
 *
 * @param client The client to use.
 * @param path The path to delete. (must be a fully-qualified path)
 * @since libimobiledevice 1.1.7
 * @note Only available in iOS 6 and later.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_remove_path_and_contents(afc_client_t client, const char *path);

/* Helper functions */

/**
 * Get a specific key of the device info list for a client connection.
 * Known key values are: Model, FSTotalBytes, FSFreeBytes and FSBlockSize.
 * This is a helper function for afc_get_device_info().
 *
 * @param client The client to get device info for.
 * @param key The key to get the value of.
 * @param value The value for the key if successful or NULL otherwise.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_get_device_info_key(afc_client_t client, const char *key, char **value);

/**
 * Frees up a char dictionary as returned by some AFC functions.
 *
 * @param dictionary The char array terminated by an empty string.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_dictionary_free(char **dictionary);

#ifdef __cplusplus
}
#endif

#endif
