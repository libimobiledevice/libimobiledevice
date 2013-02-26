/**
 * @file libimobiledevice/file_relay.h
 * @brief Retrieve compressed CPIO archives.
 * \internal
 *
 * Copyright (c) 2010 Nikias Bassen All Rights Reserved.
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

#ifndef IFILE_RELAY_H
#define IFILE_RELAY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** @name Error Codes */
/*@{*/
#define FILE_RELAY_E_SUCCESS                0
#define FILE_RELAY_E_INVALID_ARG           -1
#define FILE_RELAY_E_PLIST_ERROR           -2
#define FILE_RELAY_E_MUX_ERROR             -3
#define FILE_RELAY_E_INVALID_SOURCE        -4
#define FILE_RELAY_E_STAGING_EMPTY         -5

#define FILE_RELAY_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t file_relay_error_t;

typedef struct file_relay_client_private file_relay_client_private;
typedef file_relay_client_private *file_relay_client_t; /**< The client handle. */

file_relay_error_t file_relay_client_new(idevice_t device, lockdownd_service_descriptor_t service, file_relay_client_t *client);
file_relay_error_t file_relay_client_free(file_relay_client_t client);

file_relay_error_t file_relay_request_sources(file_relay_client_t client, const char **sources, idevice_connection_t *connection);

#ifdef __cplusplus
}
#endif

#endif
