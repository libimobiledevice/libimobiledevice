/**
 * @file libimobiledevice/mobilebackup.h
 * @brief MobileBackup Implementation
 * \internal
 *
 * Copyright (c) 2009 Martin Szulecki All Rights Reserved.
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

#ifndef IMOBILEBACKUP_H
#define IMOBILEBACKUP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>

/* Error Codes */
#define MOBILEBACKUP_E_SUCCESS                0
#define MOBILEBACKUP_E_INVALID_ARG           -1
#define MOBILEBACKUP_E_PLIST_ERROR           -2
#define MOBILEBACKUP_E_MUX_ERROR             -3
#define MOBILEBACKUP_E_BAD_VERSION           -4

#define MOBILEBACKUP_E_UNKNOWN_ERROR       -256

typedef int16_t mobilebackup_error_t;

struct mobilebackup_client_int;
typedef struct mobilebackup_client_int *mobilebackup_client_t;

mobilebackup_error_t mobilebackup_client_new(idevice_t device, uint16_t port, mobilebackup_client_t * client);
mobilebackup_error_t mobilebackup_client_free(mobilebackup_client_t client);
mobilebackup_error_t mobilebackup_receive(mobilebackup_client_t client, plist_t *plist);
mobilebackup_error_t mobilebackup_send(mobilebackup_client_t client, plist_t plist);

#ifdef __cplusplus
}
#endif

#endif
