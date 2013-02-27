/**
 * @file libimobiledevice/misagent.h
 * @brief Manage provisioning profiles.
 * \internal
 *
 * Copyright (c) 2012 Nikias Bassen, All Rights Reserved.
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

#ifndef IMISAGENT_H
#define IMISAGENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** @name Error Codes */
/*@{*/
#define MISAGENT_E_SUCCESS                0
#define MISAGENT_E_INVALID_ARG           -1
#define MISAGENT_E_PLIST_ERROR           -2
#define MISAGENT_E_CONN_FAILED           -3
#define MISAGENT_E_REQUEST_FAILED        -4

#define MISAGENT_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t misagent_error_t;

typedef struct misagent_client_private misagent_client_private;
typedef misagent_client_private *misagent_client_t; /**< The client handle. */

/* Interface */
misagent_error_t misagent_client_new(idevice_t device, lockdownd_service_descriptor_t service, misagent_client_t *client);
misagent_error_t misagent_client_free(misagent_client_t client);

misagent_error_t misagent_install(misagent_client_t client, plist_t profile);
misagent_error_t misagent_copy(misagent_client_t client, plist_t* profiles);
misagent_error_t misagent_remove(misagent_client_t client, const char* profileID);
int misagent_get_status_code(misagent_client_t client);

#ifdef __cplusplus
}
#endif

#endif
