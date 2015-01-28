/**
 * @file libimobiledevice/misagent.h
 * @brief Manage provisioning profiles.
 * \internal
 *
 * Copyright (c) 2013-2014 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2012 Nikias Bassen All Rights Reserved.
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

#define MISAGENT_SERVICE_NAME "com.apple.misagent"

/** Error Codes */
typedef enum {
	MISAGENT_E_SUCCESS        =  0,
	MISAGENT_E_INVALID_ARG    = -1,
	MISAGENT_E_PLIST_ERROR    = -2,
	MISAGENT_E_CONN_FAILED    = -3,
	MISAGENT_E_REQUEST_FAILED = -4,
	MISAGENT_E_UNKNOWN_ERROR  = -256
} misagent_error_t;

typedef struct misagent_client_private misagent_client_private;
typedef misagent_client_private *misagent_client_t; /**< The client handle. */

/* Interface */

/**
 * Connects to the misagent service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     misagent_client_t upon successful return.
 *
 * @return MISAGENT_E_SUCCESS on success, MISAGENT_E_INVALID_ARG when
 *     client is NULL, or an MISAGENT_E_* error code otherwise.
 */
misagent_error_t misagent_client_new(idevice_t device, lockdownd_service_descriptor_t service, misagent_client_t *client);

/**
 * Starts a new misagent service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     misagent_client_t upon successful return. Must be freed using
 *     misagent_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return MISAGENT_E_SUCCESS on success, or an MISAGENT_E_* error
 *     code otherwise.
 */
misagent_error_t misagent_client_start_service(idevice_t device, misagent_client_t* client, const char* label);

/**
 * Disconnects an misagent client from the device and frees up the
 * misagent client data.
 *
 * @param client The misagent client to disconnect and free.
 *
 * @return MISAGENT_E_SUCCESS on success, MISAGENT_E_INVALID_ARG when
 *     client is NULL, or an MISAGENT_E_* error code otherwise.
 */
misagent_error_t misagent_client_free(misagent_client_t client);


/**
 * Installs the given provisioning profile. Only works with valid profiles.
 *
 * @param client The connected misagent to use for installation
 * @param profile The valid provisioning profile to install. This has to be
 *    passed as a PLIST_DATA, otherwise the function will fail.
 *
 * @return MISAGENT_E_SUCCESS on success, MISAGENT_E_INVALID_ARG when
 *     client is invalid, or an MISAGENT_E_* error code otherwise.
 */
misagent_error_t misagent_install(misagent_client_t client, plist_t profile);

/**
 * Retrieves an array of all installed provisioning profiles.
 *
 * @param client The connected misagent to use.
 * @param profiles Pointer to a plist_t that will be set to a PLIST_ARRAY
 *    if the function is successful.
 *
 * @return MISAGENT_E_SUCCESS on success, MISAGENT_E_INVALID_ARG when
 *     client is invalid, or an MISAGENT_E_* error code otherwise.
 *
 * @note If no provisioning profiles are installed on the device, this function
 *     still returns MISAGENT_E_SUCCESS and profiles will just point to an
 *     empty array.
 */
misagent_error_t misagent_copy(misagent_client_t client, plist_t* profiles);

/**
 * Removes a given provisioning profile.
 *
 * @param client The connected misagent to use.
 * @param profileID Identifier of the provisioning profile to remove.
 *    This is a UUID that can be obtained from the provisioning profile data.
 * @see misagent_copy
 *
 * @return MISAGENT_E_SUCCESS on success, MISAGENT_E_INVALID_ARG when
 *     client is invalid, or an MISAGENT_E_* error code otherwise.
 */
misagent_error_t misagent_remove(misagent_client_t client, const char* profileID);

/**
 * Retrieves the status code from the last operation.
 *
 * @param client The misagent to use.
 *
 * @return -1 if client is invalid, or the status code from the last operation
 */
int misagent_get_status_code(misagent_client_t client);

#ifdef __cplusplus
}
#endif

#endif
