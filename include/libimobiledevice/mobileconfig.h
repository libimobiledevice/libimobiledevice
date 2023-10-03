/**
 * @file libimobiledevice/moibileconfig.h
 * @brief Manage configuration profiles.
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

#ifndef IMOBILECONFIG_H
#define IMOBILECONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define MOBILECONFIG_SERVICE_NAME "com.apple.mobile.MCInstall"

/** Error Codes */
typedef enum {
	MOBILECONFIG_E_SUCCESS        =  0,
	MOBILECONFIG_E_INVALID_ARG    = -1,
	MOBILECONFIG_E_PLIST_ERROR    = -2,
	MOBILECONFIG_E_CONN_FAILED    = -3,
	MOBILECONFIG_E_REQUEST_FAILED = -4,
	MOBILECONFIG_E_UNKNOWN_ERROR  = -256
} mobileconfig_error_t;

typedef struct mobileconfig_client_private mobileconfig_client_private;
typedef mobileconfig_client_private *mobileconfig_client_t; /**< The client handle. */

/* Interface */

/**
 * Connects to the mobileconfig service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     mobileconfig_client_t upon successful return.
 *
 * @return MOBILECONFIG_E_SUCCESS on success, MOBILECONFIG_E_INVALID_ARG when
 *     client is NULL, or an MOBILECONFIG_E_* error code otherwise.
 */
mobileconfig_error_t mobileconfig_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobileconfig_client_t *client);

/**
 * Starts a new mobileconfig service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     mobileconfig_client_t upon successful return. Must be freed using
 *     mobileconfig_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return MOBILECONFIG_E_SUCCESS on success, or an MOBILECONFIG_E_* error
 *     code otherwise.
 */
mobileconfig_error_t mobileconfig_client_start_service(idevice_t device, mobileconfig_client_t* client, const char* label);

/**
 * Disconnects an mobileconfig client from the device and frees up the
 * mobileconfig client data.
 *
 * @param client The mobileconfig client to disconnect and free.
 *
 * @return MOBILECONFIG_E_SUCCESS on success, MOBILECONFIG_E_INVALID_ARG when
 *     client is NULL, or an MOBILECONFIG_E_* error code otherwise.
 */
mobileconfig_error_t mobileconfig_client_free(mobileconfig_client_t client);


/**
 * Installs the given provisioning profile. Only works with valid profiles.
 *
 * @param client The connected mobileconfig to use for installation
 * @param profile The valid provisioning profile to install. This has to be
 *    passed as a PLIST_DATA, otherwise the function will fail.
 *
 * @return MOBILECONFIG_E_SUCCESS on success, MOBILECONFIG_E_INVALID_ARG when
 *     client is invalid, or an MOBILECONFIG_E_* error code otherwise.
 */
mobileconfig_error_t mobileconfig_install(mobileconfig_client_t client, plist_t profile);

/**
 * Attempts to erase the device through mc_mobile_tunnel
 *
 * @param client The connected mobileconfig to use for installation
 *
 * @return MOBILECONFIG_E_SUCCESS on success, MOBILECONFIG_E_INVALID_ARG when
 *     client is invalid, or an MOBILECONFIG_E_* error code otherwise.
 */
mobileconfig_error_t mobileconfig_erase(mobileconfig_client_t client);

/**
 * Retrieves all installed provisioning profiles (iOS 9.2.1 or below).
 *
 * @param client The connected mobileconfig to use.
 * @param profiles Pointer to a plist_t that will be set to a PLIST_ARRAY
 *    if the function is successful.
 *
 * @return MOBILECONFIG_E_SUCCESS on success, MOBILECONFIG_E_INVALID_ARG when
 *     client is invalid, or an MOBILECONFIG_E_* error code otherwise.
 *
 * @note This API call only works with iOS 9.2.1 or below.
 *     For newer iOS versions use mobileconfig_copy_all() instead.
 *
 * @note If no provisioning profiles are installed on the device, this function
 *     still returns MOBILECONFIG_E_SUCCESS and profiles will just point to an
 *     empty array.
 */
mobileconfig_error_t mobileconfig_copy(mobileconfig_client_t client, plist_t* profiles, uint16_t justName);

/**
 * Retrieves all installed provisioning profiles (iOS 9.3 or higher).
 *
 * @param client The connected mobileconfig to use.
 * @param profiles Pointer to a plist_t that will be set to a PLIST_ARRAY
 *    if the function is successful.
 *
 * @return MOBILECONFIG_E_SUCCESS on success, MOBILECONFIG_E_INVALID_ARG when
 *     client is invalid, or an MOBILECONFIG_E_* error code otherwise.
 *
 * @note This API call only works with iOS 9.3 or higher.
 *     For older iOS versions use mobileconfig_copy() instead.
 *
 * @note If no provisioning profiles are installed on the device, this function
 *     still returns MOBILECONFIG_E_SUCCESS and profiles will just point to an
 *     empty array.
 */
mobileconfig_error_t mobileconfig_copy_all(mobileconfig_client_t client, plist_t* profiles, uint16_t justName);

/**
 * Removes a given provisioning profile.
 *
 * @param client The connected mobileconfig to use.
 * @param profileID Identifier of the provisioning profile to remove.
 *    This is a UUID that can be obtained from the provisioning profile data.
 * @see mobileconfig_copy
 *
 * @return MOBILECONFIG_E_SUCCESS on success, MOBILECONFIG_E_INVALID_ARG when
 *     client is invalid, or an MOBILECONFIG_E_* error code otherwise.
 */
mobileconfig_error_t mobileconfig_remove(mobileconfig_client_t client, const char* profileID, const char* UUID, uint64_t version);

/**
 * Retrieves the status code from the last operation.
 *
 * @param client The mobileconfig to use.
 *
 * @return -1 if client is invalid, or the status code from the last operation
 */
int mobileconfig_get_status_code(mobileconfig_client_t client);

#ifdef __cplusplus
}
#endif

#endif

