/**
 * @file libimobiledevice/mcinstall.h
 * @brief Manage mobileconfig profiles.
 * \internal
 *
 *  Copyright (c) 2020 Ethan Carlson All Rights Reserved.
 * Uses base code from mcinstall.h Copyright Nikias Bassen and Martin Szulecki
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

#ifndef IMCINSTALL_H
#define IMCINSTALL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define MCINSTALL_SERVICE_NAME "com.apple.MCInstall"

/** Error Codes */
typedef enum {
	MCINSTALL_E_SUCCESS        =  0,
	MCINSTALL_E_INVALID_ARG    = -1,
	MCINSTALL_E_PLIST_ERROR    = -2,
	MCINSTALL_E_CONN_FAILED    = -3,
	MCINSTALL_E_REQUEST_FAILED = -4,
	MCINSTALL_E_UNKNOWN_ERROR  = -256
} mcinstall_error_t;

typedef struct mcinstall_client_private mcinstall_client_private;
typedef mcinstall_client_private *mcinstall_client_t; /**< The client handle. */

/* Interface */

/**
 * Connects to the mcinstall service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     mcinstall_client_t upon successful return.
 *
 * @return MCINSTALL_E_SUCCESS on success, MCINSTALL_E_INVALID_ARG when
 *     client is NULL, or an MCINSTALL_E_* error code otherwise.
 */
mcinstall_error_t mcinstall_client_new(idevice_t device, lockdownd_service_descriptor_t service, mcinstall_client_t *client);

/**
 * Starts a new mcinstall service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     mcinstall_client_t upon successful return. Must be freed using
 *     mcinstall_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return MCINSTALL_E_SUCCESS on success, or an MCINSTALL_E_* error
 *     code otherwise.
 */
mcinstall_error_t mcinstall_client_start_service(idevice_t device, mcinstall_client_t* client, const char* label);

/**
 * Disconnects an mcinstall client from the device and frees up the
 * mcinstall client data.
 *
 * @param client The mcinstall client to disconnect and free.
 *
 * @return MCINSTALL_E_SUCCESS on success, MCINSTALL_E_INVALID_ARG when
 *     client is NULL, or an MCINSTALL_E_* error code otherwise.
 */
mcinstall_error_t mcinstall_client_free(mcinstall_client_t client);

/**
 * Retrieves all installed mobileconfig profiles
 *
 * @param client The connected mcinstall to use.
 * @param profiles Pointer to a plist_t that will be set to a PLIST_ARRAY
 *    if the function is successful.
 *
 * @return MCINSTALL_E_SUCCESS on success, MCINSTALL_E_INVALID_ARG when
 *     client is invalid, or an MCINSTALL_E_* error code otherwise.
 *
 *
 * @note If no mobileconfig profiles are installed on the device, this function
 *     still returns MCINSTALL_E_SUCCESS and profiles will just point to an
 *     empty array.
 */
mcinstall_error_t mcinstall_copy(mcinstall_client_t client, plist_t* profiles);


/**
 * Installs the given mobileconfig profile. Only works with valid profiles.
 *
 * @param client The connected mcinstall to use for installation
 * @param profile The valid mobileconfig profile to install. This has to be
 *    passed as a PLIST_DATA, otherwise the function will fail.
 *
 * @return MCINSTALL_E_SUCCESS on success, MCINSTALL_E_INVALID_ARG when
 *     client is invalid, or an MCINSTALL_E_* error code otherwise.
 */
mcinstall_error_t mcinstall_install(mcinstall_client_t client, plist_t profile);


/**
 * Installs the given DEP Enrollment CloudCOnfig Data. Use this carfully, you only get one shot before an erase is neccesary. Only works with valid profiles.
 *
 * @param client The connected mcinstall to use for installation
 * @param profile The valid mobileconfig profile to install. This has to be
 *    passed as a PLIST_DATA, otherwise the function will fail.
 *
 * @return MCINSTALL_E_SUCCESS on success, MCINSTALL_E_INVALID_ARG when
 *     client is invalid, or an MCINSTALL_E_* error code otherwise.
 */
mcinstall_error_t mcinstall_install_cloud_config(mcinstall_client_t client, plist_t profile);


/**
 * Retrieves DEP Enrollment Information
 *
 * @param client The connected mcinstall to use.
 * @param profiles Pointer to a plist_t that will be set to a PLIST_ARRAY
 *    if the function is successful.
 *
 * @return MCINSTALL_E_SUCCESS on success, MCINSTALL_E_INVALID_ARG when
 *     client is invalid, or an MCINSTALL_E_* error code otherwise.
 *
 *
 * @note If no mobileconfig profiles are installed on the device, this function
 *     still returns MCINSTALL_E_SUCCESS and profiles will just point to an
 *     empty array.
 */
mcinstall_error_t mcinstall_get_cloud_config(mcinstall_client_t client, plist_t* profiles);


/**
 * Requests that device download a DEP Enrollment Profile from the server
 *
 * @param client The connected mcinstall to use.
 * @param profiles Pointer to a plist_t that will be set to a PLIST_ARRAY
 *    if the function is successful.
 *
 * @return MCINSTALL_E_SUCCESS on success, MCINSTALL_E_INVALID_ARG when
 *     client is invalid, or an MCINSTALL_E_* error code otherwise.
 *
 *
 * @note If no mobileconfig profiles are installed on the device, this function
 *     still returns MCINSTALL_E_SUCCESS and profiles will just point to an
 *     empty array.
 */
mcinstall_error_t mcinstall_download_cloud_config(mcinstall_client_t client, plist_t* profiles);



/**
 * Removes a specified mobileconfig from the device
 *
 * @param client The connected mcinstall to use.
 * @param profile Pointer to a plist_t DICT that is recived from mcinstall_copy for the ID Specified
 *    if the function is successful.
 * 
 * @param profileID The Key that was used to access the DICS passed as profile, it is the pofiles identifier
 *
 * @return MCINSTALL_E_SUCCESS on success, MCINSTALL_E_INVALID_ARG when
 *     client is invalid, or an MCINSTALL_E_* error code otherwise.
 *
 *
 * @note If no mobileconfig profiles are installed on the device, this function
 *     still returns MCINSTALL_E_SUCCESS and profiles will just point to an
 *     empty array.
 */
mcinstall_error_t mcinstall_remove(mcinstall_client_t client, plist_t profile, const char* profileID);



/**
 * Retrieves the status code from the last operation.
 *
 * @param client The mcinstall to use.
 *
 * @return -1 if client is invalid, or the status code from the last operation
 */
int mcinstall_get_status_code(mcinstall_client_t client);

#ifdef __cplusplus
}
#endif

#endif
