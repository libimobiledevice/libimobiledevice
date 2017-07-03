/**
 * @file libimobiledevice/mobileactivation.h
 * @brief Handle device activation and deactivation.
 * \internal
 *
 * Copyright (c) 2016-2017 Nikias Bassen, All Rights Reserved.
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

#ifndef IMOBILEACTIVATION_H
#define IMOBILEACTIVATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define MOBILEACTIVATION_SERVICE_NAME "com.apple.mobileactivationd"

/** Error Codes */
typedef enum {
	MOBILEACTIVATION_E_SUCCESS         =  0,
	MOBILEACTIVATION_E_INVALID_ARG     = -1,
	MOBILEACTIVATION_E_PLIST_ERROR     = -2,
	MOBILEACTIVATION_E_MUX_ERROR       = -3,
	MOBILEACTIVATION_E_UNKNOWN_REQUEST = -4,
	MOBILEACTIVATION_E_REQUEST_FAILED  = -5,
	MOBILEACTIVATION_E_UNKNOWN_ERROR   = -256
} mobileactivation_error_t;

typedef struct mobileactivation_client_private mobileactivation_client_private;
typedef mobileactivation_client_private *mobileactivation_client_t; /**< The client handle. */

/**
 * Connects to the mobileactivation service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Reference that will point to a newly allocated
 *     mobileactivation_client_t upon successful return.
 *
 * @return MOBILEACTIVATION_E_SUCCESS on success,
 *     MOBILEACTIVATION_E_INVALID_ARG when one of the parameters is invalid,
 *     or MOBILEACTIVATION_E_MUX_ERROR when the connection failed.
 */
mobileactivation_error_t mobileactivation_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobileactivation_client_t *client);

/**
 * Starts a new mobileactivation service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     mobileactivation_client_t upon successful return. Must be freed using
 *     mobileactivation_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return MOBILEACTIVATION_E_SUCCESS on success, or an MOBILEACTIVATION_E_*
 *     error code otherwise.
 */
mobileactivation_error_t mobileactivation_client_start_service(idevice_t device, mobileactivation_client_t* client, const char* label);

/**
 * Disconnects a mobileactivation client from the device and frees up the
 * mobileactivation client data.
 *
 * @param client The mobileactivation client to disconnect and free.
 *
 * @return MOBILEACTIVATION_E_SUCCESS on success,
 *     MOBILEACTIVATION_E_INVALID_ARG when one of client or client->parent
 *     is invalid, or MOBILEACTIVATION_E_UNKNOWN_ERROR when the was an
 *     error freeing the parent property_list_service client.
 */
mobileactivation_error_t mobileactivation_client_free(mobileactivation_client_t client);


/**
 * Retrieves the device's activation state.
 *
 * @param client The mobileactivation client.
 * @param state Pointer to a plist_t variable that will be set to the
 *     activation state reported by the mobileactivation service. The
 *     consumer is responsible for freeing the returned object using
 *     plist_free().
 *
 * @return MOBILEACTIVATION_E_SUCCESS on success, or an MOBILEACTIVATION_E_*
 *     error code otherwise.
 */
mobileactivation_error_t mobileactivation_get_activation_state(mobileactivation_client_t client, plist_t *state);

/**
 * Retrieves a session blob required for 'drmHandshake' via albert.apple.com.
 *
 * @param client The mobileactivation client
 * @param blob Pointer to a plist_t variable that will be set to the
 *     session blob created by the mobielactivation service. The
 *     consumer is responsible for freeing the returned object using
 *     plist_free().
 *
 * @return MOBILEACTIVATION_E_SUCCESS on success, or an MOBILEACTIVATION_E_*
 *     error code otherwise.
 */
mobileactivation_error_t mobileactivation_create_activation_session_info(mobileactivation_client_t client, plist_t *blob);

/**
 * Retrieves the activation info required for device activation.
 *
 * @param client The mobileactivation client
 * @param info Pointer to a plist_t variable that will be set to the
 *     activation info created by the mobileactivation service. The
 *     consumer is responsible for freeing the returned object using
 *     plist_free().
 *
 * @return MOBILEACTIVATION_E_SUCCESS on success, or an MOBILEACTIVATION_E_*
 *     error code otherwise.
 */
mobileactivation_error_t mobileactivation_create_activation_info(mobileactivation_client_t client, plist_t *info);

/**
 * Retrieves the activation info required for device activation in 'session'
 * mode. This function expects a handshake result retrieved from
 * https://albert.apple.com/deviceservies/drmHandshake  with a blob
 * provided by mobileactivation_create_activation_session_info().
 *
 * @param client The mobileactivation client
 * @aram handshake_result The handshake result returned from drmHandshake
 * @param info Pointer to a plist_t variable that will be set to the
 *     activation info created by the mobileactivation service. The
 *     consumer is responsible for freeing the returned object using
 *     plist_free().
 *
 * @return MOBILEACTIVATION_E_SUCCESS on success, or an MOBILEACTIVATION_E_*
 *     error code otherwise.
 */
mobileactivation_error_t mobileactivation_create_activation_info_with_session(mobileactivation_client_t client, plist_t handshake_result, plist_t *info);

/**
 * Activates the device with the given activation record.
 * The activation record plist dictionary must be obtained using the
 * activation protocol requesting from Apple's https webservice.
 *
 * @param client The mobileactivation client
 * @param activation_record The activation record plist dictionary
 *
 * @return MOBILEACTIVATION_E_SUCCESS on success, or an MOBILEACTIVATION_E_*
 *     error code otherwise.
 */
mobileactivation_error_t mobileactivation_activate(mobileactivation_client_t client, plist_t activation_record);

/**
 * Activates the device with the given activation record in 'session' mode.
 * The activation record plist dictionary must be obtained using the
 * activation protocol requesting from Apple's https webservice.
 *
 * @param client The mobileactivation client
 * @param activation_record The activation record plist dictionary
 *
 * @return MOBILEACTIVATION_E_SUCCESS on success, or an MOBILEACTIVATION_E_*
 *     error code otherwise.
 */
mobileactivation_error_t mobileactivation_activate_with_session(mobileactivation_client_t client, plist_t activation_record);

/**
 * Deactivates the device.
 *
 * @param client The mobileactivation client
 */
mobileactivation_error_t mobileactivation_deactivate(mobileactivation_client_t client);

#ifdef __cplusplus
}
#endif

#endif
