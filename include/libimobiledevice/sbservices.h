/**
 * @file libimobiledevice/sbservices.h
 * @brief Manage SpringBoard icons and retrieve icon images.
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

#ifndef ISB_SERVICES_H
#define ISB_SERVICES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define SBSERVICES_SERVICE_NAME "com.apple.springboardservices"

/** Error Codes */
typedef enum {
	SBSERVICES_E_SUCCESS       =  0,
	SBSERVICES_E_INVALID_ARG   = -1,
	SBSERVICES_E_PLIST_ERROR   = -2,
	SBSERVICES_E_CONN_FAILED   = -3,
	SBSERVICES_E_UNKNOWN_ERROR = -256
} sbservices_error_t;

/** @name Orientation of the user interface on the device */
/*@{*/
typedef enum {
  SBSERVICES_INTERFACE_ORIENTATION_UNKNOWN                = 0,
  SBSERVICES_INTERFACE_ORIENTATION_PORTRAIT               = 1,
  SBSERVICES_INTERFACE_ORIENTATION_PORTRAIT_UPSIDE_DOWN   = 2,
  SBSERVICES_INTERFACE_ORIENTATION_LANDSCAPE_RIGHT        = 3,
  SBSERVICES_INTERFACE_ORIENTATION_LANDSCAPE_LEFT         = 4
} sbservices_interface_orientation_t;
/*@}*/

typedef struct sbservices_client_private sbservices_client_private;
typedef sbservices_client_private *sbservices_client_t; /**< The client handle. */

/* Interface */

/**
 * Connects to the springboardservices service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     sbservices_client_t upon successful return.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client is NULL, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_client_new(idevice_t device, lockdownd_service_descriptor_t service, sbservices_client_t *client);

/**
 * Starts a new sbservices service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     sbservices_client_t upon successful return. Must be freed using
 *     sbservices_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return SBSERVICES_E_SUCCESS on success, or an SBSERVICES_E_* error
 *     code otherwise.
 */
sbservices_error_t sbservices_client_start_service(idevice_t device, sbservices_client_t* client, const char* label);

/**
 * Disconnects an sbservices client from the device and frees up the
 * sbservices client data.
 *
 * @param client The sbservices client to disconnect and free.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client is NULL, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_client_free(sbservices_client_t client);


/**
 * Gets the icon state of the connected device.
 *
 * @param client The connected sbservices client to use.
 * @param state Pointer that will point to a newly allocated plist containing
 *     the current icon state. It is up to the caller to free the memory.
 * @param format_version A string to be passed as formatVersion along with
 *     the request, or NULL if no formatVersion should be passed. This is only
 *     supported since iOS 4.0 so for older firmware versions this must be set
 *     to NULL.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client or state is invalid, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_get_icon_state(sbservices_client_t client, plist_t *state, const char *format_version);

/**
 * Sets the icon state of the connected device.
 *
 * @param client The connected sbservices client to use.
 * @param newstate A plist containing the new iconstate.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client or newstate is NULL, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_set_icon_state(sbservices_client_t client, plist_t newstate);

/**
 * Get the icon of the specified app as PNG data.
 *
 * @param client The connected sbservices client to use.
 * @param bundleId The bundle identifier of the app to retrieve the icon for.
 * @param pngdata Pointer that will point to a newly allocated buffer
 *     containing the PNG data upon successful return. It is up to the caller
 *     to free the memory.
 * @param pngsize Pointer to a uint64_t that will be set to the size of the
 *     buffer pngdata points to upon successful return.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client, bundleId, or pngdata are invalid, or an SBSERVICES_E_* error
 *     code otherwise.
 */
sbservices_error_t sbservices_get_icon_pngdata(sbservices_client_t client, const char *bundleId, char **pngdata, uint64_t *pngsize);

/**
 * Gets the interface orientation of the device.
 *
 * @param client The connected sbservices client to use.
 * @param interface_orientation The interface orientation upon successful return.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client or state is invalid, or an SBSERVICES_E_* error code otherwise.
 */
sbservices_error_t sbservices_get_interface_orientation(sbservices_client_t client, sbservices_interface_orientation_t* interface_orientation);

/**
 * Get the home screen wallpaper as PNG data.
 *
 * @param client The connected sbservices client to use.
 * @param pngdata Pointer that will point to a newly allocated buffer
 *     containing the PNG data upon successful return. It is up to the caller
 *     to free the memory.
 * @param pngsize Pointer to a uint64_t that will be set to the size of the
 *     buffer pngdata points to upon successful return.
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client or pngdata are invalid, or an SBSERVICES_E_* error
 *     code otherwise.
 */
sbservices_error_t sbservices_get_home_screen_wallpaper_pngdata(sbservices_client_t client, char **pngdata, uint64_t *pngsize);

#ifdef __cplusplus
}
#endif

#endif
