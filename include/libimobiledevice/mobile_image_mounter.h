/**
 * @file libimobiledevice/mobile_image_mounter.h
 * @brief Mount developer/debug disk images on the device.
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

#ifndef IMOBILE_IMAGE_MOUNTER_H
#define IMOBILE_IMAGE_MOUNTER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** @name Error Codes */
/*@{*/
#define MOBILE_IMAGE_MOUNTER_E_SUCCESS                0
#define MOBILE_IMAGE_MOUNTER_E_INVALID_ARG           -1
#define MOBILE_IMAGE_MOUNTER_E_PLIST_ERROR           -2
#define MOBILE_IMAGE_MOUNTER_E_CONN_FAILED           -3

#define MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t mobile_image_mounter_error_t;

typedef struct mobile_image_mounter_client_private mobile_image_mounter_client_private;
typedef mobile_image_mounter_client_private *mobile_image_mounter_client_t; /**< The client handle. */

/* Interface */
mobile_image_mounter_error_t mobile_image_mounter_new(idevice_t device, lockdownd_service_descriptor_t service, mobile_image_mounter_client_t *client);
mobile_image_mounter_error_t mobile_image_mounter_free(mobile_image_mounter_client_t client);
mobile_image_mounter_error_t mobile_image_mounter_lookup_image(mobile_image_mounter_client_t client, const char *image_type, plist_t *result);
mobile_image_mounter_error_t mobile_image_mounter_mount_image(mobile_image_mounter_client_t client, const char *image_path, const char *image_signature, uint16_t signature_length, const char *image_type, plist_t *result);
mobile_image_mounter_error_t mobile_image_mounter_hangup(mobile_image_mounter_client_t client);

#ifdef __cplusplus
}
#endif

#endif
