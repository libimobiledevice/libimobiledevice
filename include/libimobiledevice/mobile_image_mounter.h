/**
 * @file libimobiledevice/mobile_image_mounter.h
 * @brief Mount developer/debug disk images on the device.
 * \internal
 *
 * Copyright (c) 2010-2014 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2010-2014 Nikias Bassen All Rights Reserved.
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

#define MOBILE_IMAGE_MOUNTER_SERVICE_NAME "com.apple.mobile.mobile_image_mounter"

/** Error Codes */
typedef enum {
	MOBILE_IMAGE_MOUNTER_E_SUCCESS        =  0,
	MOBILE_IMAGE_MOUNTER_E_INVALID_ARG    = -1,
	MOBILE_IMAGE_MOUNTER_E_PLIST_ERROR    = -2,
	MOBILE_IMAGE_MOUNTER_E_CONN_FAILED    = -3,
	MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED = -4,
	MOBILE_IMAGE_MOUNTER_E_DEVICE_LOCKED  = -5,
	MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR  = -256
} mobile_image_mounter_error_t;

typedef struct mobile_image_mounter_client_private mobile_image_mounter_client_private;
typedef mobile_image_mounter_client_private *mobile_image_mounter_client_t; /**< The client handle. */

/** callback for image upload */
typedef ssize_t (*mobile_image_mounter_upload_cb_t) (void* buffer, size_t length, void *user_data);

/* Interface */

/**
 * Connects to the mobile_image_mounter service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated
 *    mobile_image_mounter_client_t upon successful return.
 *
 * @return MOBILE_IMAGE_MOUNTER_E_SUCCESS on success,
 *    MOBILE_IMAGE_MOUNTER_E_INVALID_ARG if device is NULL,
 *    or MOBILE_IMAGE_MOUNTER_E_CONN_FAILED if the connection to the
 *    device could not be established.
 */
mobile_image_mounter_error_t mobile_image_mounter_new(idevice_t device, lockdownd_service_descriptor_t service, mobile_image_mounter_client_t *client);

/**
 * Starts a new mobile_image_mounter service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     mobile_image_mounter_t upon successful return. Must be freed using
 *     mobile_image_mounter_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return MOBILE_IMAGE_MOUNTER_E_SUCCESS on success, or an MOBILE_IMAGE_MOUNTER_E_* error
 *     code otherwise.
 */
mobile_image_mounter_error_t mobile_image_mounter_start_service(idevice_t device, mobile_image_mounter_client_t* client, const char* label);

/**
 * Disconnects a mobile_image_mounter client from the device and frees up the
 * mobile_image_mounter client data.
 *
 * @param client The mobile_image_mounter client to disconnect and free.
 *
 * @return MOBILE_IMAGE_MOUNTER_E_SUCCESS on success,
 *    or MOBILE_IMAGE_MOUNTER_E_INVALID_ARG if client is NULL.
 */
mobile_image_mounter_error_t mobile_image_mounter_free(mobile_image_mounter_client_t client);


/**
 * Tells if the image of ImageType is already mounted.
 *
 * @param client The client use
 * @param image_type The type of the image to look up
 * @param result Pointer to a plist that will receive the result of the
 *    operation.
 *
 * @note This function may return MOBILE_IMAGE_MOUNTER_E_SUCCESS even if the
 *    operation has failed. Check the resulting plist for further information.
 *
 * @return MOBILE_IMAGE_MOUNTER_E_SUCCESS on success, or an error code on error
 */
mobile_image_mounter_error_t mobile_image_mounter_lookup_image(mobile_image_mounter_client_t client, const char *image_type, plist_t *result);

/**
 * Uploads an image with an optional signature to the device.
 *
 * @param client The connected mobile_image_mounter client.
 * @param image_type Type of image that is being uploaded.
 * @param image_size Total size of the image.
 * @param signature Buffer with a signature of the image being uploaded. If
 *    NULL, no signature will be used.
 * @param signature_size Total size of the image signature buffer. If 0, no
 *    signature will be used.
 * @param upload_cb Callback function that gets the data chunks for uploading
 *    the image.
 * @param userdata User defined data for the upload callback function.
 *
 * @return MOBILE_IMAGE_MOUNTER_E_SUCCESS on succes, or a
 *    MOBILE_IMAGE_MOUNTER_E_* error code otherwise.
 */
mobile_image_mounter_error_t mobile_image_mounter_upload_image(mobile_image_mounter_client_t client, const char *image_type, size_t image_size, const char *signature, uint16_t signature_size, mobile_image_mounter_upload_cb_t upload_cb, void* userdata);

/**
 * Mounts an image on the device.
 *
 * @param client The connected mobile_image_mounter client.
 * @param image_path The absolute path of the image to mount. The image must
 *    be present before calling this function.
 * @param signature Pointer to a buffer holding the images' signature
 * @param signature_size Length of the signature image_signature points to
 * @param image_type Type of image to mount
 * @param result Pointer to a plist that will receive the result of the
 *    operation.
 *
 * @note This function may return MOBILE_IMAGE_MOUNTER_E_SUCCESS even if the
 *    operation has failed. Check the resulting plist for further information.
 *    Note that there is no unmounting function. The mount persists until the
 *    device is rebooted.
 *
 * @return MOBILE_IMAGE_MOUNTER_E_SUCCESS on success,
 *    MOBILE_IMAGE_MOUNTER_E_INVALID_ARG if on ore more parameters are
 *    invalid, or another error code otherwise.
 */
mobile_image_mounter_error_t mobile_image_mounter_mount_image(mobile_image_mounter_client_t client, const char *image_path, const char *signature, uint16_t signature_size, const char *image_type, plist_t *result);

/**
 * Hangs up the connection to the mobile_image_mounter service.
 * This functions has to be called before freeing up a mobile_image_mounter
 * instance. If not, errors appear in the device's syslog.
 *
 * @param client The client to hang up
 *
 * @return MOBILE_IMAGE_MOUNTER_E_SUCCESS on success,
 *     MOBILE_IMAGE_MOUNTER_E_INVALID_ARG if client is invalid,
 *     or another error code otherwise.
 */
mobile_image_mounter_error_t mobile_image_mounter_hangup(mobile_image_mounter_client_t client);

#ifdef __cplusplus
}
#endif

#endif
