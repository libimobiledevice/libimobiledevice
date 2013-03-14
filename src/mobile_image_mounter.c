/*
 * mobile_image_mounter.c
 * com.apple.mobile.mobile_image_mounter service implementation.
 *
 * Copyright (c) 2010 Nikias Bassen, All Rights Reserved.
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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <plist/plist.h>

#include "mobile_image_mounter.h"
#include "property_list_service.h"
#include "debug.h"

/**
 * Locks a mobile_image_mounter client, used for thread safety.
 *
 * @param client mobile_image_mounter client to lock
 */
static void mobile_image_mounter_lock(mobile_image_mounter_client_t client)
{
#ifdef WIN32
	EnterCriticalSection(&client->mutex);
#else
	pthread_mutex_lock(&client->mutex);
#endif
}

/**
 * Unlocks a mobile_image_mounter client, used for thread safety.
 * 
 * @param client mobile_image_mounter client to unlock
 */
static void mobile_image_mounter_unlock(mobile_image_mounter_client_t client)
{
#ifdef WIN32
	LeaveCriticalSection(&client->mutex);
#else
	pthread_mutex_unlock(&client->mutex);
#endif
}

/**
 * Convert a property_list_service_error_t value to a
 * mobile_image_mounter_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err A property_list_service_error_t error code
 *
 * @return A matching mobile_image_mounter_error_t error code,
 *     MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR otherwise.
 */
static mobile_image_mounter_error_t mobile_image_mounter_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return MOBILE_IMAGE_MOUNTER_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return MOBILE_IMAGE_MOUNTER_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return MOBILE_IMAGE_MOUNTER_E_CONN_FAILED;
		default:
			break;
	}
	return MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
}

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
mobile_image_mounter_error_t mobile_image_mounter_new(idevice_t device, lockdownd_service_descriptor_t service, mobile_image_mounter_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	mobile_image_mounter_error_t err = mobile_image_mounter_error(property_list_service_client_new(device, service, &plistclient));
	if (err != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		return err;
	}

	mobile_image_mounter_client_t client_loc = (mobile_image_mounter_client_t) malloc(sizeof(struct mobile_image_mounter_client_private));
	client_loc->parent = plistclient;

#ifdef WIN32
	InitializeCriticalSection(&client_loc->mutex);
#else
	pthread_mutex_init(&client_loc->mutex, NULL);
#endif

	*client = client_loc;
	return MOBILE_IMAGE_MOUNTER_E_SUCCESS;
}

/**
 * Disconnects a mobile_image_mounter client from the device and frees up the
 * mobile_image_mounter client data.
 * 
 * @param client The mobile_image_mounter client to disconnect and free.
 *
 * @return MOBILE_IMAGE_MOUNTER_E_SUCCESS on success,
 *    or MOBILE_IMAGE_MOUNTER_E_INVALID_ARG if client is NULL.
 */
mobile_image_mounter_error_t mobile_image_mounter_free(mobile_image_mounter_client_t client)
{
	if (!client)
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;

	property_list_service_client_free(client->parent);
	client->parent = NULL;
#ifdef WIN32
	DeleteCriticalSection(&client->mutex);
#else
	pthread_mutex_destroy(&client->mutex);
#endif
	free(client);

	return MOBILE_IMAGE_MOUNTER_E_SUCCESS;
}

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
mobile_image_mounter_error_t mobile_image_mounter_lookup_image(mobile_image_mounter_client_t client, const char *image_type, plist_t *result)
{
	if (!client || !image_type || !result) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict,"Command", plist_new_string("LookupImage"));
	plist_dict_insert_item(dict,"ImageType", plist_new_string(image_type));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}

/**
 * Mounts an image on the device.
 *
 * @param client The connected mobile_image_mounter client.
 * @param image_path The absolute path of the image to mount. The image must
 *    be present before calling this function.
 * @param image_signature Pointer to a buffer holding the images' signature
 * @param signature_length Length of the signature image_signature points to
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
mobile_image_mounter_error_t mobile_image_mounter_mount_image(mobile_image_mounter_client_t client, const char *image_path, const char *image_signature, uint16_t signature_length, const char *image_type, plist_t *result)
{
	if (!client || !image_path || !image_signature || (signature_length == 0) || !image_type || !result) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "Command", plist_new_string("MountImage"));
	plist_dict_insert_item(dict, "ImagePath", plist_new_string(image_path));
	plist_dict_insert_item(dict, "ImageSignature", plist_new_data(image_signature, signature_length));
	plist_dict_insert_item(dict, "ImageType", plist_new_string(image_type));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}

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
mobile_image_mounter_error_t mobile_image_mounter_hangup(mobile_image_mounter_client_t client)
{
	if (!client) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "Command", plist_new_string("Hangup"));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	dict = NULL;
	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &dict));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}
	if (dict) {
		debug_plist(dict);
		plist_free(dict);
	}

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}
