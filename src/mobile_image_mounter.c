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
#include "common/debug.h"

/**
 * Locks a mobile_image_mounter client, used for thread safety.
 *
 * @param client mobile_image_mounter client to lock
 */
static void mobile_image_mounter_lock(mobile_image_mounter_client_t client)
{
	mutex_lock(&client->mutex);
}

/**
 * Unlocks a mobile_image_mounter client, used for thread safety.
 *
 * @param client mobile_image_mounter client to unlock
 */
static void mobile_image_mounter_unlock(mobile_image_mounter_client_t client)
{
	mutex_unlock(&client->mutex);
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

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_new(idevice_t device, lockdownd_service_descriptor_t service, mobile_image_mounter_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	mobile_image_mounter_error_t err = mobile_image_mounter_error(property_list_service_client_new(device, service, &plistclient));
	if (err != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		return err;
	}

	mobile_image_mounter_client_t client_loc = (mobile_image_mounter_client_t) malloc(sizeof(struct mobile_image_mounter_client_private));
	client_loc->parent = plistclient;

	mutex_init(&client_loc->mutex);

	*client = client_loc;
	return MOBILE_IMAGE_MOUNTER_E_SUCCESS;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_start_service(idevice_t device, mobile_image_mounter_client_t * client, const char* label)
{
	mobile_image_mounter_error_t err = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, MOBILE_IMAGE_MOUNTER_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(mobile_image_mounter_new), &err);
	return err;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_free(mobile_image_mounter_client_t client)
{
	if (!client)
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;

	property_list_service_client_free(client->parent);
	client->parent = NULL;
	mutex_destroy(&client->mutex);
	free(client);

	return MOBILE_IMAGE_MOUNTER_E_SUCCESS;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_lookup_image(mobile_image_mounter_client_t client, const char *image_type, plist_t *result)
{
	if (!client || !image_type || !result) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict,"Command", plist_new_string("LookupImage"));
	plist_dict_set_item(dict,"ImageType", plist_new_string(image_type));

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

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_upload_image(mobile_image_mounter_client_t client, const char *image_type, size_t image_size, const char *signature, uint16_t signature_size, mobile_image_mounter_upload_cb_t upload_cb, void* userdata)
{
	if (!client || !image_type || (image_size == 0) || !upload_cb) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);
	plist_t result = NULL;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("ReceiveBytes"));
	if (signature && signature_size != 0)
		plist_dict_set_item(dict, "ImageSignature", plist_new_data(signature, signature_size));
	plist_dict_set_item(dict, "ImageSize", plist_new_uint(image_size));
	plist_dict_set_item(dict, "ImageType", plist_new_string(image_type));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("Error sending XML plist to device!");
		goto leave_unlock;
	}

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("Error receiving response from device!");
		goto leave_unlock;
	}
	res = MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED;

	char* strval = NULL;
	plist_t node = plist_dict_get_item(result, "Status");
	if (node && plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, &strval);
	}
	if (!strval) {
		debug_info("Error: Unexpected response received!");
		goto leave_unlock;
	}
	if (strcmp(strval, "ReceiveBytesAck") != 0) {
		debug_info("Error: didn't get ReceiveBytesAck but %s", strval);
		free(strval);
		goto leave_unlock;
	}
	free(strval);

	size_t tx = 0;
	size_t bufsize = 65536;
	unsigned char *buf = (unsigned char*)malloc(bufsize);
	if (!buf) {
		debug_info("Out of memory");
		res = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
		goto leave_unlock;
	}
	debug_info("uploading image (%d bytes)", (int)image_size);
	while (tx < image_size) {
		size_t remaining = image_size - tx;
		size_t amount = (remaining < bufsize) ? remaining : bufsize;
		ssize_t r = upload_cb(buf, amount, userdata);
		if (r < 0) {
			debug_info("upload_cb returned %d", (int)r);
			break;
		}
		uint32_t sent = 0;
		if (service_send(client->parent->parent, (const char*)buf, (uint32_t)r, &sent) != SERVICE_E_SUCCESS) {
			debug_info("service_send failed");
			break;
		}
		tx += r;
	}
	free(buf);
	if (tx < image_size) {
		debug_info("Error: failed to upload image");
		goto leave_unlock;
	}
	debug_info("image uploaded");

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("Error receiving response from device!");
		goto leave_unlock;
	}
	res = MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED;

	strval = NULL;
	node = plist_dict_get_item(result, "Status");
	if (node && plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, &strval);
	}
	if (!strval) {
		debug_info("Error: Unexpected response received!");
		goto leave_unlock;
	}
	if (strcmp(strval, "Complete") != 0) {
		debug_info("Error: didn't get Complete but %s", strval);
		free(strval);
		goto leave_unlock;
	} else {
		res = MOBILE_IMAGE_MOUNTER_E_SUCCESS;
	}
	free(strval);


leave_unlock:
	mobile_image_mounter_unlock(client);
	if (result)
		plist_free(result);
	return res;

}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_mount_image(mobile_image_mounter_client_t client, const char *image_path, const char *signature, uint16_t signature_size, const char *image_type, plist_t *result)
{
	if (!client || !image_path || !image_type || !result) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("MountImage"));
	plist_dict_set_item(dict, "ImagePath", plist_new_string(image_path));
	if (signature && signature_size != 0)
		plist_dict_set_item(dict, "ImageSignature", plist_new_data(signature, signature_size));
	plist_dict_set_item(dict, "ImageType", plist_new_string(image_type));

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

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_hangup(mobile_image_mounter_client_t client)
{
	if (!client) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("Hangup"));

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
