/*
 * mobile_image_mounter.c
 * com.apple.mobile.mobile_image_mounter service implementation.
 *
 * Copyright (c) 2010-2019 Nikias Bassen, All Rights Reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <string.h>
#include <stdlib.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

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

mobile_image_mounter_error_t mobile_image_mounter_new(idevice_t device, lockdownd_service_descriptor_t service, mobile_image_mounter_client_t *client)
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

mobile_image_mounter_error_t mobile_image_mounter_start_service(idevice_t device, mobile_image_mounter_client_t * client, const char* label)
{
	mobile_image_mounter_error_t err = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, MOBILE_IMAGE_MOUNTER_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(mobile_image_mounter_new), &err);
	return err;
}

mobile_image_mounter_error_t mobile_image_mounter_free(mobile_image_mounter_client_t client)
{
	if (!client)
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;

	property_list_service_client_free(client->parent);
	client->parent = NULL;
	mutex_destroy(&client->mutex);
	free(client);

	return MOBILE_IMAGE_MOUNTER_E_SUCCESS;
}

mobile_image_mounter_error_t mobile_image_mounter_lookup_image(mobile_image_mounter_client_t client, const char *image_type, plist_t *result)
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

static mobile_image_mounter_error_t process_result(plist_t result, const char *expected_status)
{
	mobile_image_mounter_error_t res = MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED;
	char* strval = NULL;
	plist_t node;

	node = plist_dict_get_item(result, "Error");
	if (node && plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, &strval);
	}
	if (strval) {
		if (!strcmp(strval, "DeviceLocked")) {
			debug_info("Device is locked, can't mount");
			res = MOBILE_IMAGE_MOUNTER_E_DEVICE_LOCKED;
		} else {
			debug_info("Unhandled error '%s' received", strval);
		}
		free(strval);
		return res;
	}

	node = plist_dict_get_item(result, "Status");
	if (node && plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, &strval);
	}
	if (!strval) {
		debug_info("Error: Unexpected response received!");
	} else if (strcmp(strval, expected_status) == 0) {
		res = MOBILE_IMAGE_MOUNTER_E_SUCCESS;
	} else {
		debug_info("Error: didn't get %s but %s", expected_status, strval);
	}
	free(strval);

	return res;
}

mobile_image_mounter_error_t mobile_image_mounter_upload_image(mobile_image_mounter_client_t client, const char *image_type, size_t image_size, const unsigned char *signature, unsigned int signature_size, mobile_image_mounter_upload_cb_t upload_cb, void* userdata)
{
	if (!client || !image_type || (image_size == 0) || !upload_cb) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);
	plist_t result = NULL;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("ReceiveBytes"));
	if (signature && signature_size != 0)
		plist_dict_set_item(dict, "ImageSignature", plist_new_data((char*)signature, signature_size));
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
	res = process_result(result, "ReceiveBytesAck");
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		goto leave_unlock;
	}

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
		res = MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED;
		goto leave_unlock;
	}
	debug_info("image uploaded");

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("Error receiving response from device!");
		goto leave_unlock;
	}
	res = process_result(result, "Complete");

leave_unlock:
	mobile_image_mounter_unlock(client);
	if (result)
		plist_free(result);
	return res;

}

mobile_image_mounter_error_t mobile_image_mounter_mount_image_with_options(mobile_image_mounter_client_t client, const char *image_path, const unsigned char *signature, unsigned int signature_size, const char *image_type, plist_t options, plist_t *result)
{
	if (!client || !image_path || !image_type || !result) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("MountImage"));
	plist_dict_set_item(dict, "ImagePath", plist_new_string(image_path));
	if (signature && signature_size != 0)
		plist_dict_set_item(dict, "ImageSignature", plist_new_data((char*)signature, signature_size));
	plist_dict_set_item(dict, "ImageType", plist_new_string(image_type));
	if (PLIST_IS_DICT(options)) {
		plist_dict_merge(&dict, options);
	}

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

mobile_image_mounter_error_t mobile_image_mounter_mount_image(mobile_image_mounter_client_t client, const char *image_path, const unsigned char *signature, unsigned int signature_size, const char *image_type, plist_t *result)
{
	return mobile_image_mounter_mount_image_with_options(client, image_path, signature, signature_size, image_type, NULL, result);
}

mobile_image_mounter_error_t mobile_image_mounter_unmount_image(mobile_image_mounter_client_t client, const char *mount_path)
{
	if (!client || !mount_path) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("UnmountImage"));
	plist_dict_set_item(dict, "MountPath", plist_new_string(mount_path));
	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	plist_t result = NULL;
	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	} else {
		plist_t p_error = plist_dict_get_item(result, "Error");
		if (p_error) {
			plist_t p_detailed = plist_dict_get_item(result, "DetailedError");
			const char* detailederr = (p_detailed) ? plist_get_string_ptr(p_detailed, NULL) : "";
			const char* errstr = plist_get_string_ptr(p_error, NULL);
			if (errstr && !strcmp(errstr, "UnknownCommand")) {
				res = MOBILE_IMAGE_MOUNTER_E_NOT_SUPPORTED;
			} else if (errstr && !strcmp(errstr, "DeviceLocked")) {
				res = MOBILE_IMAGE_MOUNTER_E_DEVICE_LOCKED;
			} else if (strstr(detailederr, "no matching entry")) {
				res = MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED;
			} else {
				res = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
			}
		}
	}

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}

mobile_image_mounter_error_t mobile_image_mounter_hangup(mobile_image_mounter_client_t client)
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

mobile_image_mounter_error_t mobile_image_mounter_query_developer_mode_status(mobile_image_mounter_client_t client, plist_t *result)
{
	if (!client || !result) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("QueryDeveloperModeStatus"));
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

mobile_image_mounter_error_t mobile_image_mounter_query_nonce(mobile_image_mounter_client_t client, const char* image_type, unsigned char** nonce, unsigned int* nonce_size)
{
	if (!client || !nonce || !nonce_size) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("QueryNonce"));
	if (image_type) {
		plist_dict_set_item(dict, "PersonalizedImageType", plist_new_string(image_type));
	}
	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	plist_t result = NULL;
	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	} else {
		plist_t p_nonce = plist_dict_get_item(result, "PersonalizationNonce");
		if (!p_nonce) {
			res = MOBILE_IMAGE_MOUNTER_E_NOT_SUPPORTED;
		} else {
			uint64_t nonce_size_ = 0;
			plist_get_data_val(p_nonce, (char**)nonce, &nonce_size_);
			if (*nonce) {
				*nonce_size = (unsigned int)nonce_size_;
			} else {
				res = MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED;
			}
		}
	}
	plist_free(result);

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}

mobile_image_mounter_error_t mobile_image_mounter_query_personalization_identifiers(mobile_image_mounter_client_t client, const char* image_type, plist_t *result)
{
	if (!client || !result) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("QueryPersonalizationIdentifiers"));
	if (image_type) {
		plist_dict_set_item(dict, "PersonalizedImageType", plist_new_string(image_type));
	}
	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	plist_t _result = NULL;
	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &_result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}
	*result = plist_copy(plist_dict_get_item(_result, "PersonalizationIdentifiers"));
	if (!*result) {
		debug_info("%s: Response did not contain PersonalizationIdentifiers!", __func__);
		res = MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED;
	}

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}

mobile_image_mounter_error_t mobile_image_mounter_query_personalization_manifest(mobile_image_mounter_client_t client, const char* image_type, const unsigned char* signature, unsigned int signature_size, unsigned char** manifest, unsigned int* manifest_size)
{
	if (!client || !image_type || !signature || !signature_size || !manifest || !manifest_size) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("QueryPersonalizationManifest"));
	plist_dict_set_item(dict, "PersonalizedImageType", plist_new_string(image_type));
	plist_dict_set_item(dict, "ImageType", plist_new_string(image_type));
	plist_dict_set_item(dict, "ImageSignature", plist_new_data((char*)signature, signature_size));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	plist_t result = NULL;
	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	} else {
		plist_t p_manifest = plist_dict_get_item(result, "ImageSignature");
		if (!p_manifest) {
			res = MOBILE_IMAGE_MOUNTER_E_NOT_SUPPORTED;
		} else {
			uint64_t manifest_size_ = 0;
			plist_get_data_val(p_manifest, (char**)manifest, &manifest_size_);
			if (*manifest) {
				*manifest_size = (unsigned int)manifest_size_;
			} else {
				res = MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED;
			}
		}
	}
	plist_free(result);

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}

mobile_image_mounter_error_t mobile_image_mounter_roll_personalization_nonce(mobile_image_mounter_client_t client)
{
	if (!client) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("RollPersonalizationNonce"));
	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	plist_t result = NULL;
	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}
	plist_free(result);

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}

mobile_image_mounter_error_t mobile_image_mounter_roll_cryptex_nonce(mobile_image_mounter_client_t client)
{
	if (!client) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("RollCryptexNonce"));
	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	plist_t result = NULL;
	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}
	plist_free(result);

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}
