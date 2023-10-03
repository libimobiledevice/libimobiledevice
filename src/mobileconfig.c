/*
 * mobileconfig.c
 * com.apple.mobile.MCInstall service implementation.
 *
 * Copyright (c) 2012 Nikias Bassen, All Rights Reserved.
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
#include <unistd.h>
#include <plist/plist.h>
#include <stdio.h>

#include "mobileconfig.h"
#include "property_list_service.h"
#include "common/debug.h"

/**
 * Convert a property_list_service_error_t value to a mobileconfig_error_t
 * value. Used internally to get correct error codes.
 *
 * @param err A property_list_service_error_t error code
 *
 * @return A matching mobileconfig_error_t error code,
 *     MOBILECONFIG_E_UNKNOWN_ERROR otherwise.
 */
static mobileconfig_error_t mobileconfig_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return MOBILECONFIG_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return MOBILECONFIG_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return MOBILECONFIG_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return MOBILECONFIG_E_CONN_FAILED;
		default:
			break;
	}
	return MOBILECONFIG_E_UNKNOWN_ERROR;
}

/**
 * Checks the response from MCInstal to determine if the operation
 * was successful or an error occurred. Internally used only.
 *
 * @param response a PLIST_DICT received from device's MCInstall
 * @param status_code pointer to an int that will be set to the status code
 *   contained in the response
 */
static mobileconfig_error_t mobileconfig_check_result(plist_t response, int* status_code)
{
	if (plist_get_node_type(response) != PLIST_DICT) {
		return MOBILECONFIG_E_PLIST_ERROR;
	}

	plist_t node = plist_dict_get_item(response, "Status");
	if (!node || (plist_get_node_type(node) != PLIST_STRING)) {
		return MOBILECONFIG_E_PLIST_ERROR;
	}

    char* val = NULL;
    plist_get_string_val(node, &val);
    if (strcmp(val, "Acknowledged") != 0) {
		plist_free(node);
        return MOBILECONFIG_E_PLIST_ERROR;
    }
	plist_free(node);
    return MOBILECONFIG_E_SUCCESS;

	// uint64_t val = -1LL;
	// plist_get_uint_val(node, &val);
	// if ((int64_t)val == -1LL) {
	// 	return MOBILECONFIG_E_PLIST_ERROR;
	// }
	// *status_code = (int)(val & 0xFFFFFFFF);
	// if (*status_code == 0) {
	// 	return MOBILECONFIG_E_SUCCESS;
	// } else {
	// 	return MOBILECONFIG_E_REQUEST_FAILED;
	// }
}

LIBIMOBILEDEVICE_API mobileconfig_error_t mobileconfig_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobileconfig_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	mobileconfig_error_t err = mobileconfig_error(property_list_service_client_new(device, service, &plistclient));
	if (err != MOBILECONFIG_E_SUCCESS) {
		return err;
	}

	mobileconfig_client_t client_loc = (mobileconfig_client_t) malloc(sizeof(struct mobileconfig_client_private));
	client_loc->parent = plistclient;
	client_loc->last_error = 0;

	*client = client_loc;
	return MOBILECONFIG_E_SUCCESS;
}

LIBIMOBILEDEVICE_API mobileconfig_error_t mobileconfig_client_start_service(idevice_t device, mobileconfig_client_t * client, const char* label)
{
	mobileconfig_error_t err = MOBILECONFIG_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, MOBILECONFIG_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(mobileconfig_client_new), &err);
	return err;
}

LIBIMOBILEDEVICE_API mobileconfig_error_t mobileconfig_client_free(mobileconfig_client_t client)
{
	if (!client)
		return MOBILECONFIG_E_INVALID_ARG;

	mobileconfig_error_t err = MOBILECONFIG_E_SUCCESS;
	if (client->parent && client->parent->parent) {
		mobileconfig_error(property_list_service_client_free(client->parent));
	}
	client->parent = NULL;
	free(client);

	return err;
}

LIBIMOBILEDEVICE_API mobileconfig_error_t mobileconfig_install(mobileconfig_client_t client, plist_t profile)
{
	if (!client || !client->parent || !profile || (plist_get_node_type(profile) != PLIST_DATA)) {
		debug_info("Unexpected PLIST_TYPE");
		return MOBILECONFIG_E_INVALID_ARG;
	}

	client->last_error = MOBILECONFIG_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "RequestType", plist_new_string("InstallProfile"));
	plist_dict_set_item(dict, "Payload", plist_copy(profile));
	// plist_dict_set_item(dict, "MessageType", plist_new_string("Install"));
	// plist_dict_set_item(dict, "Profile", plist_copy(profile));
	// plist_dict_set_item(dict, "ProfileType", plist_new_string("Provisioning"));

	mobileconfig_error_t res = mobileconfig_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	dict = NULL;

	if (res != MOBILECONFIG_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	res = mobileconfig_error(property_list_service_receive_plist(client->parent, &dict));
	if (res != MOBILECONFIG_E_SUCCESS) {
		debug_info("could not receive response, error %d", res);
		return res;
	}
	if (!dict) {
		debug_info("could not get response plist");
		return MOBILECONFIG_E_UNKNOWN_ERROR;
	}

	res = mobileconfig_check_result(dict, &client->last_error);
	plist_free(dict);

	return res;
}

LIBIMOBILEDEVICE_API mobileconfig_error_t mobileconfig_erase(mobileconfig_client_t client)
{
    client->last_error = MOBILECONFIG_E_UNKNOWN_ERROR;

    plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "RequestType", plist_new_string("EraseDevice"));
    //plist_dict_set_item(dict, "Payload", plist_copy(profile));
    // plist_dict_set_item(dict, "MessageType", plist_new_string("Install"));
    // plist_dict_set_item(dict, "Profile", plist_copy(profile));
    // plist_dict_set_item(dict, "ProfileType", plist_new_string("Provisioning"));

    mobileconfig_error_t res = mobileconfig_error(property_list_service_send_xml_plist(client->parent, dict));
    plist_free(dict);
    dict = NULL;

    if (res != MOBILECONFIG_E_SUCCESS) {
        debug_info("could not send plist, error %d", res);
        return res;
    }
    
    res = MOBILECONFIG_E_SUCCESS;

    // res = mobileconfig_error(property_list_service_receive_plist(client->parent, &dict));
    // if (res != MOBILECONFIG_E_SUCCESS) {
    //     debug_info("could not receive response, error %d", res);
    //     return res;
    // }
    // if (!dict) {
    //     debug_info("could not get response plist");
    //     return MOBILECONFIG_E_UNKNOWN_ERROR;
    // }

    // res = mobileconfig_check_result(dict, &client->last_error);
    plist_free(dict);

    return res;
}


LIBIMOBILEDEVICE_API mobileconfig_error_t mobileconfig_copy(mobileconfig_client_t client, plist_t* profiles, uint16_t justName)
{
	if (!client || !client->parent || !profiles)
		return MOBILECONFIG_E_INVALID_ARG;

	client->last_error = MOBILECONFIG_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "RequestType", plist_new_string("GetProfileList"));
	//plist_dict_set_item(dict, "MessageType", plist_new_string("Copy"));
	//plist_dict_set_item(dict, "ProfileType", plist_new_string("Provisioning"));

	mobileconfig_error_t res = mobileconfig_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	dict = NULL;

	if (res != MOBILECONFIG_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	res = mobileconfig_error(property_list_service_receive_plist(client->parent, &dict));
	if (res != MOBILECONFIG_E_SUCCESS) {
		debug_info("could not receive response, error %d", res);
		return res;
	}
	if (!dict) {
		debug_info("could not get response plist");
		return MOBILECONFIG_E_UNKNOWN_ERROR;
	}

	res = mobileconfig_check_result(dict, &client->last_error);
	if (res == MOBILECONFIG_E_SUCCESS) {
		if(justName == 0) {
			*profiles = plist_copy(plist_dict_get_item(dict, "OrderedIdentifiers"));
		}
		else
		{
			*profiles = plist_copy(plist_dict_get_item(dict, "ProfileMetadata"));
		}
	}
	plist_free(dict);

	return res;

}

LIBIMOBILEDEVICE_API mobileconfig_error_t mobileconfig_copy_all(mobileconfig_client_t client, plist_t* profiles, uint16_t justName)
{
	if (!client || !client->parent || !profiles)
		return MOBILECONFIG_E_INVALID_ARG;

	client->last_error = MOBILECONFIG_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "RequestType", plist_new_string("GetProfileList"));
	//plist_dict_set_item(dict, "MessageType", plist_new_string("CopyAll"));
	//plist_dict_set_item(dict, "ProfileType", plist_new_string("Provisioning"));

	mobileconfig_error_t res = mobileconfig_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	dict = NULL;

	if (res != MOBILECONFIG_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	res = mobileconfig_error(property_list_service_receive_plist(client->parent, &dict));
	if (res != MOBILECONFIG_E_SUCCESS) {
		debug_info("could not receive response, error %d", res);
		return res;
	}
	if (!dict) {
		debug_info("could not get response plist");
		return MOBILECONFIG_E_UNKNOWN_ERROR;
	}

	res = mobileconfig_check_result(dict, &client->last_error);
	if (res == MOBILECONFIG_E_SUCCESS) {
		if(justName == 0) {
			*profiles = plist_copy(plist_dict_get_item(dict, "OrderedIdentifiers"));
		}
		else
		{
			*profiles = plist_copy(plist_dict_get_item(dict, "ProfileMetadata"));
		}	
	}
	plist_free(dict);

	return res;

}

LIBIMOBILEDEVICE_API mobileconfig_error_t mobileconfig_remove(mobileconfig_client_t client, const char* profileID, const char* UUID, uint64_t version)
{
	if (!client || !client->parent || !profileID)
		return MOBILECONFIG_E_INVALID_ARG;

	client->last_error = MOBILECONFIG_E_UNKNOWN_ERROR;

	plist_t temp_dict = plist_new_dict();
	char* xml = NULL;
	uint32_t xlen = 0;
	plist_dict_set_item(temp_dict, "PayloadType", plist_new_string("Configuration"));
	plist_dict_set_item(temp_dict, "PayloadIdentifier", plist_new_string(profileID));
	plist_dict_set_item(temp_dict, "PayloadUUID", plist_new_string(UUID));
	plist_dict_set_item(temp_dict, "PayloadVersion", plist_new_uint(version));
	plist_to_xml(temp_dict, &xml, &xlen);
	plist_t profile_dict = plist_new_data(xml, xlen);
	plist_free(temp_dict);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "RequestType", plist_new_string("RemoveProfile"));
	plist_dict_set_item(dict, "ProfileIdentifier", profile_dict);

	mobileconfig_error_t res = mobileconfig_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	plist_mem_free(xml);
	dict = NULL;

	if (res != MOBILECONFIG_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	res = mobileconfig_error(property_list_service_receive_plist(client->parent, &dict));
	if (res != MOBILECONFIG_E_SUCCESS) {
		debug_info("could not receive response, error %d", res);
		return res;
	}
	if (!dict) {
		debug_info("could not get response plist");
		return MOBILECONFIG_E_UNKNOWN_ERROR;
	}

	res = mobileconfig_check_result(dict, &client->last_error);
	plist_free(dict);

	return res;
}

LIBIMOBILEDEVICE_API int mobileconfig_get_status_code(mobileconfig_client_t client)
{
	if (!client) {
		return -1;
	}
	return client->last_error;
}
