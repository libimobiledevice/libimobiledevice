/*
 * mcinstall.c
 * com.apple.mobile.MCInstall service implementation.
 *
 * Copyright (c) 2020 Ethan Carlson, All Rights Reserved.
 * Uses base code from misagent.c Copyright Nikias Bassen
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

#include "mcinstall.h"
#include "property_list_service.h"
#include "common/debug.h"
#include "common/utils.h"

/**
 * Convert a property_list_service_error_t value to a mcinstall_error_t
 * value. Used internally to get correct error codes.
 *
 * @param err A property_list_service_error_t error code
 *
 * @return A matching mcinstall_error_t error code,
 *     MCINSTALL_E_UNKNOWN_ERROR otherwise.
 */
static mcinstall_error_t mcinstall_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return MCINSTALL_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return MCINSTALL_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return MCINSTALL_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return MCINSTALL_E_CONN_FAILED;
		default:
			break;
	}
	return MCINSTALL_E_UNKNOWN_ERROR;
}

static mcinstall_error_t mcinstall_check_result(plist_t response, int* status_code)
{
    if (plist_get_node_type(response) != PLIST_DICT) {
        return MCINSTALL_E_PLIST_ERROR;
    }

    plist_t node = plist_dict_get_item(response, "Status");
    if (!node || (plist_get_node_type(node) != PLIST_STRING)) {
        debug_info("plist error");
        return MCINSTALL_E_PLIST_ERROR;
    }
    char *query_value = NULL;

    plist_get_string_val(node, &query_value);
    if (!query_value) {
        debug_info("no plist value");
        return MCINSTALL_E_REQUEST_FAILED;
    }

    if (strcmp(query_value, "Acknowledged") == 0) {
        debug_info("success");
        free(query_value);
        return MCINSTALL_E_SUCCESS;
    } else {
        debug_info("values not equal %s", query_value);
        free(query_value);
        return MCINSTALL_E_REQUEST_FAILED;
    }
}

LIBIMOBILEDEVICE_API mcinstall_error_t mcinstall_client_new(idevice_t device, lockdownd_service_descriptor_t service, mcinstall_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	mcinstall_error_t err = mcinstall_error(property_list_service_client_new(device, service, &plistclient));
	if (err != MCINSTALL_E_SUCCESS) {
		return err;
	}

	mcinstall_client_t client_loc = (mcinstall_client_t) malloc(sizeof(struct mcinstall_client_private));
	client_loc->parent = plistclient;
	client_loc->last_error = 0;

	*client = client_loc;
	return MCINSTALL_E_SUCCESS;
}

LIBIMOBILEDEVICE_API mcinstall_error_t mcinstall_client_start_service(idevice_t device, mcinstall_client_t * client, const char* label)
{
	mcinstall_error_t err = MCINSTALL_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, MCINSTALL_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(mcinstall_client_new), &err);
	return err;
}

LIBIMOBILEDEVICE_API mcinstall_error_t mcinstall_client_free(mcinstall_client_t client)
{
	if (!client)
		return MCINSTALL_E_INVALID_ARG;

	mcinstall_error_t err = MCINSTALL_E_SUCCESS;
	if (client->parent && client->parent->parent) {
		mcinstall_error(property_list_service_client_free(client->parent));
	}
	client->parent = NULL;
	free(client);

	return err;
}

LIBIMOBILEDEVICE_API mcinstall_error_t mcinstall_install(mcinstall_client_t client, plist_t profile)
{
    if (!client || !client->parent || !profile || (plist_get_node_type(profile) != PLIST_DATA))
        return MCINSTALL_E_INVALID_ARG;

    client->last_error = MCINSTALL_E_UNKNOWN_ERROR;

    plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "RequestType", plist_new_string("InstallProfile"));
    plist_dict_set_item(dict, "Payload", plist_copy(profile));

    mcinstall_error_t res = mcinstall_error(property_list_service_send_xml_plist(client->parent, dict));
    plist_free(dict);
    dict = NULL;

    if (res != MCINSTALL_E_SUCCESS) {
        debug_info("could not send plist, error %d", res);
        return res;
    }

    res = mcinstall_error(property_list_service_receive_plist(client->parent, &dict));
    if (res != MCINSTALL_E_SUCCESS) {
        debug_info("could not receive response, error %d", res);
        return res;
    }
    if (!dict) {
        debug_info("could not get response plist");
        return MCINSTALL_E_UNKNOWN_ERROR;
    }

    res = mcinstall_check_result(dict, &client->last_error);
    plist_free(dict);

    return res;
}

LIBIMOBILEDEVICE_API mcinstall_error_t mcinstall_copy(mcinstall_client_t client, plist_t* profiles)
{
	if (!client || !client->parent || !profiles)
		return MCINSTALL_E_INVALID_ARG;

	client->last_error = MCINSTALL_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "RequestType", plist_new_string("GetProfileList"));

	mcinstall_error_t res = mcinstall_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	dict = NULL;

	if (res != MCINSTALL_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	res = mcinstall_error(property_list_service_receive_plist(client->parent, &dict));
	if (res != MCINSTALL_E_SUCCESS) {
		debug_info("could not receive response, error %d", res);
		return res;
	}
	if (!dict) {
		debug_info("could not get response plist");
		return MCINSTALL_E_UNKNOWN_ERROR;
	}

	res = mcinstall_check_result(dict, &client->last_error);
	if (res == MCINSTALL_E_SUCCESS) {
		*profiles = plist_copy(dict);
	}
	plist_free(dict);

	return res;

}

LIBIMOBILEDEVICE_API mcinstall_error_t mcinstall_install_cloud_config(mcinstall_client_t client, plist_t profile)
{
    if (!client || !client->parent || !profile || (plist_get_node_type(profile) != PLIST_DICT))
        return MCINSTALL_E_INVALID_ARG;

    client->last_error = MCINSTALL_E_UNKNOWN_ERROR;

    plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "RequestType", plist_new_string("SetCloudConfiguration"));
    plist_dict_set_item(dict, "CloudConfiguration", plist_copy(profile));
    plist_print_to_stream(dict, stdout);

    mcinstall_error_t res = mcinstall_error(property_list_service_send_xml_plist(client->parent, dict));
    plist_free(dict);
    dict = NULL;

    if (res != MCINSTALL_E_SUCCESS) {
        debug_info("could not send plist, error %d", res);
        return res;
    }

    res = mcinstall_error(property_list_service_receive_plist(client->parent, &dict));
    if (res != MCINSTALL_E_SUCCESS) {
        debug_info("could not receive response, error %d", res);
        return res;
    }
    if (!dict) {
        debug_info("could not get response plist");
        return MCINSTALL_E_UNKNOWN_ERROR;
    }

    res = mcinstall_check_result(dict, &client->last_error);
    plist_free(dict);

    return res;
}

LIBIMOBILEDEVICE_API mcinstall_error_t mcinstall_get_cloud_config(mcinstall_client_t client, plist_t* profiles)
{
	if (!client || !client->parent || !profiles)
		return MCINSTALL_E_INVALID_ARG;

	client->last_error = MCINSTALL_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "RequestType", plist_new_string("GetCloudConfiguration"));

	mcinstall_error_t res = mcinstall_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	dict = NULL;

	if (res != MCINSTALL_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	res = mcinstall_error(property_list_service_receive_plist(client->parent, &dict));
	if (res != MCINSTALL_E_SUCCESS) {
		debug_info("could not receive response, error %d", res);
		return res;
	}
	if (!dict) {
		debug_info("could not get response plist");
		return MCINSTALL_E_UNKNOWN_ERROR;
	}

	res = mcinstall_check_result(dict, &client->last_error);
	if (res == MCINSTALL_E_SUCCESS) {
		*profiles = plist_copy(dict);
	}
	plist_free(dict);

	return res;

}

LIBIMOBILEDEVICE_API mcinstall_error_t mcinstall_download_cloud_config(mcinstall_client_t client, plist_t* profiles)
{
	if (!client || !client->parent || !profiles)
		return MCINSTALL_E_INVALID_ARG;

	client->last_error = MCINSTALL_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
    
	plist_dict_set_item(dict, "RequestType", plist_new_string("DownloadAndApplyCloudConfiguration"));


	mcinstall_error_t res = mcinstall_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	dict = NULL;

	if (res != MCINSTALL_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	res = mcinstall_error(property_list_service_receive_plist(client->parent, &dict));
	if (res != MCINSTALL_E_SUCCESS) {
		debug_info("could not receive response, error %d", res);
		return res;
	}
	if (!dict) {
		debug_info("could not get response plist");
		return MCINSTALL_E_UNKNOWN_ERROR;
	}

	res = mcinstall_check_result(dict, &client->last_error);
	if (res == MCINSTALL_E_SUCCESS) {
		*profiles = plist_copy(dict);
	}
	plist_free(dict);

	return res;

}

LIBIMOBILEDEVICE_API mcinstall_error_t mcinstall_remove(mcinstall_client_t client, plist_t profile, const char* profileID)
{
	if (!client || !client->parent || !profile)
		return MCINSTALL_E_INVALID_ARG;

	client->last_error = MCINSTALL_E_UNKNOWN_ERROR;

    plist_t profileInfoDict = plist_new_dict();
    plist_dict_set_item(profileInfoDict, "PayloadType", plist_new_string("Configuration"));
    plist_dict_set_item(profileInfoDict, "PayloadIdentifier", plist_new_string(profileID));

    

    plist_t uuid = plist_dict_get_item(profile, "PayloadUUID");
    plist_dict_set_item(profileInfoDict, "PayloadUUID", plist_copy(uuid));

    plist_t payloadVersion = plist_dict_get_item(profile, "PayloadVersion");
    plist_dict_set_item(profileInfoDict, "PayloadVersion", plist_copy(payloadVersion));
    

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "RequestType", plist_new_string("RemoveProfile"));
    char* xml = NULL;
	uint32_t xlen = 0;
	
    plist_to_bin(profileInfoDict, &xml, &xlen);
    
	plist_dict_set_item(dict, "ProfileIdentifier", plist_new_data(xml, xlen));

	mcinstall_error_t res = mcinstall_error(property_list_service_send_xml_plist(client->parent, dict));

    
    

	if (res != MCINSTALL_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	res = mcinstall_error(property_list_service_receive_plist(client->parent, &dict));
	if (res != MCINSTALL_E_SUCCESS) {
		debug_info("could not receive response, error %d", res);
		return res;
	}
	if (!dict) {
		debug_info("could not get response plist");
		return MCINSTALL_E_UNKNOWN_ERROR;
	}

	res = mcinstall_check_result(dict, &client->last_error);
	plist_free(dict);

	return res;
}


LIBIMOBILEDEVICE_API int mcinstall_get_status_code(mcinstall_client_t client)
{
	if (!client) {
		return -1;
	}
	return client->last_error;
}
