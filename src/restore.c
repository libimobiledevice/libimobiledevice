/*
 * restore.c
 * com.apple.mobile.restored service implementation.
 *
 * Copyright (c) 2010 Joshua Hill. All Rights Reserved.
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

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <plist/plist.h>

#include "property_list_service.h"
#include "restore.h"
#include "idevice.h"
#include "common/debug.h"

#define RESULT_SUCCESS 0
#define RESULT_FAILURE 1

/**
 * Internally used function for checking the result from restore's answer
 * plist to a previously sent request.
 *
 * @param dict The plist to evaluate.
 * @param query_match Name of the request to match.
 *
 * @return RESULT_SUCCESS when the result is 'Success',
 *         RESULT_FAILURE when the result is 'Failure',
 *         or a negative value if an error occured during evaluation.
 */
static int restored_check_result(plist_t dict)
{
	int ret = -1;
	plist_t result_node = plist_dict_get_item(dict, "Result");
	if (!result_node) {
		return ret;
	}

	plist_type result_type = plist_get_node_type(result_node);

	if (result_type == PLIST_STRING) {

		char *result_value = NULL;

		plist_get_string_val(result_node, &result_value);

		if (result_value) {
			if (!strcmp(result_value, "Success")) {
				ret = RESULT_SUCCESS;
			} else if (!strcmp(result_value, "Failure")) {
				ret = RESULT_FAILURE;
			} else {
				debug_info("ERROR: unknown result value '%s'", result_value);
			}
		}
		if (result_value)
			free(result_value);
	}
	return ret;
}

/**
 * Adds a label key with the passed value to a plist dict node.
 *
 * @param plist The plist to add the key to
 * @param label The value for the label key
 *
 */
static void plist_dict_add_label(plist_t plist, const char *label)
{
	if (plist && label) {
		if (plist_get_node_type(plist) == PLIST_DICT)
			plist_dict_set_item(plist, "Label", plist_new_string(label));
	}
}

restored_error_t restored_client_free(restored_client_t client)
{
	if (!client)
		return RESTORE_E_INVALID_ARG;
		
	restored_error_t ret = RESTORE_E_UNKNOWN_ERROR;

	if (client->parent) {
		restored_goodbye(client);

		if (property_list_service_client_free(client->parent) == PROPERTY_LIST_SERVICE_E_SUCCESS) {
			ret = RESTORE_E_SUCCESS;
		}
	}

	if (client->udid) {
		free(client->udid);
	}
	if (client->label) {
		free(client->label);
	}
	
	if (client->info) {
		plist_free(client->info);
	}

	free(client);
	return ret;
}

void restored_client_set_label(restored_client_t client, const char *label)
{
	if (client) {
		if (client->label)
			free(client->label);

		client->label = (label != NULL) ? strdup(label): NULL;
	}
}

restored_error_t restored_receive(restored_client_t client, plist_t *plist)
{
	if (!client || !plist || (plist && *plist))
		return RESTORE_E_INVALID_ARG;
		
	restored_error_t ret = RESTORE_E_SUCCESS;
	property_list_service_error_t err;

	err = property_list_service_receive_plist(client->parent, plist);
	if (err != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		ret = RESTORE_E_UNKNOWN_ERROR;
	}

	if (!*plist)
		ret = RESTORE_E_PLIST_ERROR;

	return ret;
}

restored_error_t restored_send(restored_client_t client, plist_t plist)
{
	if (!client || !plist)
		return RESTORE_E_INVALID_ARG;

	restored_error_t ret = RESTORE_E_SUCCESS;
	idevice_error_t err;

	err = property_list_service_send_xml_plist(client->parent, plist);
	if (err != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		ret = RESTORE_E_UNKNOWN_ERROR;
	}
	return ret;
}

restored_error_t restored_query_type(restored_client_t client, char **type, uint64_t *version)
{
	if (!client)
		return RESTORE_E_INVALID_ARG;

	restored_error_t ret = RESTORE_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict,"Request", plist_new_string("QueryType"));

	debug_info("called");
	ret = restored_send(client, dict);

	plist_free(dict);
	dict = NULL;

	ret = restored_receive(client, &dict);
	
	if (RESTORE_E_SUCCESS != ret)
		return ret;

	ret = RESTORE_E_UNKNOWN_ERROR;
	plist_t type_node = plist_dict_get_item(dict, "Type");
	if (type_node && (plist_get_node_type(type_node) == PLIST_STRING)) {
		char* typestr = NULL;

		/* save our device information info */
		client->info = dict;

		plist_get_string_val(type_node, &typestr);
		debug_info("success with type %s", typestr);
		/* return the type if requested */
		if (type) {
			*type = typestr;
		} else {
			free(typestr);
		}

		/* fetch the restore protocol version */
		if (version) {
			plist_t version_node = plist_dict_get_item(dict, "RestoreProtocolVersion");
			if (version_node && PLIST_UINT == plist_get_node_type(version_node)) {
				plist_get_uint_val(version_node, version);
				debug_info("restored protocol version %llu", *version);
			} else {
				return RESTORE_E_UNKNOWN_ERROR;
			}
		}
		ret = RESTORE_E_SUCCESS;
	} else {
		debug_info("hmm. QueryType response does not contain a type?!");
		debug_plist(dict);
		plist_free(dict);
	}

	return ret;
}

restored_error_t restored_query_value(restored_client_t client, const char *key, plist_t *value)
{
	if (!client || !key)
		return RESTORE_E_INVALID_ARG;

	plist_t dict = NULL;
	restored_error_t ret = RESTORE_E_UNKNOWN_ERROR;

	/* setup request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	if (key) {
		plist_dict_set_item(dict,"QueryKey", plist_new_string(key));
	}
	plist_dict_set_item(dict,"Request", plist_new_string("QueryValue"));

	/* send to device */
	ret = restored_send(client, dict);

	plist_free(dict);
	dict = NULL;

	if (ret != RESTORE_E_SUCCESS)
		return ret;

	/* Now get device's answer */
	ret = restored_receive(client, &dict);
	if (ret != RESTORE_E_SUCCESS)
		return ret;

	plist_t value_node = plist_dict_get_item(dict, key);
	if (value_node) {
		debug_info("has a value");
		*value = plist_copy(value_node);
	} else {
		ret = RESTORE_E_PLIST_ERROR;
	}

	plist_free(dict);
	return ret;
}

restored_error_t restored_get_value(restored_client_t client, const char *key, plist_t *value)
{
	if (!client || !value || (value && *value))
		return RESTORE_E_INVALID_ARG;
		
	if (!client->info)
		return RESTORE_E_NOT_ENOUGH_DATA;
		
	restored_error_t ret = RESTORE_E_SUCCESS;
	plist_t item = NULL;
	
	if (!key) {
		*value = plist_copy(client->info);
		return RESTORE_E_SUCCESS;
	} else {
		item = plist_dict_get_item(client->info, key);
	}
	
	if (item) {
		*value = plist_copy(item);
	} else {
		ret = RESTORE_E_PLIST_ERROR;
	}
	
	return ret;
}

restored_error_t restored_client_new(idevice_t device, restored_client_t *client, const char *label)
{
	if (!client)
		return RESTORE_E_INVALID_ARG;

	restored_error_t ret = RESTORE_E_SUCCESS;

	static struct lockdownd_service_descriptor service = {
		.port = 0xf27e,
		.ssl_enabled = 0
	};

	property_list_service_client_t plistclient = NULL;
	if (property_list_service_client_new(device, (lockdownd_service_descriptor_t)&service, &plistclient) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		debug_info("could not connect to restored (device %s)", device->udid);
		return RESTORE_E_MUX_ERROR;
	}

	restored_client_t client_loc = (restored_client_t) malloc(sizeof(struct restored_client_private));
	client_loc->parent = plistclient;
	client_loc->udid = NULL;
	client_loc->label = NULL;
	client_loc->info = NULL;
	if (label != NULL)
		client_loc->label = strdup(label);

	ret = idevice_get_udid(device, &client_loc->udid);
	if (RESTORE_E_SUCCESS != ret) {
		debug_info("failed to get device udid.");
	}
	debug_info("device udid: %s", client_loc->udid);

	if (RESTORE_E_SUCCESS == ret) {
		*client = client_loc;
	} else {
		restored_client_free(client_loc);
	}

	return ret;
}

restored_error_t restored_goodbye(restored_client_t client)
{
	if (!client)
		return RESTORE_E_INVALID_ARG;

	restored_error_t ret = RESTORE_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict,"Request", plist_new_string("Goodbye"));

	debug_info("called");

	ret = restored_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = restored_receive(client, &dict);
	if (!dict) {
		debug_info("did not get goodbye response back");
		return RESTORE_E_PLIST_ERROR;
	}

	if (restored_check_result(dict) == RESULT_SUCCESS) {
		debug_info("success");
		ret = RESTORE_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;
	return ret;
}

restored_error_t restored_start_restore(restored_client_t client, plist_t options, uint64_t version)
{
	if (!client)
		return RESTORE_E_INVALID_ARG;

	plist_t dict = NULL;
	restored_error_t ret = RESTORE_E_UNKNOWN_ERROR;

	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict,"Request", plist_new_string("StartRestore"));
	if (options) {
		plist_dict_set_item(dict, "RestoreOptions", plist_copy(options));
	}
	plist_dict_set_item(dict,"RestoreProtocolVersion", plist_new_uint(version));

	/* send to device */
	ret = restored_send(client, dict);
	plist_free(dict);
	dict = NULL;

	return ret;
}

restored_error_t restored_reboot(restored_client_t client)
{
	if (!client)
		return RESTORE_E_INVALID_ARG;

	plist_t dict = NULL;
	restored_error_t ret = RESTORE_E_UNKNOWN_ERROR;

	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict,"Request", plist_new_string("Reboot"));

	/* send to device */
	ret = restored_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (RESTORE_E_SUCCESS != ret)
		return ret;

	ret = restored_receive(client, &dict);
	if (RESTORE_E_SUCCESS != ret)
		return ret;

	if (!dict)
		return RESTORE_E_PLIST_ERROR;

	plist_free(dict);
	dict = NULL;
	return ret;
}

