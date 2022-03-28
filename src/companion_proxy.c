/*
 * companion_proxy.c
 * com.apple.companion_proxy service implementation.
 *
 * Copyright (c) 2019-2020 Nikias Bassen, All Rights Reserved.
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
#include <plist/plist.h>

#include "companion_proxy.h"
#include "lockdown.h"
#include "common/debug.h"

/**
 * Convert a property_list_service_error_t value to a companion_proxy_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An property_list_service_error_t error code
 *
 * @return A matching companion_proxy_error_t error code,
 *     COMPANION_PROXY_E_UNKNOWN_ERROR otherwise.
 */
static companion_proxy_error_t companion_proxy_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return COMPANION_PROXY_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return COMPANION_PROXY_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return COMPANION_PROXY_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return COMPANION_PROXY_E_MUX_ERROR;
		case PROPERTY_LIST_SERVICE_E_SSL_ERROR:
			return COMPANION_PROXY_E_SSL_ERROR;
		case PROPERTY_LIST_SERVICE_E_NOT_ENOUGH_DATA:
			return COMPANION_PROXY_E_NOT_ENOUGH_DATA;
		case PROPERTY_LIST_SERVICE_E_RECEIVE_TIMEOUT:
			return COMPANION_PROXY_E_TIMEOUT;
		default:
			break;
	}
	return COMPANION_PROXY_E_UNKNOWN_ERROR;
}

companion_proxy_error_t companion_proxy_client_new(idevice_t device, lockdownd_service_descriptor_t service, companion_proxy_client_t * client)
{
	*client = NULL;

	if (!device || !service || service->port == 0 || !client || *client) {
		debug_info("Incorrect parameter passed to companion_proxy_client_new.");
		return COMPANION_PROXY_E_INVALID_ARG;
	}

	debug_info("Creating companion_proxy_client, port = %d.", service->port);

	property_list_service_client_t plclient = NULL;
	companion_proxy_error_t ret = companion_proxy_error(property_list_service_client_new(device, service, &plclient));
	if (ret != COMPANION_PROXY_E_SUCCESS) {
		debug_info("Creating a property list client failed. Error: %i", ret);
		return ret;
	}

	companion_proxy_client_t client_loc = (companion_proxy_client_t) malloc(sizeof(struct companion_proxy_client_private));
	client_loc->parent = plclient;
	client_loc->event_thread = THREAD_T_NULL;

	*client = client_loc;

	debug_info("Created companion_proxy_client successfully.");
	return COMPANION_PROXY_E_SUCCESS;
}

companion_proxy_error_t companion_proxy_client_start_service(idevice_t device, companion_proxy_client_t * client, const char* label)
{
	companion_proxy_error_t err = COMPANION_PROXY_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, COMPANION_PROXY_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(companion_proxy_client_new), &err);
	return err;
}

companion_proxy_error_t companion_proxy_client_free(companion_proxy_client_t client)
{
	if (!client)
		return COMPANION_PROXY_E_INVALID_ARG;

	property_list_service_client_t parent = client->parent;
	client->parent = NULL;
	if (client->event_thread) {
		debug_info("joining event thread");
		thread_join(client->event_thread);
		thread_free(client->event_thread);
		client->event_thread = THREAD_T_NULL;
	}
	companion_proxy_error_t err = companion_proxy_error(property_list_service_client_free(parent));
	free(client);

	return err;
}

companion_proxy_error_t companion_proxy_send(companion_proxy_client_t client, plist_t plist)
{
	companion_proxy_error_t res = COMPANION_PROXY_E_UNKNOWN_ERROR;

	res = companion_proxy_error(property_list_service_send_binary_plist(client->parent, plist));
	if (res != COMPANION_PROXY_E_SUCCESS) {
		debug_info("Sending plist failed with error %d", res);
		return res;
	}

	return res;
}

companion_proxy_error_t companion_proxy_receive(companion_proxy_client_t client, plist_t * plist)
{
	companion_proxy_error_t res = COMPANION_PROXY_E_UNKNOWN_ERROR;
	plist_t outplist = NULL;
	res = companion_proxy_error(property_list_service_receive_plist_with_timeout(client->parent, &outplist, 10000));
	if (res != COMPANION_PROXY_E_SUCCESS && res != COMPANION_PROXY_E_TIMEOUT) {
		debug_info("Could not receive plist, error %d", res);
		plist_free(outplist);
	} else if (res == COMPANION_PROXY_E_SUCCESS) {
		*plist = outplist;
	}
	return res;
}

companion_proxy_error_t companion_proxy_get_device_registry(companion_proxy_client_t client, plist_t* paired_devices)
{
	if (!client || !paired_devices) {
		return COMPANION_PROXY_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("GetDeviceRegistry"));

	companion_proxy_error_t res = companion_proxy_send(client, dict);
	plist_free(dict);
	dict = NULL;
	if (res != COMPANION_PROXY_E_SUCCESS) {
		return res;
	}

	res = companion_proxy_receive(client, &dict);
	if (res != COMPANION_PROXY_E_SUCCESS) {
		return res;
	}
	if (!dict || !PLIST_IS_DICT(dict)) {
		return COMPANION_PROXY_E_PLIST_ERROR;
	}
	plist_t val = plist_dict_get_item(dict, "PairedDevicesArray");
	if (val) {
		*paired_devices = plist_copy(val);
		res = COMPANION_PROXY_E_SUCCESS;
	} else {
		res = COMPANION_PROXY_E_UNKNOWN_ERROR;
		val = plist_dict_get_item(dict, "Error");
		if (val) {
			if (plist_string_val_compare(val, "NoPairedWatches")) {
				res = COMPANION_PROXY_E_NO_DEVICES;
			}
		}
	}
	plist_free(dict);
	return res;
}

struct companion_proxy_cb_data {
	companion_proxy_client_t client;
	companion_proxy_device_event_cb_t cbfunc;
	void* user_data;
};

static void* companion_proxy_event_thread(void* arg)
{
	struct companion_proxy_cb_data* data = (struct companion_proxy_cb_data*)arg;
	companion_proxy_client_t client = data->client;
	companion_proxy_error_t res;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("StartListeningForDevices"));
	res = companion_proxy_send(client, command);
	plist_free(command);

	if (res != COMPANION_PROXY_E_SUCCESS) {
		free(data);
		client->event_thread = THREAD_T_NULL;
		return NULL;
	}

	while (client && client->parent) {
		plist_t node = NULL;
		res = companion_proxy_error(property_list_service_receive_plist_with_timeout(client->parent, &node, 1000));
		if (res != COMPANION_PROXY_E_SUCCESS && res != COMPANION_PROXY_E_TIMEOUT) {
			debug_info("could not receive plist, error %d", res);
			break;
		}

		if (node) {
			data->cbfunc(node, data->user_data);
		}
		plist_free(node);
	}

	client->event_thread = THREAD_T_NULL;
	free(data);

	return NULL;
}

companion_proxy_error_t companion_proxy_start_listening_for_devices(companion_proxy_client_t client, companion_proxy_device_event_cb_t callback, void* userdata)
{
	if (!client || !client->parent || !callback) {
		return COMPANION_PROXY_E_INVALID_ARG;
	}

	if (client->event_thread) {
		return COMPANION_PROXY_E_OP_IN_PROGRESS;
	}

	companion_proxy_error_t res = COMPANION_PROXY_E_UNKNOWN_ERROR;
	struct companion_proxy_cb_data *data = (struct companion_proxy_cb_data*)malloc(sizeof(struct companion_proxy_cb_data));
	if (data) {
		data->client = client;
		data->cbfunc = callback;
		data->user_data = userdata;

		if (thread_new(&client->event_thread, companion_proxy_event_thread, data) == 0) {
			res = COMPANION_PROXY_E_SUCCESS;
		} else {
			free(data);
		}
	}
	return res;
}

companion_proxy_error_t companion_proxy_stop_listening_for_devices(companion_proxy_client_t client)
{
	property_list_service_client_t parent = client->parent;
	client->parent = NULL;
	if (client->event_thread) {
		debug_info("joining event thread");
		thread_join(client->event_thread);
		thread_free(client->event_thread);
		client->event_thread = THREAD_T_NULL;
	}
	client->parent = parent;
	return COMPANION_PROXY_E_SUCCESS;
}

companion_proxy_error_t companion_proxy_get_value_from_registry(companion_proxy_client_t client, const char* companion_udid, const char* key, plist_t* value)
{
	if (!client || !companion_udid || !key || !value) {
		return COMPANION_PROXY_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("GetValueFromRegistry"));
	plist_dict_set_item(dict, "GetValueGizmoUDIDKey", plist_new_string(companion_udid));
	plist_dict_set_item(dict, "GetValueKeyKey", plist_new_string(key));

	companion_proxy_error_t res = companion_proxy_send(client, dict);
	plist_free(dict);
	dict = NULL;
	if (res != COMPANION_PROXY_E_SUCCESS) {
		return res;
	}

	res = companion_proxy_receive(client, &dict);
	if (res != COMPANION_PROXY_E_SUCCESS) {
		return res;
	}
	if (!dict || !PLIST_IS_DICT(dict)) {
		return COMPANION_PROXY_E_PLIST_ERROR;
	}
	plist_t val = plist_dict_get_item(dict, "RetrievedValueDictionary");
	if (val) {
		*value = plist_copy(val);
		res = COMPANION_PROXY_E_SUCCESS;
	} else {
		res = COMPANION_PROXY_E_UNKNOWN_ERROR;
		val = plist_dict_get_item(dict, "Error");
		if (val) {
			if (!plist_string_val_compare(val, "UnsupportedWatchKey")) {
				res = COMPANION_PROXY_E_UNSUPPORTED_KEY;
			} else if (plist_string_val_compare(val, "TimeoutReply")) {
				res = COMPANION_PROXY_E_TIMEOUT_REPLY;
			}
		}
	}
	plist_free(dict);
	return res;
}

companion_proxy_error_t companion_proxy_start_forwarding_service_port(companion_proxy_client_t client, uint16_t remote_port, const char* service_name, uint16_t* forward_port, plist_t options)
{
	if (!client) {
		return COMPANION_PROXY_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("StartForwardingServicePort"));
	plist_dict_set_item(dict, "GizmoRemotePortNumber", plist_new_uint(remote_port));
	if (service_name) {
		plist_dict_set_item(dict, "ForwardedServiceName", plist_new_string(service_name));
	}
	plist_dict_set_item(dict, "IsServiceLowPriority", plist_new_bool(0));
	plist_dict_set_item(dict, "PreferWifi", plist_new_bool(0));
	if (options) {
		plist_dict_merge(&dict, options);
	}

	companion_proxy_error_t res = companion_proxy_send(client, dict);
	plist_free(dict);
	dict = NULL;
	if (res != COMPANION_PROXY_E_SUCCESS) {
		return res;
	}

	res = companion_proxy_receive(client, &dict);
	if (res != COMPANION_PROXY_E_SUCCESS) {
		return res;
	}
	plist_t val = plist_dict_get_item(dict, "CompanionProxyServicePort");
	if (val) {
		uint64_t u64val = 0;
		plist_get_uint_val(val, &u64val);
		*forward_port = (uint16_t)u64val;
		res = COMPANION_PROXY_E_SUCCESS;
	} else {
		res = COMPANION_PROXY_E_UNKNOWN_ERROR;
	}
	plist_free(dict);

	return res;
}

companion_proxy_error_t companion_proxy_stop_forwarding_service_port(companion_proxy_client_t client, uint16_t remote_port)
{
	if (!client) {
		return COMPANION_PROXY_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("StopForwardingServicePort"));
	plist_dict_set_item(dict, "GizmoRemotePortNumber", plist_new_uint(remote_port));

	companion_proxy_error_t res = companion_proxy_send(client, dict);
	plist_free(dict);
	dict = NULL;
	if (res != COMPANION_PROXY_E_SUCCESS) {
		return res;
	}

	res = companion_proxy_receive(client, &dict);
	if (res != COMPANION_PROXY_E_SUCCESS) {
		return res;
	}
	plist_free(dict);

	return res;
}
