/*
 * compproxy.c
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
#include "common/thread.h"

/**
 * Convert a property_list_service_error_t value to a compproxy_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An property_list_service_error_t error code
 *
 * @return A matching compproxy_error_t error code,
 *     COMPPROXY_E_UNKNOWN_ERROR otherwise.
 */
static compproxy_error_t compproxy_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return COMPPROXY_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return COMPPROXY_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return COMPPROXY_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return COMPPROXY_E_MUX_ERROR;
		case PROPERTY_LIST_SERVICE_E_SSL_ERROR:
			return COMPPROXY_E_SSL_ERROR;
		case PROPERTY_LIST_SERVICE_E_NOT_ENOUGH_DATA:
			return COMPPROXY_E_NOT_ENOUGH_DATA;
		case PROPERTY_LIST_SERVICE_E_RECEIVE_TIMEOUT:
			return COMPPROXY_E_TIMEOUT;
		default:
			break;
	}
	return COMPPROXY_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_client_new(idevice_t device, lockdownd_service_descriptor_t service, compproxy_client_t * client)
{
	*client = NULL;

	if (!device || !service || service->port == 0 || !client || *client) {
		debug_info("Incorrect parameter passed to compproxy_client_new.");
		return COMPPROXY_E_INVALID_ARG;
	}

	debug_info("Creating compproxy_client, port = %d.", service->port);

	property_list_service_client_t plclient = NULL;
	compproxy_error_t ret = compproxy_error(property_list_service_client_new(device, service, &plclient));
	if (ret != COMPPROXY_E_SUCCESS) {
		debug_info("Creating a property list client failed. Error: %i", ret);
		return ret;
	}

	compproxy_client_t client_loc = (compproxy_client_t) malloc(sizeof(struct compproxy_client_private));
	client_loc->parent = plclient;
	client_loc->event_thread = THREAD_T_NULL;

	*client = client_loc;

	debug_info("compproxy_client successfully created.");
	return COMPPROXY_E_SUCCESS;
}

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_client_start_service(idevice_t device, compproxy_client_t * client, const char* label)
{
	compproxy_error_t err = COMPPROXY_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, COMPPROXY_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(compproxy_client_new), &err);
	return err;
}

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_client_free(compproxy_client_t client)
{
	if (!client)
		return COMPPROXY_E_INVALID_ARG;

	property_list_service_client_t parent = client->parent;
	client->parent = NULL;
	if (client->event_thread) {
		debug_info("joining event thread");
		thread_join(client->event_thread);
		thread_free(client->event_thread);
		client->event_thread = THREAD_T_NULL;
	}
	compproxy_error_t err = compproxy_error(property_list_service_client_free(parent));
	free(client);

	return err;
}

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_send(compproxy_client_t client, plist_t plist)
{
	compproxy_error_t res = COMPPROXY_E_UNKNOWN_ERROR;

	res = compproxy_error(property_list_service_send_binary_plist(client->parent, plist));
	if (res != COMPPROXY_E_SUCCESS) {
		debug_info("Sending plist failed with error %d", res);
		return res;
	}

	return res;
}

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_receive(compproxy_client_t client, plist_t * plist)
{
	compproxy_error_t res = COMPPROXY_E_UNKNOWN_ERROR;
	plist_t outplist = NULL;
	res = compproxy_error(property_list_service_receive_plist_with_timeout(client->parent, &outplist, 10000));
	if (res != COMPPROXY_E_SUCCESS && res != COMPPROXY_E_TIMEOUT) {
		debug_info("Could not receive plist, error %d", res);
		plist_free(outplist);
	} else if (res == COMPPROXY_E_SUCCESS) {
		*plist = outplist;
	}
	return res;
}

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_get_device_registry(compproxy_client_t client, plist_t* paired_devices)
{
	if (!client || !paired_devices) {
		return COMPPROXY_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("GetDeviceRegistry"));

	compproxy_error_t res = compproxy_send(client, dict);
	plist_free(dict);
	dict = NULL;
	if (res != COMPPROXY_E_SUCCESS) {
		return res;
	}

	res = compproxy_receive(client, &dict);
	if (res != COMPPROXY_E_SUCCESS) {
		return res;
	}
	if (!dict || !PLIST_IS_DICT(dict)) {
		return COMPPROXY_E_PLIST_ERROR;
	}
	plist_t val = plist_dict_get_item(dict, "PairedDevicesArray");
	if (val) {
		*paired_devices = plist_copy(val);
		res = COMPPROXY_E_SUCCESS;
	} else {
		res = COMPPROXY_E_UNKNOWN_ERROR;
		val = plist_dict_get_item(dict, "Error");
		if (val) {
			if (plist_string_val_compare(val, "NoPairedWatches")) {
				res = COMPPROXY_E_NO_DEVICES;
			}
		}
	}
	plist_free(dict);
	return res;
}

struct compproxy_cb_data {
	compproxy_client_t client;
	compproxy_device_event_cb_t cbfunc;
	void* user_data;
};

static void* compproxy_event_thread(void* arg)
{
	struct compproxy_cb_data* data = (struct compproxy_cb_data*)arg;
	compproxy_client_t client = data->client;
	compproxy_error_t res;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("StartListeningForDevices"));
	res = compproxy_send(client, command);
	plist_free(command);

	if (res != COMPPROXY_E_SUCCESS) {
		free(data);
		client->event_thread = THREAD_T_NULL;
		return NULL;
	}

	while (client && client->parent) {
		plist_t node = NULL;
		res = compproxy_error(property_list_service_receive_plist_with_timeout(client->parent, &node, 1000));
		if (res != COMPPROXY_E_SUCCESS && res != COMPPROXY_E_TIMEOUT) {
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

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_start_listening_for_devices(compproxy_client_t client, compproxy_device_event_cb_t callback, void* userdata)
{
	if (!client || !client->parent || !callback) {
		return COMPPROXY_E_INVALID_ARG;
	}

	if (client->event_thread) {
		return COMPPROXY_E_OP_IN_PROGRESS;
	}

	compproxy_error_t res = COMPPROXY_E_UNKNOWN_ERROR;
	struct compproxy_cb_data *data = (struct compproxy_cb_data*)malloc(sizeof(struct compproxy_cb_data));
	if (data) {
		data->client = client;
		data->cbfunc = callback;
		data->user_data = userdata;

		if (thread_new(&client->event_thread, compproxy_event_thread, data) == 0) {
			res = COMPPROXY_E_SUCCESS;
		} else {
			free(data);
		}
	}
	return res;
}

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_stop_listening_for_devices(compproxy_client_t client)
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
	return COMPPROXY_E_SUCCESS;
}

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_get_value_from_registry(compproxy_client_t client, const char* companion_udid, const char* key, plist_t* value)
{
	if (!client || !companion_udid || !key || !value) {
		return COMPPROXY_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("GetValueFromRegistry"));
	plist_dict_set_item(dict, "GetValueGizmoUDIDKey", plist_new_string(companion_udid));
	plist_dict_set_item(dict, "GetValueKeyKey", plist_new_string(key));

	compproxy_error_t res = compproxy_send(client, dict);
	plist_free(dict);
	dict = NULL;
	if (res != COMPPROXY_E_SUCCESS) {
		return res;
	}

	res = compproxy_receive(client, &dict);
	if (res != COMPPROXY_E_SUCCESS) {
		return res;
	}
	if (!dict || !PLIST_IS_DICT(dict)) {
		return COMPPROXY_E_PLIST_ERROR;
	}
	plist_t val = plist_dict_get_item(dict, "RetrievedValueDictionary");
	if (val) {
		*value = plist_copy(val);
		res = COMPPROXY_E_SUCCESS;
	} else {
		res = COMPPROXY_E_UNKNOWN_ERROR;
		val = plist_dict_get_item(dict, "Error");
		if (val) {
			if (!plist_string_val_compare(val, "UnsupportedWatchKey")) {
				res = COMPPROXY_E_UNSUPPORTED_KEY;
			} else if (plist_string_val_compare(val, "TimeoutReply")) {
				res = COMPPROXY_E_TIMEOUT_REPLY;
			}
		}
	}
	plist_free(dict);
	return res;
}

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_start_forwarding_service_port(compproxy_client_t client, uint16_t remote_port, const char* service_name, uint16_t* forward_port, plist_t options)
{
	if (!client) {
		return COMPPROXY_E_INVALID_ARG;
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
		plist_dict_merge(dict, options);
	}

	compproxy_error_t res = compproxy_send(client, dict);
	plist_free(dict);
	dict = NULL;
	if (res != COMPPROXY_E_SUCCESS) {
		return res;
	}

	res = compproxy_receive(client, &dict);
	if (res != COMPPROXY_E_SUCCESS) {
		return res;
	}
	plist_t val = plist_dict_get_item(dict, "CompanionProxyServicePort");
	if (val) {
		uint64_t u64val = 0;
		plist_get_uint_val(val, &u64val);
		*forward_port = (uint16_t)u64val;
		res = COMPPROXY_E_SUCCESS;
	} else {
		res = COMPPROXY_E_UNKNOWN_ERROR;
	}
	plist_free(dict);

	return res;
}

LIBIMOBILEDEVICE_API compproxy_error_t compproxy_stop_forwarding_service_port(compproxy_client_t client, uint16_t remote_port)
{
	if (!client) {
		return COMPPROXY_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("StopForwardingServicePort"));
	plist_dict_set_item(dict, "GizmoRemotePortNumber", plist_new_uint(remote_port));

	compproxy_error_t res = compproxy_send(client, dict);
	plist_free(dict);
	dict = NULL;
	if (res != COMPPROXY_E_SUCCESS) {
		return res;
	}

	res = compproxy_receive(client, &dict);
	if (res != COMPPROXY_E_SUCCESS) {
		return res;
	}
	plist_free(dict);

	return res;
}
