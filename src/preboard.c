/*
 * preboard.c
 * com.apple.preboardservice_v2 service implementation.
 *
 * Copyright (c) 2019 Nikias Bassen, All Rights Reserved.
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

#include "preboard.h"
#include "lockdown.h"
#include "common/debug.h"

/**
 * Convert a property_list_service_error_t value to a preboard_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An property_list_service_error_t error code
 *
 * @return A matching preboard_error_t error code,
 *     PREBOARD_E_UNKNOWN_ERROR otherwise.
 */
static preboard_error_t preboard_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return PREBOARD_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return PREBOARD_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return PREBOARD_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return PREBOARD_E_MUX_ERROR;
		case PROPERTY_LIST_SERVICE_E_SSL_ERROR:
			return PREBOARD_E_SSL_ERROR;
		case PROPERTY_LIST_SERVICE_E_NOT_ENOUGH_DATA:
			return PREBOARD_E_NOT_ENOUGH_DATA;
		case PROPERTY_LIST_SERVICE_E_RECEIVE_TIMEOUT:
			return PREBOARD_E_TIMEOUT;
		default:
			break;
	}
	return PREBOARD_E_UNKNOWN_ERROR;
}

preboard_error_t preboard_client_new(idevice_t device, lockdownd_service_descriptor_t service, preboard_client_t * client)
{
	*client = NULL;

	if (!device || !service || service->port == 0 || !client || *client) {
		debug_info("Incorrect parameter passed to preboard_client_new.");
		return PREBOARD_E_INVALID_ARG;
	}

	debug_info("Creating preboard_client, port = %d.", service->port);

	property_list_service_client_t plclient = NULL;
	preboard_error_t ret = preboard_error(property_list_service_client_new(device, service, &plclient));
	if (ret != PREBOARD_E_SUCCESS) {
		debug_info("Creating a property list client failed. Error: %i", ret);
		return ret;
	}

	preboard_client_t client_loc = (preboard_client_t) malloc(sizeof(struct preboard_client_private));
	client_loc->parent = plclient;
	client_loc->receive_status_thread = THREAD_T_NULL;

	*client = client_loc;

	debug_info("preboard_client successfully created.");
	return 0;
}

preboard_error_t preboard_client_start_service(idevice_t device, preboard_client_t * client, const char* label)
{
	preboard_error_t err = PREBOARD_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, PREBOARD_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(preboard_client_new), &err);
	return err;
}

preboard_error_t preboard_client_free(preboard_client_t client)
{
	if (!client)
		return PREBOARD_E_INVALID_ARG;

	property_list_service_client_t parent = client->parent;
	client->parent = NULL;
	if (client->receive_status_thread) {
		debug_info("joining receive_status_thread");
		thread_join(client->receive_status_thread);
		thread_free(client->receive_status_thread);
		client->receive_status_thread = THREAD_T_NULL;
	}
	preboard_error_t err = preboard_error(property_list_service_client_free(parent));
	free(client);

	return err;
}

preboard_error_t preboard_send(preboard_client_t client, plist_t plist)
{
	preboard_error_t res = PREBOARD_E_UNKNOWN_ERROR;
	res = preboard_error(property_list_service_send_binary_plist(client->parent, plist));
	if (res != PREBOARD_E_SUCCESS) {
		debug_info("Sending plist failed with error %d", res);
		return res;
	}
	return res;
}

preboard_error_t preboard_receive_with_timeout(preboard_client_t client, plist_t * plist, uint32_t timeout_ms)
{
	preboard_error_t res = PREBOARD_E_UNKNOWN_ERROR;
	plist_t outplist = NULL;
	res = preboard_error(property_list_service_receive_plist_with_timeout(client->parent, &outplist, timeout_ms));
	if (res != PREBOARD_E_SUCCESS && res != PREBOARD_E_TIMEOUT) {
		debug_info("Could not receive plist, error %d", res);
		plist_free(outplist);
	} else if (res == PREBOARD_E_SUCCESS) {
		*plist = outplist;
	}
	return res;
}

preboard_error_t preboard_receive(preboard_client_t client, plist_t * plist)
{
	return preboard_receive_with_timeout(client, plist, 5000);
}

struct preboard_status_data {
	preboard_client_t client;
	preboard_status_cb_t cbfunc;
	void *user_data;
};

static void* preboard_receive_status_loop_thread(void* arg)
{
	struct preboard_status_data *data = (struct preboard_status_data*)arg;

	/* run until the service disconnects or an error occurs */
	while (data->client && data->client->parent) {
		plist_t pl = NULL;
		preboard_error_t perr = preboard_receive_with_timeout(data->client, &pl, 1000);
		if (perr == PREBOARD_E_TIMEOUT) {
			continue;
		}
		if (perr == PREBOARD_E_SUCCESS) {
			data->cbfunc(pl, data->user_data);
		}
		plist_free(pl);
		if (perr != PREBOARD_E_SUCCESS) {
			data->cbfunc(NULL, data->user_data);
			break;
		}
	}

	/* cleanup */
	debug_info("done, cleaning up.");

	if (data->client->receive_status_thread) {
		thread_free(data->client->receive_status_thread);
		data->client->receive_status_thread = THREAD_T_NULL;
	}
	free(data);

	return NULL;
}

static preboard_error_t preboard_receive_status_loop_with_callback(preboard_client_t client, preboard_status_cb_t status_cb, void *user_data)
{
	if (!client || !client->parent) {
		return PREBOARD_E_INVALID_ARG;
	}

	if (client->receive_status_thread) {
		return PREBOARD_E_OP_IN_PROGRESS;
	}

	preboard_error_t res = PREBOARD_E_UNKNOWN_ERROR;
	struct preboard_status_data *data = (struct preboard_status_data*)malloc(sizeof(struct preboard_status_data));
	if (data) {
		data->client = client;
		data->cbfunc = status_cb;
		data->user_data = user_data;
		if (thread_new(&client->receive_status_thread, preboard_receive_status_loop_thread, data) == 0) {
			res = PREBOARD_E_SUCCESS;
		}
	}

	return res;
}

preboard_error_t preboard_create_stashbag(preboard_client_t client, plist_t manifest, preboard_status_cb_t status_cb, void *user_data)
{
	if (!client) {
		return PREBOARD_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("CreateStashbag"));
	if (manifest) {
		plist_dict_set_item(dict, "Manifest", plist_copy(manifest));
	}
	preboard_error_t perr = preboard_send(client, dict);
	plist_free(dict);
	if (perr != PREBOARD_E_SUCCESS) {
		return perr;
	}
	if (!status_cb) {
		return PREBOARD_E_SUCCESS;
	}

	return preboard_receive_status_loop_with_callback(client, status_cb, user_data);
}

preboard_error_t preboard_commit_stashbag(preboard_client_t client, plist_t manifest, preboard_status_cb_t status_cb, void *user_data)
{
	if (!client) {
		return PREBOARD_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("CommitStashbag"));
	if (manifest) {
		plist_dict_set_item(dict, "Manifest", plist_copy(manifest));
	}
	preboard_error_t perr = preboard_send(client, dict);
	plist_free(dict);
	if (perr != PREBOARD_E_SUCCESS) {
		return perr;
	}
	if (!status_cb) {
		return PREBOARD_E_SUCCESS;
	}

	return preboard_receive_status_loop_with_callback(client, status_cb, user_data);
}
