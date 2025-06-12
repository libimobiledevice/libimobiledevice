/*
 * ostrace.c
 * com.apple.os_trace_relay service implementation.
 *
 * Copyright (c) 2020-2025 Nikias Bassen, All Rights Reserved.
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

#include "ostrace.h"
#include "lockdown.h"
#include "common/debug.h"
#include "endianness.h"

struct ostrace_worker_thread {
	ostrace_client_t client;
	ostrace_activity_cb_t cbfunc;
	void *user_data;
};

/**
 * Convert a service_error_t value to a ostrace_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An service_error_t error code
 *
 * @return A matching ostrace_error_t error code,
 *     OSTRACE_E_UNKNOWN_ERROR otherwise.
 */
static ostrace_error_t ostrace_error(service_error_t err)
{
	switch (err) {
		case SERVICE_E_SUCCESS:
			return OSTRACE_E_SUCCESS;
		case SERVICE_E_INVALID_ARG:
			return OSTRACE_E_INVALID_ARG;
		case SERVICE_E_MUX_ERROR:
			return OSTRACE_E_MUX_ERROR;
		case SERVICE_E_SSL_ERROR:
			return OSTRACE_E_SSL_ERROR;
		case SERVICE_E_NOT_ENOUGH_DATA:
			return OSTRACE_E_NOT_ENOUGH_DATA;
		case SERVICE_E_TIMEOUT:
			return OSTRACE_E_TIMEOUT;
		default:
			break;
	}
	return OSTRACE_E_UNKNOWN_ERROR;
}

ostrace_error_t ostrace_client_new(idevice_t device, lockdownd_service_descriptor_t service, ostrace_client_t * client)
{
	*client = NULL;

	if (!device || !service || service->port == 0 || !client || *client) {
		debug_info("Incorrect parameter passed to ostrace_client_new.");
		return OSTRACE_E_INVALID_ARG;
	}

	debug_info("Creating ostrace_client, port = %d.", service->port);

	service_client_t parent = NULL;
	ostrace_error_t ret = ostrace_error(service_client_new(device, service, &parent));
	if (ret != OSTRACE_E_SUCCESS) {
		debug_info("Creating base service client failed. Error: %i", ret);
		return ret;
	}

	ostrace_client_t client_loc = (ostrace_client_t) malloc(sizeof(struct ostrace_client_private));
	client_loc->parent = parent;
	client_loc->worker = THREAD_T_NULL;

	*client = client_loc;

	debug_info("ostrace_client successfully created.");
	return 0;
}

ostrace_error_t ostrace_client_start_service(idevice_t device, ostrace_client_t * client, const char* label)
{
	ostrace_error_t err = OSTRACE_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, OSTRACE_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(ostrace_client_new), &err);
	return err;
}

ostrace_error_t ostrace_client_free(ostrace_client_t client)
{
	if (!client)
		return OSTRACE_E_INVALID_ARG;
	ostrace_stop_activity(client);
	ostrace_error_t err = ostrace_error(service_client_free(client->parent));
	free(client);

	return err;
}

static ostrace_error_t ostrace_send_plist(ostrace_client_t client, plist_t plist)
{
	ostrace_error_t res = OSTRACE_E_UNKNOWN_ERROR;
	uint32_t blen = 0;
	char* bin = NULL;
	uint32_t sent = 0;
	uint32_t swapped_len = 0;

	if (!client || !plist) {
		return OSTRACE_E_INVALID_ARG;
	}

	plist_to_bin(plist, &bin, &blen);
	swapped_len = htobe32(blen);

	res = ostrace_error(service_send(client->parent, (char*)&swapped_len, 4, &sent));
	if (res == OSTRACE_E_SUCCESS) {
		res = ostrace_error(service_send(client->parent, bin, blen, &sent));
	}
	free(bin);
	return res;
}

static ostrace_error_t ostrace_receive_plist(ostrace_client_t client, plist_t *plist)
{
	ostrace_error_t res = OSTRACE_E_UNKNOWN_ERROR;
	uint8_t msgtype = 0;
	uint32_t received = 0;
	res = ostrace_error(service_receive(client->parent, (char*)&msgtype, 1, &received));
	if (res != OSTRACE_E_SUCCESS) {
		debug_info("Failed to read message type from service");
		return res;
	}
	uint32_t rlen = 0;
	res = ostrace_error(service_receive(client->parent, (char*)&rlen, 4, &received));
	if (res != OSTRACE_E_SUCCESS) {
		debug_info("Failed to read message size from service");
		return res;
	}

	if (msgtype == 1) {
		rlen = be32toh(rlen);
	} else if (msgtype == 2) {
		rlen = le32toh(rlen);
	} else {
		debug_info("Unexpected message type %d", msgtype);
		return OSTRACE_E_UNKNOWN_ERROR;
	}
	debug_info("got length %d", rlen);

	char* buf = (char*)malloc(rlen);
	res = ostrace_error(service_receive(client->parent, buf, rlen, &received));
	if (res != OSTRACE_E_SUCCESS) {
		return res;
	}

	plist_t reply = NULL;
	plist_err_t perr = plist_from_memory(buf, received, &reply, NULL);
	free(buf);
	if (perr != PLIST_ERR_SUCCESS) {
		return OSTRACE_E_UNKNOWN_ERROR;
	}
	*plist = reply;
	return OSTRACE_E_SUCCESS;	
}

static ostrace_error_t _ostrace_check_result(plist_t reply)
{
	ostrace_error_t res = OSTRACE_E_REQUEST_FAILED;
	if (!reply) {
		return res;
	}
	plist_t p_status = plist_dict_get_item(reply, "Status");
	if (!p_status) {
		return res;
	}
	const char* status = plist_get_string_ptr(p_status, NULL);
	if (!status) {
		return res;
	}
	if (!strcmp(status, "RequestSuccessful")) {
		res = OSTRACE_E_SUCCESS;
	}
	return res;
}

void *ostrace_worker(void *arg)
{
	ostrace_error_t res = OSTRACE_E_UNKNOWN_ERROR;
	struct ostrace_worker_thread *oswt = (struct ostrace_worker_thread*)arg;

	if (!oswt)
		return NULL;

	uint8_t msgtype = 0;
	uint32_t received = 0;

	debug_info("Running");

	while (oswt->client->parent) {
		res = ostrace_error(service_receive(oswt->client->parent, (char*)&msgtype, 1, &received));
		if (res == OSTRACE_E_TIMEOUT) {
			debug_info("Nothing received, retrying\n");
			continue;
		}
		if (res != OSTRACE_E_SUCCESS) {
			debug_info("Failed to read message type from service");
			break;
		}
		uint32_t rlen = 0;
		res = ostrace_error(service_receive(oswt->client->parent, (char*)&rlen, 4, &received));
		if (res != OSTRACE_E_SUCCESS) {
			debug_info("Failed to read message size from service");
			break;
		}

		if (msgtype == 1) {
			rlen = be32toh(rlen);
		} else if (msgtype == 2) {
			rlen = le32toh(rlen);
		} else {
			debug_info("Unexpected message type %d", msgtype);
			break;
		}

		debug_info("got length %d", rlen);

		void* buf = malloc(rlen);
		res = ostrace_error(service_receive(oswt->client->parent, (char*)buf, rlen, &received));
		if (res != OSTRACE_E_SUCCESS) {
			debug_info("Failed to receive %d bytes, error %d", rlen, res);
			break;
		}
		if (received < rlen) {
			debug_info("Failed to receive all data, got %d/%d", received, rlen);
			break;
		}
		oswt->cbfunc(buf, received, oswt->user_data);
	}

	if (oswt) {
		free(oswt);
	}

	debug_info("Exiting");

	return NULL;
}

ostrace_error_t ostrace_start_activity(ostrace_client_t client, plist_t options, ostrace_activity_cb_t callback, void* user_data)
{
	if (!client || !callback)
		return OSTRACE_E_INVALID_ARG;

	ostrace_error_t res = OSTRACE_E_UNKNOWN_ERROR;

	if (client->worker) {
		debug_info("Another ostrace activity thread appears to be running already.");
		return res;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Pid", plist_new_uint(0x0FFFFFFFF));
	plist_dict_set_item(dict, "MessageFilter", plist_new_uint(0xFFFF));
	plist_dict_set_item(dict, "StreamFlags", plist_new_uint(0x3C));
	if (options) {
		plist_dict_merge(&dict, options);
	}
	plist_dict_set_item(dict, "Request", plist_new_string("StartActivity"));

	res = ostrace_send_plist(client, dict);
	plist_free(dict);
	if (res != OSTRACE_E_SUCCESS) {
		return res;
	}
	
	dict = NULL;
	res = ostrace_receive_plist(client, &dict);
	if (res != OSTRACE_E_SUCCESS) {
		return res;
	}
	res = _ostrace_check_result(dict);
	if (res != OSTRACE_E_SUCCESS) {
		return res;
	}

	/* start worker thread */
	struct ostrace_worker_thread *oswt = (struct ostrace_worker_thread*)malloc(sizeof(struct ostrace_worker_thread));
	if (oswt) {
		oswt->client = client;
		oswt->cbfunc = callback;
		oswt->user_data = user_data;

		if (thread_new(&client->worker, ostrace_worker, oswt) == 0) {
			res = OSTRACE_E_SUCCESS;
		}
	}

	return res;
}

ostrace_error_t ostrace_stop_activity(ostrace_client_t client)
{
	if (client->worker) {
		/* notify thread to finish */
		service_client_t parent = client->parent;
		client->parent = NULL;
		/* join thread to make it exit */
		thread_join(client->worker);
		thread_free(client->worker);
		client->worker = THREAD_T_NULL;
		client->parent = parent;
	}

	return OSTRACE_E_SUCCESS;
}

ostrace_error_t ostrace_get_pid_list(ostrace_client_t client, plist_t* list)
{
	ostrace_error_t res = OSTRACE_E_UNKNOWN_ERROR;
	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Request", plist_new_string("PidList"));

	if (!client || !list) {
		return OSTRACE_E_INVALID_ARG;
	}

	res = ostrace_send_plist(client, dict);
	plist_free(dict);
	if (res != OSTRACE_E_SUCCESS) {
		return res;
	}

	plist_t reply = NULL;
	res = ostrace_receive_plist(client, &reply);
	if (res != OSTRACE_E_SUCCESS) {
		return res;
	}
	res = _ostrace_check_result(reply);
	if (res != OSTRACE_E_SUCCESS) {
		return res;
	}

	plist_t payload = plist_dict_get_item(reply, "Payload");
	if (!payload) {
		return OSTRACE_E_REQUEST_FAILED;
	}
	*list = plist_copy(payload);
	plist_free(reply);

	return OSTRACE_E_SUCCESS;
}

ostrace_error_t ostrace_create_archive(ostrace_client_t client, plist_t options, ostrace_archive_write_cb_t callback, void* user_data)
{
	ostrace_error_t res = OSTRACE_E_UNKNOWN_ERROR;
	if (!client || !callback) {
		return OSTRACE_E_INVALID_ARG;
	}
	plist_t dict = plist_new_dict();
	if (options) {
		plist_dict_merge(&dict, options);
	}
	plist_dict_set_item(dict, "Request", plist_new_string("CreateArchive"));

	res = ostrace_send_plist(client, dict);
	plist_free(dict);
	if (res != OSTRACE_E_SUCCESS) {
		return res;
	}

	plist_t reply = NULL;
	res = ostrace_receive_plist(client, &reply);
	if (res != OSTRACE_E_SUCCESS) {
		return res;
	}

	res = _ostrace_check_result(reply);
	if (res != OSTRACE_E_SUCCESS) {
		return res;
	}

	debug_info("Receiving archive...\n");
	while (1) {
		uint8_t msgtype = 0;
		uint32_t received = 0;
		res = ostrace_error(service_receive(client->parent, (char*)&msgtype, 1, &received));
		if (res != OSTRACE_E_SUCCESS) {
			debug_info("Could not read message type from service: %d", res);
			break;
		}
		if (msgtype != 3) {
			debug_info("Unexpected packet type %d", msgtype);
			return OSTRACE_E_REQUEST_FAILED;
		}
		uint32_t rlen = 0;
		res = ostrace_error(service_receive(client->parent, (char*)&rlen, 4, &received));
		if (res != OSTRACE_E_SUCCESS) {
			debug_info("Failed to read message size from service");
			break;
		}

		rlen = le32toh(rlen);
		debug_info("got length %d", rlen);

		unsigned char* buf = (unsigned char*)malloc(rlen);
		res = ostrace_error(service_receive(client->parent, (char*)buf, rlen, &received));
		if (res != OSTRACE_E_SUCCESS) {
			debug_info("Could not read data from service: %d", res);
			break;
		}
		if (callback(buf, received, user_data) < 0) {
			debug_info("Aborted through callback");
			return OSTRACE_E_REQUEST_FAILED;
		}
	}
	debug_info("Done.\n");

	return OSTRACE_E_SUCCESS;
}

