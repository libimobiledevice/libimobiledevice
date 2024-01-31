/*
 * bt_packet_logger.c
 * com.apple.bluetooth.BTPacketLogger service implementation.
 *
 * Copyright (c) 2021 Geoffrey Kruse, All Rights Reserved.
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

#include "bt_packet_logger.h"
#include "lockdown.h"
#include "common/debug.h"

struct bt_packet_logger_worker_thread {
	bt_packet_logger_client_t client;
	bt_packet_logger_receive_cb_t cbfunc;
	void *user_data;
	uint8_t rxbuff[BT_MAX_PACKET_SIZE];
};

#define SZ_READ_TIMEOUT 100
#define PAYLOAD_READ_TIMEOUT 500

/**
 * Convert a service_error_t value to a bt_packet_logger_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An service_error_t error code
 *
 * @return A matching bt_packet_logger_error_t error code,
 *     BT_PACKET_LOGGER_E_UNKNOWN_ERROR otherwise.
 */
static bt_packet_logger_error_t bt_packet_logger_error(service_error_t err)
{
	switch (err) {
		case SERVICE_E_SUCCESS:
			return BT_PACKET_LOGGER_E_SUCCESS;
		case SERVICE_E_INVALID_ARG:
			return BT_PACKET_LOGGER_E_INVALID_ARG;
		case SERVICE_E_MUX_ERROR:
			return BT_PACKET_LOGGER_E_MUX_ERROR;
		case SERVICE_E_SSL_ERROR:
			return BT_PACKET_LOGGER_E_SSL_ERROR;
		case SERVICE_E_NOT_ENOUGH_DATA:
			return BT_PACKET_LOGGER_E_NOT_ENOUGH_DATA;
		case SERVICE_E_TIMEOUT:
			return BT_PACKET_LOGGER_E_TIMEOUT;
		default:
			break;
	}
	return BT_PACKET_LOGGER_E_UNKNOWN_ERROR;
}

bt_packet_logger_error_t bt_packet_logger_client_new(idevice_t device, lockdownd_service_descriptor_t service, bt_packet_logger_client_t * client)
{
	if (!device || !service || service->port == 0 || !client || *client) {
		debug_info("Incorrect parameter passed to bt_packet_logger_client_new.");
		return BT_PACKET_LOGGER_E_INVALID_ARG;
	}

	debug_info("Creating bt_packet_logger_client, port = %d.", service->port);

	service_client_t parent = NULL;
	bt_packet_logger_error_t ret = bt_packet_logger_error(service_client_new(device, service, &parent));
	if (ret != BT_PACKET_LOGGER_E_SUCCESS) {
		debug_info("Creating base service client failed. Error: %i", ret);
		return ret;
	}

	bt_packet_logger_client_t client_loc = (bt_packet_logger_client_t) malloc(sizeof(struct bt_packet_logger_client_private));
	client_loc->parent = parent;
	client_loc->worker = THREAD_T_NULL;

	*client = client_loc;

	debug_info("bt_packet_logger_client successfully created.");
	return 0;
}

bt_packet_logger_error_t bt_packet_logger_client_start_service(idevice_t device, bt_packet_logger_client_t * client, const char* label)
{
	bt_packet_logger_error_t err = BT_PACKET_LOGGER_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, BT_PACKETLOGGER_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(bt_packet_logger_client_new), &err);
	return err;
}

bt_packet_logger_error_t bt_packet_logger_client_free(bt_packet_logger_client_t client)
{
	if (!client)
		return BT_PACKET_LOGGER_E_INVALID_ARG;
	bt_packet_logger_stop_capture(client);
	bt_packet_logger_error_t err = bt_packet_logger_error(service_client_free(client->parent));
	free(client);

	return err;
}

bt_packet_logger_error_t bt_packet_logger_receive_with_timeout(bt_packet_logger_client_t client, char* data, uint32_t size, uint32_t *received, unsigned int timeout)
{
	bt_packet_logger_error_t res = BT_PACKET_LOGGER_E_UNKNOWN_ERROR;
	int bytes = 0;

	if (!client || !data || (size == 0)) {
		return BT_PACKET_LOGGER_E_INVALID_ARG;
	}

	res = bt_packet_logger_error(service_receive_with_timeout(client->parent, data, size, (uint32_t*)&bytes, timeout));
	if (res != BT_PACKET_LOGGER_E_SUCCESS && res != BT_PACKET_LOGGER_E_TIMEOUT && res != BT_PACKET_LOGGER_E_NOT_ENOUGH_DATA) {
		debug_info("Could not read data, error %d", res);
	}
	if (received) {
		*received = (uint32_t)bytes;
	}

	return res;
}

void *bt_packet_logger_worker(void *arg)
{
	bt_packet_logger_error_t ret = BT_PACKET_LOGGER_E_UNKNOWN_ERROR;
	struct bt_packet_logger_worker_thread *btwt = (struct bt_packet_logger_worker_thread*)arg;

	if (!btwt) {
		return NULL;
	}

	debug_info("Running");

	while (btwt->client->parent) {
		uint32_t bytes = 0;
		uint16_t len;

		ret = bt_packet_logger_receive_with_timeout(btwt->client, (char*)&len, 2, &bytes, SZ_READ_TIMEOUT);

		if (ret == BT_PACKET_LOGGER_E_TIMEOUT || ret == BT_PACKET_LOGGER_E_NOT_ENOUGH_DATA || ((bytes == 0) && (ret == BT_PACKET_LOGGER_E_SUCCESS))) {
			continue;
		} else if (ret < 0) {
			debug_info("Connection to bt packet logger interrupted");
			break;
		}

		// sanity check received length
		if(bytes > 0 && len > sizeof(bt_packet_logger_header_t)) {
			debug_info("Reading %u bytes\n", len);
			ret = bt_packet_logger_receive_with_timeout(btwt->client, (char *)btwt->rxbuff, len, &bytes, PAYLOAD_READ_TIMEOUT);

			if(len != bytes) {
				debug_info("Failed Read Expected %u, Received %u\n", len, bytes);
				continue;
			}

			if (ret == BT_PACKET_LOGGER_E_TIMEOUT || ret == BT_PACKET_LOGGER_E_NOT_ENOUGH_DATA || ((bytes == 0) && (ret == BT_PACKET_LOGGER_E_SUCCESS))) {
				continue;
			} else if (ret < 0) {
				debug_info("Connection to bt packet logger interrupted");
				break;
			}

			btwt->cbfunc(btwt->rxbuff, len, btwt->user_data);
		}
	}

	// null check performed above
	free(btwt);

	debug_info("Exiting");

	return NULL;
}

bt_packet_logger_error_t bt_packet_logger_start_capture(bt_packet_logger_client_t client, bt_packet_logger_receive_cb_t callback, void* user_data)
{
	if (!client || !callback)
		return BT_PACKET_LOGGER_E_INVALID_ARG;

	bt_packet_logger_error_t res = BT_PACKET_LOGGER_E_UNKNOWN_ERROR;

	if (client->worker) {
		debug_info("Another syslog capture thread appears to be running already.");
		return res;
	}

	/* start worker thread */
	struct bt_packet_logger_worker_thread *btwt = (struct bt_packet_logger_worker_thread*)malloc(sizeof(struct bt_packet_logger_worker_thread));
	if (btwt) {
		btwt->client = client;
		btwt->cbfunc = callback;
		btwt->user_data = user_data;

		if (thread_new(&client->worker, bt_packet_logger_worker, btwt) == 0) {
			res = BT_PACKET_LOGGER_E_SUCCESS;
		}
	}

	return res;
}


bt_packet_logger_error_t bt_packet_logger_stop_capture(bt_packet_logger_client_t client)
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

	return BT_PACKET_LOGGER_E_SUCCESS;
}
