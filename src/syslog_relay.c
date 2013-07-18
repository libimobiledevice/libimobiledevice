/*
 * syslog_relay.c 
 * com.apple.syslog_relay service implementation.
 * 
 * Copyright (c) 2013 Martin Szulecki All Rights Reserved.
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

#include "syslog_relay.h"
#include "lockdown.h"
#include "common/debug.h"

struct syslog_relay_worker_thread {
	syslog_relay_client_t client;
	syslog_relay_receive_cb_t cbfunc;
	void *user_data;
};

/**
 * Convert a service_error_t value to a syslog_relay_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An service_error_t error code
 *
 * @return A matching syslog_relay_error_t error code,
 *     SYSLOG_RELAY_E_UNKNOWN_ERROR otherwise.
 */
static syslog_relay_error_t syslog_relay_error(service_error_t err)
{
	switch (err) {
		case SERVICE_E_SUCCESS:
			return SYSLOG_RELAY_E_SUCCESS;
		case SERVICE_E_INVALID_ARG:
			return SYSLOG_RELAY_E_INVALID_ARG;
		case SERVICE_E_MUX_ERROR:
			return SYSLOG_RELAY_E_MUX_ERROR;
		case SERVICE_E_SSL_ERROR:
			return SYSLOG_RELAY_E_SSL_ERROR;
		default:
			break;
	}
	return SYSLOG_RELAY_E_UNKNOWN_ERROR;
}

/**
 * Connects to the syslog_relay service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     syslog_relay_client_t upon successful return. Must be freed using
 *     syslog_relay_client_free() after use.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success, SYSLOG_RELAY_E_INVALID_ARG when
 *     client is NULL, or an SYSLOG_RELAY_E_* error code otherwise.
 */
syslog_relay_error_t syslog_relay_client_new(idevice_t device, lockdownd_service_descriptor_t service, syslog_relay_client_t * client)
{
	*client = NULL;

	if (!device || !service || service->port == 0 || !client || *client) {
		debug_info("Incorrect parameter passed to syslog_relay_client_new.");
		return SYSLOG_RELAY_E_INVALID_ARG;
	}

	debug_info("Creating syslog_relay_client, port = %d.", service->port);

	service_client_t parent = NULL;
	syslog_relay_error_t ret = syslog_relay_error(service_client_new(device, service, &parent));
	if (ret != SYSLOG_RELAY_E_SUCCESS) {
		debug_info("Creating base service client failed. Error: %i", ret);
		return ret;
	}

	syslog_relay_client_t client_loc = (syslog_relay_client_t) malloc(sizeof(struct syslog_relay_client_private));
	client_loc->parent = parent;
	client_loc->worker = (thread_t)NULL;

	*client = client_loc;

	debug_info("syslog_relay_client successfully created.");
	return 0;
}

/**
 * Starts a new syslog_relay service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     syslog_relay_client_t upon successful return. Must be freed using
 *     syslog_relay_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success, or an SYSLOG_RELAY_E_* error
 *     code otherwise.
 */
syslog_relay_error_t syslog_relay_client_start_service(idevice_t device, syslog_relay_client_t * client, const char* label)
{
	syslog_relay_error_t err = SYSLOG_RELAY_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, SYSLOG_RELAY_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(syslog_relay_client_new), &err);
	return err;
}

/**
 * Disconnects a syslog_relay client from the device and frees up the
 * syslog_relay client data.
 *
 * @param client The syslog_relay client to disconnect and free.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success, SYSLOG_RELAY_E_INVALID_ARG when
 *     client is NULL, or an SYSLOG_RELAY_E_* error code otherwise.
 */
syslog_relay_error_t syslog_relay_client_free(syslog_relay_client_t client)
{
	if (!client)
		return SYSLOG_RELAY_E_INVALID_ARG;

	syslog_relay_error_t err = syslog_relay_error(service_client_free(client->parent));
	client->parent = NULL;
	if (client->worker) {
		debug_info("Joining syslog capture callback worker thread");
		thread_join(client->worker);
	}
	free(client);

	return err;
}

/**
 * Receives data from the service.
 *
 * @param client The syslog_relay client
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success,
 *  SYSLOG_RELAY_E_INVALID_ARG when client or plist is NULL
 */
syslog_relay_error_t syslog_relay_receive(syslog_relay_client_t client, char* data, uint32_t size, uint32_t *received)
{
	return syslog_relay_receive_with_timeout(client, data, size, received, 1000);
}

/**
 * Receives data using the given syslog_relay client with specified timeout.
 *
 * @param client The syslog_relay client to use for receiving
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success,
 *      SYSLOG_RELAY_E_INVALID_ARG when one or more parameters are
 *      invalid, SYSLOG_RELAY_E_MUX_ERROR when a communication error
 *      occurs, or SYSLOG_RELAY_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
syslog_relay_error_t syslog_relay_receive_with_timeout(syslog_relay_client_t client, char* data, uint32_t size, uint32_t *received, unsigned int timeout)
{
	syslog_relay_error_t res = SYSLOG_RELAY_E_UNKNOWN_ERROR;
	int bytes = 0;

	if (!client || !data || (size == 0)) {
		return SYSLOG_RELAY_E_INVALID_ARG;
	}

	res = syslog_relay_error(service_receive_with_timeout(client->parent, data, size, (uint32_t*)&bytes, timeout));
	if (bytes <= 0) {
		debug_info("Could not read data, error %d", res);
	}
	if (received) {
		*received = (uint32_t)bytes;
	}

	return res;
}

void *syslog_relay_worker(void *arg)
{
	service_error_t ret = SERVICE_E_UNKNOWN_ERROR;
	struct syslog_relay_worker_thread *srwt = (struct syslog_relay_worker_thread*)arg;

	if (!srwt)
		return NULL;

	debug_info("Running");

	while (srwt->client->parent) {
		char c;
		uint32_t bytes = 0;
		ret = syslog_relay_receive_with_timeout(srwt->client, &c, 1, &bytes, 100);
		if ((bytes == 0) && (ret == SYSLOG_RELAY_E_SUCCESS)) {
			continue;
		} else if (ret < 0) {
			debug_info("Connection to syslog relay interrupted");
			break;
		}
		if(c != 0) {
			srwt->cbfunc(c, srwt->user_data);
		}
	}

	if (srwt) {
		free(srwt);
	}

	debug_info("Exiting");

	return NULL;
}

/**
 * Starts capturing the syslog of the device using a callback.
 *
 * Use syslog_relay_stop_capture() to stop receiving the syslog.
 *
 * @param client The syslog_relay client to use
 * @param callback Callback to receive each character from the syslog.
 * @param user_data Custom pointer passed to the callback function.
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success,
 *      SYSLOG_RELAY_E_INVALID_ARG when one or more parameters are
 *      invalid or SYSLOG_RELAY_E_UNKNOWN_ERROR when an unspecified
 *      error occurs or a syslog capture has already been started.
 */
syslog_relay_error_t syslog_relay_start_capture(syslog_relay_client_t client, syslog_relay_receive_cb_t callback, void* user_data)
{
	if (!client || !callback)
		return SYSLOG_RELAY_E_INVALID_ARG;

	syslog_relay_error_t res = SYSLOG_RELAY_E_UNKNOWN_ERROR;

	if (client->worker) {
		debug_info("Another syslog capture thread appears to be running already.");
		return res;
	}

	/* start worker thread */
	struct syslog_relay_worker_thread *srwt = (struct syslog_relay_worker_thread*)malloc(sizeof(struct syslog_relay_worker_thread));
	if (srwt) {
		srwt->client = client;
		srwt->cbfunc = callback;
		srwt->user_data = user_data;

		if (thread_create(&client->worker, syslog_relay_worker, srwt) == 0) {
			res = SYSLOG_RELAY_E_SUCCESS;
		}
	}

	return res;
}

/**
 * Stops capturing the syslog of the device.
 *
 * Use syslog_relay_start_capture() to start receiving the syslog.
 *
 * @param client The syslog_relay client to use
 *
 * @return SYSLOG_RELAY_E_SUCCESS on success,
 *      SYSLOG_RELAY_E_INVALID_ARG when one or more parameters are
 *      invalid or SYSLOG_RELAY_E_UNKNOWN_ERROR when an unspecified
 *      error occurs or a syslog capture has already been started.
 */
syslog_relay_error_t syslog_relay_stop_capture(syslog_relay_client_t client)
{
	if (client->worker) {
		/* notify thread to finish */
		service_client_t parent = client->parent;
		client->parent = NULL;
		/* join thread to make it exit */
		thread_join(client->worker);
		client->worker = (thread_t)NULL;
		client->parent = parent;
	}

	return SYSLOG_RELAY_E_SUCCESS;
}