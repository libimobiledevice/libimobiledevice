/*
 * webinspector.c 
 * com.apple.webinspector service implementation.
 * 
 * Copyright (c) 2013 Yury Melnichek All Rights Reserved.
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

#include "webinspector.h"
#include "lockdown.h"
#include "debug.h"

/**
 * Convert a property_list_service_error_t value to a webinspector_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An property_list_service_error_t error code
 *
 * @return A matching webinspector_error_t error code,
 *     WEBINSPECTOR_E_UNKNOWN_ERROR otherwise.
 */
static webinspector_error_t webinspector_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return WEBINSPECTOR_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return WEBINSPECTOR_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return WEBINSPECTOR_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return WEBINSPECTOR_E_MUX_ERROR;
		case PROPERTY_LIST_SERVICE_E_SSL_ERROR:
			return WEBINSPECTOR_E_SSL_ERROR;
		default:
			break;
	}
	return WEBINSPECTOR_E_UNKNOWN_ERROR;
}

/**
 * Connects to the webinspector service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     webinspector_client_t upon successful return. Must be freed using
 *     webinspector_client_free() after use.
 *
 * @return WEBINSPECTOR_E_SUCCESS on success, WEBINSPECTOR_E_INVALID_ARG when
 *     client is NULL, or an WEBINSPECTOR_E_* error code otherwise.
 */
webinspector_error_t webinspector_client_new(idevice_t device, lockdownd_service_descriptor_t service, webinspector_client_t * client)
{
	*client = NULL;

	if (!device || !service || service->port == 0 || !client || *client) {
		debug_info("Incorrect parameter passed to webinspector_client_new.");
		return WEBINSPECTOR_E_INVALID_ARG;
	}

	debug_info("Creating webinspector_client, port = %d.", service->port);

	property_list_service_client_t plclient = NULL;
	webinspector_error_t ret = webinspector_error(property_list_service_client_new(device, service, &plclient));
	if (ret != WEBINSPECTOR_E_SUCCESS) {
		debug_info("Creating a property list client failed. Error: %i", ret);
		return ret;
	}

	webinspector_client_t client_loc = (webinspector_client_t) malloc(sizeof(struct webinspector_client_private));
	client_loc->parent = plclient;

	*client = client_loc;

	debug_info("webinspector_client successfully created.");
	return 0;
}

/**
 * Starts a new webinspector service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     webinspector_client_t upon successful return. Must be freed using
 *     webinspector_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return WEBINSPECTOR_E_SUCCESS on success, or an WEBINSPECTOR_E_* error
 *     code otherwise.
 */
webinspector_error_t webinspector_client_start_service(idevice_t device, webinspector_client_t * client, const char* label)
{
	webinspector_error_t err = WEBINSPECTOR_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, WEBINSPECTOR_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(webinspector_client_new), &err);
	return err;
}

/**
 * Disconnects a webinspector client from the device and frees up the
 * webinspector client data.
 *
 * @param client The webinspector client to disconnect and free.
 *
 * @return WEBINSPECTOR_E_SUCCESS on success, WEBINSPECTOR_E_INVALID_ARG when
 *     client is NULL, or an WEBINSPECTOR_E_* error code otherwise.
 */
webinspector_error_t webinspector_client_free(webinspector_client_t client)
{
	if (!client)
		return WEBINSPECTOR_E_INVALID_ARG;

	webinspector_error_t err = webinspector_error(property_list_service_client_free(client->parent));
	free(client);

	return err;
}

/**
 * Sends a plist to the service.
 *
 * @param client The webinspector client
 * @param plist The plist to send
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client or plist is NULL
 */
webinspector_error_t webinspector_send(webinspector_client_t client, plist_t plist)
{
	webinspector_error_t res = WEBINSPECTOR_E_UNKNOWN_ERROR;
	char * buf = NULL;
	uint32_t length = 0;

	plist_to_bin(plist, &buf, &length);
	if (!buf || length == 0) {
		debug_info("Error converting plist to binary.");
		return res;
	}

	plist_t outplist = plist_new_dict();
	plist_dict_insert_item(outplist, "WIRFinalMessageKey", plist_new_data(buf, length));
	free(buf);

	debug_plist(outplist);

	res = webinspector_error(property_list_service_send_binary_plist(client->parent, outplist));
	plist_free(outplist);
	if (res != WEBINSPECTOR_E_SUCCESS) {
		debug_info("Sending plist failed with error %d", res);
		return res;
	}

	return res;
}

/**
 * Receives a plist from the service.
 *
 * @param client The webinspector client
 * @param plist The plist to store the received data
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client or plist is NULL
 */
webinspector_error_t webinspector_receive(webinspector_client_t client, plist_t * plist)
{
	return webinspector_receive_with_timeout(client, plist, 5000);
}

/**
 * Receives a plist using the given webinspector client.
 *
 * @param client The webinspector client to use for receiving
 * @param plist pointer to a plist_t that will point to the received plist
 *      upon successful return
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return WEBINSPECTOR_E_SUCCESS on success,
 *      WEBINSPECTOR_E_INVALID_ARG when client or *plist is NULL,
 *      WEBINSPECTOR_E_PLIST_ERROR when the received data cannot be
 *      converted to a plist, WEBINSPECTOR_E_MUX_ERROR when a
 *      communication error occurs, or WEBINSPECTOR_E_UNKNOWN_ERROR
 *      when an unspecified error occurs.
 */
webinspector_error_t webinspector_receive_with_timeout(webinspector_client_t client, plist_t * plist, uint32_t timeout_ms)
{
	webinspector_error_t res = WEBINSPECTOR_E_UNKNOWN_ERROR;
	plist_t outplist = NULL;

	res = webinspector_error(property_list_service_receive_plist_with_timeout(client->parent, &outplist, timeout_ms));
	if (res != WEBINSPECTOR_E_SUCCESS || !outplist) {
		debug_info("Could not receive plist, error %d", res);
		plist_free(outplist);
		return WEBINSPECTOR_E_MUX_ERROR;
	}

	plist_t inplistdata = plist_dict_get_item(outplist, "WIRFinalMessageKey");
	if (!inplistdata) {
		debug_info("Could not find the internal message plist.");
		plist_free(outplist);
		return WEBINSPECTOR_E_PLIST_ERROR;
	}

	char * buf;
	uint64_t length64;
	plist_get_data_val(inplistdata, &buf, &length64);
	plist_free(outplist);
	if (!buf || length64 == 0 || length64 > 0xFFFFFFFF) {
		debug_info("Error getting the inner plist binary data.");
		free(buf);
		return WEBINSPECTOR_E_PLIST_ERROR;
	}

	plist_from_bin(buf, (uint32_t) length64, plist);
	free(buf);
	if (!*plist) {
		debug_info("Error restoring the inner plist.");
		return WEBINSPECTOR_E_PLIST_ERROR;
	}

	debug_plist(*plist);

	return res;
}
