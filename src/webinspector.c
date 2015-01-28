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
#include "common/debug.h"

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

LIBIMOBILEDEVICE_API webinspector_error_t webinspector_client_new(idevice_t device, lockdownd_service_descriptor_t service, webinspector_client_t * client)
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

LIBIMOBILEDEVICE_API webinspector_error_t webinspector_client_start_service(idevice_t device, webinspector_client_t * client, const char* label)
{
	webinspector_error_t err = WEBINSPECTOR_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, WEBINSPECTOR_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(webinspector_client_new), &err);
	return err;
}

LIBIMOBILEDEVICE_API webinspector_error_t webinspector_client_free(webinspector_client_t client)
{
	if (!client)
		return WEBINSPECTOR_E_INVALID_ARG;

	webinspector_error_t err = webinspector_error(property_list_service_client_free(client->parent));
	free(client);

	return err;
}

LIBIMOBILEDEVICE_API webinspector_error_t webinspector_send(webinspector_client_t client, plist_t plist)
{
	webinspector_error_t res = WEBINSPECTOR_E_UNKNOWN_ERROR;

	uint32_t offset = 0;
	int is_final_message = 0;

	char *packet = NULL;
	uint32_t packet_length = 0;

	debug_info("Sending webinspector message...");
	debug_plist(plist);

	/* convert plist to packet */
	plist_to_bin(plist, &packet, &packet_length);
	if (!packet || packet_length == 0) {
		debug_info("Error converting plist to binary.");
		return res;
	}

	do {
		/* determine if we need to send partial messages */
		if (packet_length < WEBINSPECTOR_PARTIAL_PACKET_CHUNK_SIZE) {
			is_final_message = 1;
		} else {
			/* send partial packet */
			is_final_message = 0;
		}

		plist_t outplist = plist_new_dict();
		if (!is_final_message) {
			/* split packet into partial chunks */
			plist_dict_set_item(outplist, "WIRPartialMessageKey", plist_new_data(packet + offset, WEBINSPECTOR_PARTIAL_PACKET_CHUNK_SIZE));
			offset += WEBINSPECTOR_PARTIAL_PACKET_CHUNK_SIZE;
			packet_length -= WEBINSPECTOR_PARTIAL_PACKET_CHUNK_SIZE;
		} else {
			/* send final chunk */
			plist_dict_set_item(outplist, "WIRFinalMessageKey", plist_new_data(packet + offset, packet_length));
			offset += packet_length;
			packet_length -= packet_length;
		}

		res = webinspector_error(property_list_service_send_binary_plist(client->parent, outplist));
		plist_free(outplist);
		outplist = NULL;
		if (res != WEBINSPECTOR_E_SUCCESS) {
			debug_info("Sending plist failed with error %d", res);
			return res;
		}
	} while(packet_length > 0);

	free(packet);
	packet = NULL;

	return res;
}

LIBIMOBILEDEVICE_API webinspector_error_t webinspector_receive(webinspector_client_t client, plist_t * plist)
{
	return webinspector_receive_with_timeout(client, plist, 5000);
}

LIBIMOBILEDEVICE_API webinspector_error_t webinspector_receive_with_timeout(webinspector_client_t client, plist_t * plist, uint32_t timeout_ms)
{
	webinspector_error_t res = WEBINSPECTOR_E_UNKNOWN_ERROR;
	plist_t message = NULL;
	plist_t key = NULL;

	int is_final_message = 1;

	char* buffer = NULL;
	uint64_t length = 0;

	char* packet = NULL;
	char* newpacket = NULL;
	uint64_t packet_length = 0;

	debug_info("Receiving webinspector message...");

	do {
		/* receive message */
		res = webinspector_error(property_list_service_receive_plist_with_timeout(client->parent, &message, timeout_ms));
		if (res != WEBINSPECTOR_E_SUCCESS || !message) {
			debug_info("Could not receive message, error %d", res);
			plist_free(message);
			return WEBINSPECTOR_E_MUX_ERROR;
		}

		/* get message key */
		key = plist_dict_get_item(message, "WIRFinalMessageKey");
		if (!key) {
			key = plist_dict_get_item(message, "WIRPartialMessageKey");
			if (!key) {
				debug_info("ERROR: Unable to read message key.");
				plist_free(message);
				return WEBINSPECTOR_E_PLIST_ERROR;
			}
			is_final_message = 0;
		} else {
			is_final_message = 1;
		}

		/* read partial data */
		plist_get_data_val(key, &buffer, &length);
		if (!buffer || length == 0 || length > 0xFFFFFFFF) {
			debug_info("ERROR: Unable to get the inner plist binary data.");
			free(packet);
			free(buffer);
			return WEBINSPECTOR_E_PLIST_ERROR;
		}

		/* (re)allocate packet data */
		if (!packet) {
			packet = (char*)malloc(length * sizeof(char));
		} else {
			newpacket = (char*)realloc(packet, (packet_length + length) * sizeof(char));
			packet = newpacket;
		}

		/* copy partial data into final packet data */
		memcpy(packet + packet_length, buffer, length);

		/* cleanup buffer */
		free(buffer);
		buffer = NULL;

		if (message) {
			plist_free(message);
			message = NULL;
		}

		/* adjust packet length */
		packet_length += length;
		length = 0;
	} while(!is_final_message);

	/* read final message */
	if (packet_length) {
		plist_from_bin(packet, (uint32_t)packet_length, plist);
		if (!*plist) {
			debug_info("Error restoring the final plist.");
			free(packet);
			return WEBINSPECTOR_E_PLIST_ERROR;
		}

		debug_plist(*plist);
	}

	if (packet) {
		free(packet);
	}

	return res;
}
