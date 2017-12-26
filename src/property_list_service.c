/*
 * property_list_service.c
 * PropertyList service implementation.
 *
 * Copyright (c) 2010 Nikias Bassen. All Rights Reserved.
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
#include <stdlib.h>
#include <string.h>

#include "property_list_service.h"
#include "common/debug.h"
#include "endianness.h"

/**
 * Convert a service_error_t value to a property_list_service_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err A service_error_t error code
 *
 * @return A matching property_list_service_error_t error code,
 *     PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR otherwise.
 */
static property_list_service_error_t service_to_property_list_service_error(service_error_t err)
{
	switch (err) {
		case SERVICE_E_SUCCESS:
			return PROPERTY_LIST_SERVICE_E_SUCCESS;
		case SERVICE_E_INVALID_ARG:
			return PROPERTY_LIST_SERVICE_E_INVALID_ARG;
		case SERVICE_E_MUX_ERROR:
			return PROPERTY_LIST_SERVICE_E_MUX_ERROR;
		case SERVICE_E_SSL_ERROR:
			return PROPERTY_LIST_SERVICE_E_SSL_ERROR;
		default:
			break;
	}
	return PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API property_list_service_error_t property_list_service_client_new(idevice_t device, lockdownd_service_descriptor_t service, property_list_service_client_t *client)
{
	if (!device || !service || service->port == 0 || !client || *client)
		return PROPERTY_LIST_SERVICE_E_INVALID_ARG;

	service_client_t parent = NULL;
	service_error_t rerr = service_client_new(device, service, &parent);
	if (rerr != SERVICE_E_SUCCESS) {
		return service_to_property_list_service_error(rerr);
	}

	/* create client object */
	property_list_service_client_t client_loc = (property_list_service_client_t)malloc(sizeof(struct property_list_service_client_private));
	client_loc->parent = parent;

	/* all done, return success */
	*client = client_loc;
	return PROPERTY_LIST_SERVICE_E_SUCCESS;
}

LIBIMOBILEDEVICE_API property_list_service_error_t property_list_service_client_free(property_list_service_client_t client)
{
	if (!client)
		return PROPERTY_LIST_SERVICE_E_INVALID_ARG;

	property_list_service_error_t err = service_to_property_list_service_error(service_client_free(client->parent));

	free(client);
	client = NULL;

	return err;
}

/**
 * Sends a plist using the given property list service client.
 * Internally used generic plist send function.
 *
 * @param client The property list service client to use for sending.
 * @param plist plist to send
 * @param binary 1 = send binary plist, 0 = send xml plist
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when one or more parameters are
 *      invalid, PROPERTY_LIST_SERVICE_E_PLIST_ERROR when dict is not a valid
 *      plist, PROPERTY_LIST_SERVICE_E_MUX_ERROR when a communication error
 *      occurs, or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
static property_list_service_error_t internal_plist_send(property_list_service_client_t client, plist_t plist, int binary)
{
	property_list_service_error_t res = PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR;
	char *content = NULL;
	uint32_t length = 0;
	uint32_t nlen = 0;
	int bytes = 0;

	if (!client || (client && !client->parent) || !plist) {
		return PROPERTY_LIST_SERVICE_E_INVALID_ARG;
	}

	if (binary) {
		plist_to_bin(plist, &content, &length);
	} else {
		plist_to_xml(plist, &content, &length);
	}

	if (!content || length == 0) {
		return PROPERTY_LIST_SERVICE_E_PLIST_ERROR;
	}

	nlen = htobe32(length);
	debug_info("sending %d bytes", length);
	service_send(client->parent, (const char*)&nlen, sizeof(nlen), (uint32_t*)&bytes);
	if (bytes == sizeof(nlen)) {
		service_send(client->parent, content, length, (uint32_t*)&bytes);
		if (bytes > 0) {
			debug_info("sent %d bytes", bytes);
			debug_plist(plist);
			if ((uint32_t)bytes == length) {
				res = PROPERTY_LIST_SERVICE_E_SUCCESS;
			} else {
				debug_info("ERROR: Could not send all data (%d of %d)!", bytes, length);
			}
		}
	}
	if (bytes <= 0) {
		debug_info("ERROR: sending to device failed.");
		res = PROPERTY_LIST_SERVICE_E_MUX_ERROR;
	}

	free(content);

	return res;
}

LIBIMOBILEDEVICE_API property_list_service_error_t property_list_service_send_xml_plist(property_list_service_client_t client, plist_t plist)
{
	return internal_plist_send(client, plist, 0);
}

LIBIMOBILEDEVICE_API property_list_service_error_t property_list_service_send_binary_plist(property_list_service_client_t client, plist_t plist)
{
	return internal_plist_send(client, plist, 1);
}

/**
 * Receives a plist using the given property list service client.
 * Internally used generic plist receive function.
 *
 * @param client The property list service client to use for receiving
 * @param plist pointer to a plist_t that will point to the received plist
 *      upon successful return
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when client or *plist is NULL,
 *      PROPERTY_LIST_SERVICE_E_PLIST_ERROR when the received data cannot be
 *      converted to a plist, PROPERTY_LIST_SERVICE_E_MUX_ERROR when a
 *      communication error occurs, or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR
 *      when an unspecified error occurs.
 */
static property_list_service_error_t internal_plist_receive_timeout(property_list_service_client_t client, plist_t *plist, unsigned int timeout)
{
	property_list_service_error_t res = PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR;
	uint32_t pktlen = 0;
	uint32_t bytes = 0;

	if (!client || (client && !client->parent) || !plist) {
		return PROPERTY_LIST_SERVICE_E_INVALID_ARG;
	}

	*plist = NULL;
	service_error_t serr = service_receive_with_timeout(client->parent, (char*)&pktlen, sizeof(pktlen), &bytes, timeout);
	if ((serr == SERVICE_E_SUCCESS) && (bytes == 0)) {
		return PROPERTY_LIST_SERVICE_E_RECEIVE_TIMEOUT;
	}
	debug_info("initial read=%i", bytes);
	if (bytes < 4) {
		debug_info("initial read failed!");
		return PROPERTY_LIST_SERVICE_E_MUX_ERROR;
	} else {
		uint32_t curlen = 0;
		char *content = NULL;

		pktlen = be32toh(pktlen);
		debug_info("%d bytes following", pktlen);
		content = (char*)malloc(pktlen);
		if (!content) {
			debug_info("out of memory when allocating %d bytes", pktlen);
			return PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR;
		}

		while (curlen < pktlen) {
			service_receive(client->parent, content+curlen, pktlen-curlen, &bytes);
			if (bytes <= 0) {
				res = PROPERTY_LIST_SERVICE_E_MUX_ERROR;
				break;
			}
			debug_info("received %d bytes", bytes);
			curlen += bytes;
		}
		if (curlen < pktlen) {
			debug_info("received incomplete packet (%d of %d bytes)", curlen, pktlen);
			if (curlen > 0) {
				debug_info("incomplete packet following:");
				debug_buffer(content, curlen);
			}
			free(content);
			return res;
		}
		if ((pktlen > 8) && !memcmp(content, "bplist00", 8)) {
			plist_from_bin(content, pktlen, plist);
		} else if ((pktlen > 5) && !memcmp(content, "<?xml", 5)) {
			/* iOS 4.3+ hack: plist data might contain invalid characters, thus we convert those to spaces */
			for (bytes = 0; bytes < pktlen-1; bytes++) {
				if ((content[bytes] >= 0) && (content[bytes] < 0x20) && (content[bytes] != 0x09) && (content[bytes] != 0x0a) && (content[bytes] != 0x0d))
					content[bytes] = 0x20;
			}
			plist_from_xml(content, pktlen, plist);
		} else {
			debug_info("WARNING: received unexpected non-plist content");
			debug_buffer(content, pktlen);
		}
		if (*plist) {
			debug_plist(*plist);
			res = PROPERTY_LIST_SERVICE_E_SUCCESS;
		} else {
			res = PROPERTY_LIST_SERVICE_E_PLIST_ERROR;
		}
		free(content);
		content = NULL;
	}
	return res;
}

LIBIMOBILEDEVICE_API property_list_service_error_t property_list_service_receive_plist_with_timeout(property_list_service_client_t client, plist_t *plist, unsigned int timeout)
{
	return internal_plist_receive_timeout(client, plist, timeout);
}

LIBIMOBILEDEVICE_API property_list_service_error_t property_list_service_receive_plist(property_list_service_client_t client, plist_t *plist)
{
	return internal_plist_receive_timeout(client, plist, 10000);
}

LIBIMOBILEDEVICE_API property_list_service_error_t property_list_service_enable_ssl(property_list_service_client_t client)
{
	if (!client || !client->parent)
		return PROPERTY_LIST_SERVICE_E_INVALID_ARG;
	return service_to_property_list_service_error(service_enable_ssl(client->parent));
}

LIBIMOBILEDEVICE_API property_list_service_error_t property_list_service_disable_ssl(property_list_service_client_t client)
{
	if (!client || !client->parent)
		return PROPERTY_LIST_SERVICE_E_INVALID_ARG;
	return service_to_property_list_service_error(service_disable_ssl(client->parent));
}

