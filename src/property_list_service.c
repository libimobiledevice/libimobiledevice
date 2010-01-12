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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "property_list_service.h"
#include "iphone.h"
#include "debug.h"

/**
 * Convert an iphone_error_t value to an property_list_service_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An iphone_error_t error code
 *
 * @return A matching property_list_service_error_t error code,
 *     PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR otherwise.
 */
static property_list_service_error_t iphone_to_property_list_service_error(iphone_error_t err)
{
	switch (err) {
		case IPHONE_E_SUCCESS:
			return PROPERTY_LIST_SERVICE_E_SUCCESS;
		case IPHONE_E_INVALID_ARG:
			return PROPERTY_LIST_SERVICE_E_INVALID_ARG;
		default:
			break;
	}
	return PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR;
}

/**
 * Creates a new property list service for the specified port.
 * 
 * @param device The device to connect to.
 * @param port The port on the device to connect to, usually opened by a call to
 *     lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated
 *     property_list_service_client_t upon successful return.
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *     PROPERTY_LIST_SERVICE_E_INVALID_ARG when one of the arguments is invalid,
 *     or PROPERTY_LIST_SERVICE_E_MUX_ERROR when connecting to the device failed.
 */
property_list_service_error_t property_list_service_client_new(iphone_device_t device, uint16_t port, property_list_service_client_t *client)
{
	if (!device || port == 0 || !client || *client)
		return PROPERTY_LIST_SERVICE_E_INVALID_ARG;

	/* Attempt connection */
	iphone_connection_t connection = NULL;
	if (iphone_device_connect(device, port, &connection) != IPHONE_E_SUCCESS) {
		return PROPERTY_LIST_SERVICE_E_MUX_ERROR;
	}

	/* create client object */
	property_list_service_client_t client_loc = (property_list_service_client_t)malloc(sizeof(struct property_list_service_client_int));
	client_loc->connection = connection;

	*client = client_loc;

	return PROPERTY_LIST_SERVICE_E_SUCCESS;
}

/**
 * Frees a PropertyList service.
 *
 * @param client The property list service to free.
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *     PROPERTY_LIST_SERVICE_E_INVALID_ARG when client is invalid, or a
 *     PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when another error occured.
 */
property_list_service_error_t property_list_service_client_free(property_list_service_client_t client)
{
	if (!client)
		return PROPERTY_LIST_SERVICE_E_INVALID_ARG;

	property_list_service_error_t err = iphone_to_property_list_service_error(iphone_device_disconnect(client->connection));
	free(client);
	return err;
}

/**
 * Sends a plist using the given property list service client.
 * Internally used generic plist send function.
 *
 * @param client The property list service client to use for sending.
 *      Can be NULL if ssl_session is non-NULL.
 * @param plist plist to send
 * @param binary 1 = send binary plist, 0 = send xml plist
 * @param ssl_session If set to NULL, the communication will be unencrypted.
 *      For encrypted communication, pass a valid and properly initialized
 *      gnutls_session_t. client is ignored when ssl_session is non-NULL.
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when one or more parameters are
 *      invalid, PROPERTY_LIST_SERVICE_E_PLIST_ERROR when dict is not a valid
 *      plist, or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
static property_list_service_error_t internal_plist_send(property_list_service_client_t client, plist_t plist, int binary, gnutls_session_t ssl_session)
{
	property_list_service_error_t res = PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR;
	char *content = NULL;
	uint32_t length = 0;
	uint32_t nlen = 0;
	int bytes = 0;

	if ((!client && !ssl_session) || (client && !client->connection) || !plist) {
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

	nlen = htonl(length);
	log_debug_msg("%s: sending %d bytes\n", __func__, length);
	if (ssl_session) {
		bytes = gnutls_record_send(ssl_session, (const char*)&nlen, sizeof(nlen));
	} else {
		iphone_device_send(client->connection, (const char*)&nlen, sizeof(nlen), (uint32_t*)&bytes);
	}
	if (bytes == sizeof(nlen)) {
		if (ssl_session) {
			bytes = gnutls_record_send(ssl_session, content, length);
		} else {
			iphone_device_send(client->connection, content, length, (uint32_t*)&bytes);
		}
		if (bytes > 0) {
			log_debug_msg("%s: sent %d bytes\n", __func__, bytes);
			log_debug_buffer(content, bytes);
			if ((uint32_t)bytes == length) {
				res = PROPERTY_LIST_SERVICE_E_SUCCESS;
			} else {
				log_debug_msg("%s: ERROR: Could not send all data (%d of %d)!\n", __func__, bytes, length);
			}
		}
	}
	if (bytes <= 0) {
		log_debug_msg("%s: ERROR: sending to device failed.\n", __func__);
	}

	free(content);

	return res;
}

/**
 * Sends an XML plist.
 *
 * @param client The property list service client to use for sending.
 * @param plist plist to send
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when client or plist is NULL,
 *      PROPERTY_LIST_SERVICE_E_PLIST_ERROR when dict is not a valid plist,
 *      or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when an unspecified error occurs.
 */
property_list_service_error_t property_list_service_send_xml_plist(property_list_service_client_t client, plist_t plist)
{
	return internal_plist_send(client, plist, 0, NULL);
}

/**
 * Sends a binary plist.
 *
 * @param client The property list service client to use for sending.
 * @param plist plist to send
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when client or plist is NULL,
 *      PROPERTY_LIST_SERVICE_E_PLIST_ERROR when dict is not a valid plist,
 *      or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when an unspecified error occurs.
 */
property_list_service_error_t property_list_service_send_binary_plist(property_list_service_client_t client, plist_t plist)
{
	return internal_plist_send(client, plist, 1, NULL);
}

/**
 * Sends an encrypted XML plist.
 *
 * @param ssl_session Valid and properly initialized gnutls_session_t.
 * @param plist plist to send
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when ssl_session or plist is NULL
 *      PROPERTY_LIST_SERVICE_E_PLIST_ERROR when dict is not a valid plist,
 *      or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when an unspecified error occurs.
 */
property_list_service_error_t property_list_service_send_encrypted_xml_plist(gnutls_session_t ssl_session, plist_t plist)
{
	return internal_plist_send(NULL, plist, 0, ssl_session);
}

/**
 * Sends an encrypted binary plist.
 *
 * @param ssl_session Valid and properly initialized gnutls_session_t.
 * @param plist plist to send
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when ssl_session or plist is NULL,
 *      PROPERTY_LIST_SERVICE_E_PLIST_ERROR when dict is not a valid plist,
 *      or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when an unspecified error occurs.
 */
property_list_service_error_t property_list_service_send_encrypted_binary_plist(gnutls_session_t ssl_session, plist_t plist)
{
	return internal_plist_send(NULL, plist, 1, ssl_session);
}

/**
 * Receives a plist using the given property list service client.
 * Internally used generic plist receive function.
 *
 * @param client The property list service client to use for receiving
 * @param plist pointer to a plist_t that will point to the received plist
 *      upon successful return
 * @param timeout Maximum time in milliseconds to wait for data. This parameter
 *      is ignored when ssl_session is not NULL (i.e. encrypted communication is
 *      used). A timeout has to be implemented inside the functions passed to
 *      gnutls_transport_set_push_function / gnutls_transport_set_pull_function.
 * @param ssl_session If set to NULL, the communication will be unencrypted.
 *      For encrypted communication, pass a valid and properly initialized
 *      gnutls_session_t.
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when client or *plist is NULL,
 *      PROPERTY_LIST_SERVICE_E_PLIST_ERROR when the received data cannot be
 *      converted to a plist, PROPERTY_LIST_SERVICE_E_MUX_ERROR when a
 *      communication error occurs, or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when
 *      an unspecified error occurs.
 */
static property_list_service_error_t internal_plist_recv_timeout(property_list_service_client_t client, plist_t *plist, unsigned int timeout, gnutls_session_t ssl_session)
{
	property_list_service_error_t res = PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR;
	uint32_t pktlen = 0;
	uint32_t bytes = 0;

	if ((!client && !ssl_session) || (client && !client->connection) || !plist) {
		return PROPERTY_LIST_SERVICE_E_INVALID_ARG;
	}

	if (ssl_session) {
		bytes = gnutls_record_recv(ssl_session, (char*)&pktlen, sizeof(pktlen));
	} else {
		iphone_device_recv_timeout(client->connection, (char*)&pktlen, sizeof(pktlen), &bytes, timeout);
	}
	log_debug_msg("%s: initial read=%i\n", __func__, bytes);
	if (bytes < 4) {
		log_debug_msg("%s: initial read failed!\n", __func__);
		return PROPERTY_LIST_SERVICE_E_MUX_ERROR;
	} else {
		if ((char)pktlen == 0) { /* prevent huge buffers */
			uint32_t curlen = 0;
			char *content = NULL;
			pktlen = ntohl(pktlen);
			log_debug_msg("%s: %d bytes following\n", __func__, pktlen);
			content = (char*)malloc(pktlen);

			while (curlen < pktlen) {
				if (ssl_session) {
					bytes = gnutls_record_recv(ssl_session, content+curlen, pktlen-curlen);
				} else {
					iphone_device_recv(client->connection, content+curlen, pktlen-curlen, &bytes);
				}
				if (bytes <= 0) {
					res = PROPERTY_LIST_SERVICE_E_MUX_ERROR;
					break;
				}
				log_debug_msg("%s: received %d bytes\n", __func__, bytes);
				curlen += bytes;
			}
			log_debug_buffer(content, pktlen);
			if (!memcmp(content, "bplist00", 8)) {
				plist_from_bin(content, pktlen, plist);
			} else {
				plist_from_xml(content, pktlen, plist);
			}
			if (*plist) {
				res = PROPERTY_LIST_SERVICE_E_SUCCESS;
			} else {
				res = PROPERTY_LIST_SERVICE_E_PLIST_ERROR;
			}
			free(content);
			content = NULL;
		} else {
			res = PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR;
		}
	}
	return res;
}

/**
 * Receives a plist using the given property list service client with specified
 * timeout.
 * Binary or XML plists are automatically handled.
 *
 * @param client The property list service client to use for receiving
 * @param plist pointer to a plist_t that will point to the received plist
 *              upon successful return
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when connection or *plist is NULL,
 *      PROPERTY_LIST_SERVICE_E_PLIST_ERROR when the received data cannot be
 *      converted to a plist, PROPERTY_LIST_SERVICE_E_MUX_ERROR when a
 *      communication error occurs, or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when
 *      an unspecified error occurs.
 */
property_list_service_error_t property_list_service_receive_plist_with_timeout(property_list_service_client_t client, plist_t *plist, unsigned int timeout)
{
	return internal_plist_recv_timeout(client, plist, timeout, NULL);
}

/**
 * Receives a plist using the given property list service client.
 * Binary or XML plists are automatically handled.
 *
 * This function is like property_list_service_receive_plist_with_timeout
 *   using a timeout of 10 seconds.
 * @see property_list_service_receive_plist_with_timeout
 *
 * @param client The property list service client to use for receiving
 * @param plist pointer to a plist_t that will point to the received plist
 *      upon successful return
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when client or *plist is NULL,
 *      PROPERTY_LIST_SERVICE_E_PLIST_ERROR when the received data cannot be
 *      converted to a plist, PROPERTY_LIST_SERVICE_E_MUX_ERROR when a
 *      communication error occurs, or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when
 *      an unspecified error occurs.
 */
property_list_service_error_t property_list_service_receive_plist(property_list_service_client_t client, plist_t *plist)
{
	return internal_plist_recv_timeout(client, plist, 10000, NULL);
}

/**
 * Receives an encrypted plist.
 * Binary or XML plists are automatically handled.
 * This function is like property_list_service_receive_encrypted_plist_with_timeout
 *   with a timeout value of 10 seconds.
 *
 * @param ssl_session Valid and properly initialized gnutls_session_t.
 * @param plist pointer to a plist_t that will point to the received plist
 *              upon successful return
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *      PROPERTY_LIST_SERVICE_E_INVALID_ARG when ssl_session or *plist is NULL,
 *      PROPERTY_LIST_SERVICE_E_PLIST_ERROR when the received data cannot be
 *      converted to a plist, PROPERTY_LIST_SERVICE_E_MUX_ERROR when a
 *      communication error occurs, or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when
 *      an unspecified error occurs.
 */
property_list_service_error_t property_list_service_receive_encrypted_plist(gnutls_session_t ssl_session, plist_t *plist)
{
	return internal_plist_recv_timeout(NULL, plist, 10000, ssl_session);
}

/**
 * Getter for the iphone_connection_t used by this client.
 *
 * @param client The property list service client to get the connection for.
 *
 * @return The connection used by client.
 */
iphone_connection_t property_list_service_get_connection(property_list_service_client_t client)
{
	if (!client)
		return NULL;
	return client->connection;
}
