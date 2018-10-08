/**
 * @file libimobiledevice/property_list_service.h
 * @brief Definitions for the PropertyList service
 * \internal
 *
 * Copyright (c) 2010-2014 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2010-2014 Nikias Bassen, All Rights Reserved.
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

#ifndef IPROPERTY_LIST_SERVICE_H
#define IPROPERTY_LIST_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/lockdown.h>

/* Error Codes */
typedef enum {
	PROPERTY_LIST_SERVICE_E_SUCCESS         =  0,
	PROPERTY_LIST_SERVICE_E_INVALID_ARG     = -1,
	PROPERTY_LIST_SERVICE_E_PLIST_ERROR     = -2,
	PROPERTY_LIST_SERVICE_E_MUX_ERROR       = -3,
	PROPERTY_LIST_SERVICE_E_SSL_ERROR       = -4,
	PROPERTY_LIST_SERVICE_E_RECEIVE_TIMEOUT = -5,
	PROPERTY_LIST_SERVICE_E_NOT_ENOUGH_DATA = -6,
	PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR   = -256
} property_list_service_error_t;

typedef struct property_list_service_client_private property_list_service_private;
typedef property_list_service_private* property_list_service_client_t; /**< The client handle. */

/* Interface */

/**
 * Creates a new property list service for the specified port.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated
 *     property_list_service_client_t upon successful return.
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *     PROPERTY_LIST_SERVICE_E_INVALID_ARG when one of the arguments is invalid,
 *     or PROPERTY_LIST_SERVICE_E_MUX_ERROR when connecting to the device failed.
 */
property_list_service_error_t property_list_service_client_new(idevice_t device, lockdownd_service_descriptor_t service, property_list_service_client_t *client);

/**
 * Frees a PropertyList service.
 *
 * @param client The property list service to free.
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *     PROPERTY_LIST_SERVICE_E_INVALID_ARG when client is invalid, or a
 *     PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when another error occurred.
 */
property_list_service_error_t property_list_service_client_free(property_list_service_client_t client);

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
property_list_service_error_t property_list_service_send_xml_plist(property_list_service_client_t client, plist_t plist);

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
property_list_service_error_t property_list_service_send_binary_plist(property_list_service_client_t client, plist_t plist);

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
property_list_service_error_t property_list_service_receive_plist_with_timeout(property_list_service_client_t client, plist_t *plist, unsigned int timeout);

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
 *      PROPERTY_LIST_SERVICE_E_NOT_ENOUGH_DATA when not enough data
 *      received, PROPERTY_LIST_SERVICE_E_RECEIVE_TIMEOUT when the connection times out,
 *      PROPERTY_LIST_SERVICE_E_PLIST_ERROR when the received data cannot be
 *      converted to a plist, PROPERTY_LIST_SERVICE_E_MUX_ERROR when a
 *      communication error occurs, or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR when
 *      an unspecified error occurs.
 */
property_list_service_error_t property_list_service_receive_plist(property_list_service_client_t client, plist_t *plist);

/**
 * Enable SSL for the given property list service client.
 *
 * @param client The connected property list service client for which SSL
 *     should be enabled.
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *     PROPERTY_LIST_SERVICE_E_INVALID_ARG if client or client->connection is
 *     NULL, PROPERTY_LIST_SERVICE_E_SSL_ERROR when SSL could not be enabled,
 *     or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR otherwise.
 */
property_list_service_error_t property_list_service_enable_ssl(property_list_service_client_t client);

/**
 * Disable SSL for the given property list service client.
 *
 * @param client The connected property list service client for which SSL
 *     should be disabled.
 *
 * @return PROPERTY_LIST_SERVICE_E_SUCCESS on success,
 *     PROPERTY_LIST_SERVICE_E_INVALID_ARG if client or client->connection is
 *     NULL, or PROPERTY_LIST_SERVICE_E_UNKNOWN_ERROR otherwise.
 */
property_list_service_error_t property_list_service_disable_ssl(property_list_service_client_t client);

#ifdef __cplusplus
}
#endif

#endif
