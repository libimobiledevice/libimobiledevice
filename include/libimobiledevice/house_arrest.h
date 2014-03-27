/**
 * @file libimobiledevice/house_arrest.h
 * @brief Access app folders and their contents.
 * \internal
 *
 * Copyright (c) 2010 Nikias Bassen, All Rights Reserved.
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

#ifndef IHOUSE_ARREST_H
#define IHOUSE_ARREST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>

#define HOUSE_ARREST_SERVICE_NAME "com.apple.mobile.house_arrest"

/** @name Error Codes */
/*@{*/
#define HOUSE_ARREST_E_SUCCESS                0
#define HOUSE_ARREST_E_INVALID_ARG           -1
#define HOUSE_ARREST_E_PLIST_ERROR           -2
#define HOUSE_ARREST_E_CONN_FAILED           -3
#define HOUSE_ARREST_E_INVALID_MODE          -4

#define HOUSE_ARREST_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t house_arrest_error_t;

typedef struct house_arrest_client_private house_arrest_client_private;
typedef house_arrest_client_private *house_arrest_client_t; /**< The client handle. */

/* Interface */

/**
 * Connects to the house_arrest service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     housearrest_client_t upon successful return.
 *
 * @return HOUSE_ARREST_E_SUCCESS on success, HOUSE_ARREST_E_INVALID_ARG when
 *     client is NULL, or an HOUSE_ARREST_E_* error code otherwise.
 */
house_arrest_error_t house_arrest_client_new(idevice_t device, lockdownd_service_descriptor_t service, house_arrest_client_t *client);

/**
 * Starts a new house_arrest service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     house_arrest_client_t upon successful return. Must be freed using
 *     house_arrest_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return HOUSE_ARREST_E_SUCCESS on success, or an HOUSE_ARREST_E_* error
 *     code otherwise.
 */
house_arrest_error_t house_arrest_client_start_service(idevice_t device, house_arrest_client_t* client, const char* label);

/**
 * Disconnects an house_arrest client from the device and frees up the
 * house_arrest client data.
 *
 * @note After using afc_client_new_from_house_arrest_client(), make sure
 *     you call afc_client_free() before calling this function to ensure
 *     a proper cleanup. Do not call this function if you still need to
 *     perform AFC operations since it will close the connection.
 *
 * @param client The house_arrest client to disconnect and free.
 *
 * @return HOUSE_ARREST_E_SUCCESS on success, HOUSE_ARREST_E_INVALID_ARG when
 *     client is NULL, or an HOUSE_ARREST_E_* error code otherwise.
 */
house_arrest_error_t house_arrest_client_free(house_arrest_client_t client);


/**
 * Sends a generic request to the connected house_arrest service.
 *
 * @param client The house_arrest client to use.
 * @param dict The request to send as a plist of type PLIST_DICT.
 *
 * @note If this function returns HOUSE_ARREST_E_SUCCESS it does not mean
 *     that the request was successful. To check for success or failure you
 *     need to call house_arrest_get_result().
 * @see house_arrest_get_result
 *
 * @return HOUSE_ARREST_E_SUCCESS if the request was successfully sent,
 *     HOUSE_ARREST_E_INVALID_ARG if client or dict is invalid,
 *     HOUSE_ARREST_E_PLIST_ERROR if dict is not a plist of type PLIST_DICT,
 *     HOUSE_ARREST_E_INVALID_MODE if the client is not in the correct mode,
 *     or HOUSE_ARREST_E_CONN_FAILED if a connection error occured.
 */
house_arrest_error_t house_arrest_send_request(house_arrest_client_t client, plist_t dict);

/**
 * Send a command to the connected house_arrest service.
 * Calls house_arrest_send_request() internally.
 *
 * @param client The house_arrest client to use.
 * @param command The command to send. Currently, only VendContainer and
 *     VendDocuments are known.
 * @param appid The application identifier to pass along with the .
 *
 * @note If this function returns HOUSE_ARREST_E_SUCCESS it does not mean
 *     that the command was successful. To check for success or failure you
 *     need to call house_arrest_get_result().
 * @see house_arrest_get_result
 *
 * @return HOUSE_ARREST_E_SUCCESS if the command was successfully sent,
 *     HOUSE_ARREST_E_INVALID_ARG if client, command, or appid is invalid,
 *     HOUSE_ARREST_E_INVALID_MODE if the client is not in the correct mode,
 *     or HOUSE_ARREST_E_CONN_FAILED if a connection error occured.
 */
house_arrest_error_t house_arrest_send_command(house_arrest_client_t client, const char *command, const char *appid);

/**
 * Retrieves the result of a previously sent house_arrest_request_* request.
 *
 * @param client The house_arrest client to use
 * @param dict Pointer that will be set to a plist containing the result to
 *     the last performed operation. It holds a key 'Status' with the value
 *     'Complete' on success or a key 'Error' with an error description as
 *     value. The caller is responsible for freeing the returned plist.
 *
 * @return HOUSE_ARREST_E_SUCCESS if a result plist was retrieved,
 *     HOUSE_ARREST_E_INVALID_ARG if client is invalid,
 *     HOUSE_ARREST_E_INVALID_MODE if the client is not in the correct mode,
 *     or HOUSE_ARREST_E_CONN_FAILED if a connection error occured.
 */
house_arrest_error_t house_arrest_get_result(house_arrest_client_t client, plist_t *dict);


/**
 * Creates an AFC client using the given house_arrest client's connection
 * allowing file access to a specific application directory requested by
 * functions like house_arrest_request_vendor_documents().
 *
 * @param client The house_arrest client to use.
 * @param afc_client Pointer that will be set to a newly allocated afc_client_t
 *     upon successful return.
 *
 * @note After calling this function the house_arrest client will go in an
 *     AFC mode that will only allow calling house_arrest_client_free().
 *     Only call house_arrest_client_free() if all AFC operations have
 *     completed since it will close the connection.
 *
 * @return AFC_E_SUCCESS if the afc client was successfully created,
 *     AFC_E_INVALID_ARG if client is invalid or was already used to create
 *     an afc client, or an AFC_E_* error code returned by
 *     afc_client_new_with_service_client().
 */
afc_error_t afc_client_new_from_house_arrest_client(house_arrest_client_t client, afc_client_t *afc_client);

#ifdef __cplusplus
}
#endif

#endif
