/**
 * @file libimobiledevice/diagnostics_relay.h
 * @brief Request iOS diagnostic information from device.
 * \internal
 *
 * Copyright (c) 2012-2014 Martin Szulecki, All Rights Reserved.
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

#ifndef IDIAGNOSTICS_RELAY_H
#define IDIAGNOSTICS_RELAY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** Service identifier passed to lockdownd_start_service() to start the diagnostics relay service */
#define DIAGNOSTICS_RELAY_SERVICE_NAME "com.apple.mobile.diagnostics_relay"

/** Error Codes */
typedef enum {
	DIAGNOSTICS_RELAY_E_SUCCESS         =  0,
	DIAGNOSTICS_RELAY_E_INVALID_ARG     = -1,
	DIAGNOSTICS_RELAY_E_PLIST_ERROR     = -2,
	DIAGNOSTICS_RELAY_E_MUX_ERROR       = -3,
	DIAGNOSTICS_RELAY_E_UNKNOWN_REQUEST = -4,
	DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR   = -256
} diagnostics_relay_error_t;

/** Action type for #diagnostics_relay_restart and #diagnostics_relay_shutdown */
typedef enum {
    DIAGNOSTICS_RELAY_ACTION_FLAG_WAIT_FOR_DISCONNECT = 1 << 1,
    DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_PASS = 1 << 2,
    DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_FAIL = 1 << 3
} diagnostics_relay_action_t;

#define DIAGNOSTICS_RELAY_REQUEST_TYPE_ALL                "All"      /**< Query all available diagnostics */
#define DIAGNOSTICS_RELAY_REQUEST_TYPE_WIFI               "WiFi"     /**< Query WiFi diagnostics */
#define DIAGNOSTICS_RELAY_REQUEST_TYPE_GAS_GAUGE          "GasGauge" /**< Query GasGauge diagnostics */
#define DIAGNOSTICS_RELAY_REQUEST_TYPE_NAND               "NAND"     /**< Query NAND diagnostics */

typedef struct diagnostics_relay_client_private diagnostics_relay_client_private; /**< \private */
typedef diagnostics_relay_client_private *diagnostics_relay_client_t; /**< The client handle. */

/**
 * Connects to the diagnostics_relay service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Reference that will point to a newly allocated
 *     diagnostics_relay_client_t upon successful return.
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *     DIAGNOSTICS_RELAY_E_INVALID_ARG when one of the parameters is invalid,
 *     or DIAGNOSTICS_RELAY_E_MUX_ERROR when the connection failed.
 */
diagnostics_relay_error_t diagnostics_relay_client_new(idevice_t device, lockdownd_service_descriptor_t service, diagnostics_relay_client_t *client);

/**
 * Starts a new diagnostics_relay service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     diagnostics_relay_client_t upon successful return. Must be freed using
 *     diagnostics_relay_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success, or an DIAGNOSTICS_RELAY_E_* error
 *     code otherwise.
 */
diagnostics_relay_error_t diagnostics_relay_client_start_service(idevice_t device, diagnostics_relay_client_t* client, const char* label);

/**
 * Disconnects a diagnostics_relay client from the device and frees up the
 * diagnostics_relay client data.
 *
 * @param client The diagnostics_relay client to disconnect and free.
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *     DIAGNOSTICS_RELAY_E_INVALID_ARG when one of client or client->parent
 *     is invalid, or DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR when the was an
 *     error freeing the parent property_list_service client.
 */
diagnostics_relay_error_t diagnostics_relay_client_free(diagnostics_relay_client_t client);


/**
 * Sends the Goodbye request signaling the end of communication.
 *
 * @param client The diagnostics_relay client
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client is NULL,
 *  DIAGNOSTICS_RELAY_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
diagnostics_relay_error_t diagnostics_relay_goodbye(diagnostics_relay_client_t client);

/**
 * Puts the device into deep sleep mode and disconnects from host.
 *
 * @param client The diagnostics_relay client
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client is NULL,
 *  DIAGNOSTICS_RELAY_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
diagnostics_relay_error_t diagnostics_relay_sleep(diagnostics_relay_client_t client);

/**
 * Restart the device and optionally show a user notification.
 *
 * @param client The diagnostics_relay client
 * @param flags A binary flag combination of
 *        DIAGNOSTICS_RELAY_ACTION_FLAG_WAIT_FOR_DISCONNECT to wait until
 *        diagnostics_relay_client_free() disconnects before execution and
 *        DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_FAIL to show a "FAIL" dialog
 *        or DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_PASS to show an "OK" dialog
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client is NULL,
 *  DIAGNOSTICS_RELAY_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
diagnostics_relay_error_t diagnostics_relay_restart(diagnostics_relay_client_t client, diagnostics_relay_action_t flags);

/**
 * Shutdown of the device and optionally show a user notification.
 *
 * @param client The diagnostics_relay client
 * @param flags A binary flag combination of
 *        DIAGNOSTICS_RELAY_ACTION_FLAG_WAIT_FOR_DISCONNECT to wait until
 *        diagnostics_relay_client_free() disconnects before execution and
 *        DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_FAIL to show a "FAIL" dialog
 *        or DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_PASS to show an "OK" dialog
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client is NULL,
 *  DIAGNOSTICS_RELAY_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
diagnostics_relay_error_t diagnostics_relay_shutdown(diagnostics_relay_client_t client, diagnostics_relay_action_t flags);

/**
 * Request diagnostics information for a given type.
 *
 * @param client The diagnostics_relay client
 * @param type The type or domain to query for diagnostics. Some known values
 *     are "All", "WiFi", "GasGauge", and "NAND".
 * @param diagnostics A pointer to plist_t that will receive the diagnostics information.
 *     The consumer has to free the allocated memory with plist_free() when no longer needed.
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client is NULL,
 *  DIAGNOSTICS_RELAY_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
diagnostics_relay_error_t diagnostics_relay_request_diagnostics(diagnostics_relay_client_t client, const char* type, plist_t* diagnostics);

/**
 * Query one or multiple MobileGestalt keys.
 *
 * @param client The diagnostics_relay client
 * @param keys A PLIST_ARRAY with the keys to query.
 * @param result A pointer to plist_t that will receive the result. The consumer
 *     has to free the allocated memory with plist_free() when no longer needed.
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client is NULL,
 *  DIAGNOSTICS_RELAY_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
diagnostics_relay_error_t diagnostics_relay_query_mobilegestalt(diagnostics_relay_client_t client, plist_t keys, plist_t* result);

/**
 * Query an IORegistry entry of a given class.
 *
 * @param client The diagnostics_relay client
 * @param entry_name The IORegistry entry name to query.
 * @param entry_class The IORegistry class to query.
 * @param result A pointer to plist_t that will receive the result. The consumer
 *     has to free the allocated memory with plist_free() when no longer needed.
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client is NULL,
 *  DIAGNOSTICS_RELAY_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
diagnostics_relay_error_t diagnostics_relay_query_ioregistry_entry(diagnostics_relay_client_t client, const char* entry_name, const char* entry_class, plist_t* result);

/**
 * Query an IORegistry plane.
 *
 * @param client The diagnostics_relay client
 * @param plane The IORegistry plane name to query.
 * @param result A pointer to plist_t that will receive the result. The consumer
 *     has to free the allocated memory with plist_free() when no longer needed.
 *
 * @return DIAGNOSTICS_RELAY_E_SUCCESS on success,
 *  DIAGNOSTICS_RELAY_E_INVALID_ARG when client is NULL,
 *  DIAGNOSTICS_RELAY_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
diagnostics_relay_error_t diagnostics_relay_query_ioregistry_plane(diagnostics_relay_client_t client, const char* plane, plist_t* result);

#ifdef __cplusplus
}
#endif

#endif
