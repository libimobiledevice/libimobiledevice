/**
 * @file libimobiledevice/heartbeat.h
 * @brief Send "heartbeat" to device to allow service connections over network.
 * \internal
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

#ifndef IHEARTBEAT_H
#define IHEARTBEAT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define HEARTBEAT_SERVICE_NAME "com.apple.mobile.heartbeat"

/** @name Error Codes */
/*@{*/
#define HEARTBEAT_E_SUCCESS                0
#define HEARTBEAT_E_INVALID_ARG           -1
#define HEARTBEAT_E_PLIST_ERROR           -2
#define HEARTBEAT_E_MUX_ERROR             -3
#define HEARTBEAT_E_SSL_ERROR             -4
#define HEARTBEAT_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t heartbeat_error_t;

typedef struct heartbeat_client_private heartbeat_client_private;
typedef heartbeat_client_private *heartbeat_client_t; /**< The client handle. */

heartbeat_error_t heartbeat_client_new(idevice_t device, lockdownd_service_descriptor_t service, heartbeat_client_t * client);
heartbeat_error_t heartbeat_client_start_service(idevice_t device, heartbeat_client_t * client, const char* label);
heartbeat_error_t heartbeat_client_free(heartbeat_client_t client);

heartbeat_error_t heartbeat_send(heartbeat_client_t client, plist_t plist);
heartbeat_error_t heartbeat_receive(heartbeat_client_t client, plist_t * plist);
heartbeat_error_t heartbeat_receive_with_timeout(heartbeat_client_t client, plist_t * plist, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
