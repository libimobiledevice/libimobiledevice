/**
 * @file libimobiledevice/diagnostics_relay.h
 * @brief Request iOS diagnostic information from device.
 * \internal
 *
 * Copyright (c) 2012 Martin Szulecki, All Rights Reserved.
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

/** @name Error Codes */
/*@{*/
#define DIAGNOSTICS_RELAY_E_SUCCESS                0
#define DIAGNOSTICS_RELAY_E_INVALID_ARG           -1
#define DIAGNOSTICS_RELAY_E_PLIST_ERROR           -2
#define DIAGNOSTICS_RELAY_E_MUX_ERROR             -3

#define DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t diagnostics_relay_error_t;

typedef struct diagnostics_relay_client_private diagnostics_relay_client_private;
typedef diagnostics_relay_client_private *diagnostics_relay_client_t; /**< The client handle. */

diagnostics_relay_error_t diagnostics_relay_client_new(idevice_t device, uint16_t port, diagnostics_relay_client_t *client);
diagnostics_relay_error_t diagnostics_relay_client_free(diagnostics_relay_client_t client);

diagnostics_relay_error_t diagnostics_relay_goodbye(diagnostics_relay_client_t client);
diagnostics_relay_error_t diagnostics_relay_request_diagnostics(diagnostics_relay_client_t client, plist_t* diagnostics);

#ifdef __cplusplus
}
#endif

#endif
