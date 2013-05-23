/**
 * @file libimobiledevice/syslog_relay.h
 * @brief Capture the syslog output from a device.
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

#ifndef ISYSLOG_RELAY_H
#define ISYSLOG_RELAY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define SYSLOG_RELAY_SERVICE_NAME "com.apple.syslog_relay"

/** @name Error Codes */
/*@{*/
#define SYSLOG_RELAY_E_SUCCESS                0
#define SYSLOG_RELAY_E_INVALID_ARG           -1
#define SYSLOG_RELAY_E_MUX_ERROR             -2
#define SYSLOG_RELAY_E_SSL_ERROR             -3
#define SYSLOG_RELAY_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t syslog_relay_error_t;

typedef struct syslog_relay_client_private syslog_relay_client_private;
typedef syslog_relay_client_private *syslog_relay_client_t; /**< The client handle. */

/** Receives each character received from the device. */
typedef void (*syslog_relay_receive_cb_t)(char c, void *user_data);

/* Interface */
syslog_relay_error_t syslog_relay_client_new(idevice_t device, lockdownd_service_descriptor_t service, syslog_relay_client_t * client);
syslog_relay_error_t syslog_relay_client_start_service(idevice_t device, syslog_relay_client_t * client, const char* label);
syslog_relay_error_t syslog_relay_client_free(syslog_relay_client_t client);

syslog_relay_error_t syslog_relay_start_capture(syslog_relay_client_t client, syslog_relay_receive_cb_t callback, void* user_data);
syslog_relay_error_t syslog_relay_stop_capture(syslog_relay_client_t client);

/* Receiving */
syslog_relay_error_t syslog_relay_receive_with_timeout(syslog_relay_client_t client, char *data, uint32_t size, uint32_t *received, unsigned int timeout);
syslog_relay_error_t syslog_relay_receive(syslog_relay_client_t client, char *data, uint32_t size, uint32_t *received);

#ifdef __cplusplus
}
#endif

#endif
