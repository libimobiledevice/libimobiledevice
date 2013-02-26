/**
 * @file libimobiledevice/webinspector.h
 * @brief WebKit Remote Debugging.
 * \internal
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

#ifndef IWEBINSPECTOR_H
#define IWEBINSPECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define WEBINSPECTOR_SERVICE_NAME "com.apple.webinspector"

/** @name Error Codes */
/*@{*/
#define WEBINSPECTOR_E_SUCCESS                0
#define WEBINSPECTOR_E_INVALID_ARG           -1
#define WEBINSPECTOR_E_PLIST_ERROR           -2
#define WEBINSPECTOR_E_MUX_ERROR             -3
#define WEBINSPECTOR_E_SSL_ERROR             -4
#define WEBINSPECTOR_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t webinspector_error_t;

typedef struct webinspector_client_private webinspector_client_private;
typedef webinspector_client_private *webinspector_client_t; /**< The client handle. */

webinspector_error_t webinspector_client_new(idevice_t device, lockdownd_service_descriptor_t service, webinspector_client_t * client);
webinspector_error_t webinspector_client_start_service(idevice_t device, webinspector_client_t * client, const char* label);
webinspector_error_t webinspector_client_free(webinspector_client_t client);

webinspector_error_t webinspector_send(webinspector_client_t client, plist_t plist);
webinspector_error_t webinspector_receive(webinspector_client_t client, plist_t * plist);
webinspector_error_t webinspector_receive_with_timeout(webinspector_client_t client, plist_t * plist, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
