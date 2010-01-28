/**
 * @file libimobiledevice/sbservices.h
 * @brief Implementation to talk to com.apple.springboardservices on a device
 * \internal
 *
 * Copyright (c) 2009 Nikias Bassen All Rights Reserved.
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

#ifndef SB_SERVICES_H
#define SB_SERVICES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>

/* Error Codes */
#define SBSERVICES_E_SUCCESS                0
#define SBSERVICES_E_INVALID_ARG           -1
#define SBSERVICES_E_PLIST_ERROR           -2
#define SBSERVICES_E_CONN_FAILED           -3

#define SBSERVICES_E_UNKNOWN_ERROR       -256

typedef int16_t sbservices_error_t;

struct sbservices_client_int;
typedef struct sbservices_client_int *sbservices_client_t;

/* Interface */
sbservices_error_t sbservices_client_new(idevice_t device, uint16_t port, sbservices_client_t *client);
sbservices_error_t sbservices_client_free(sbservices_client_t client);
sbservices_error_t sbservices_get_icon_state(sbservices_client_t client, plist_t *state);
sbservices_error_t sbservices_set_icon_state(sbservices_client_t client, plist_t newstate);
sbservices_error_t sbservices_get_icon_pngdata(sbservices_client_t client, const char *bundleId, char **pngdata, uint64_t *pngsize);

#ifdef __cplusplus
}
#endif

#endif
