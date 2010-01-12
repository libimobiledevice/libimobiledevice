/**
 * @file libiphone/libiphone.h
 * @brief Common code and device handling
 * \internal
 *
 * Copyright (c) 2008 Jonathan Beck All Rights Reserved.
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

#ifndef LIBIPHONE_H
#define LIBIPHONE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <plist/plist.h>

/* Error Codes */
#define IPHONE_E_SUCCESS                0
#define IPHONE_E_INVALID_ARG           -1
#define IPHONE_E_UNKNOWN_ERROR         -2
#define IPHONE_E_NO_DEVICE             -3
#define IPHONE_E_NOT_ENOUGH_DATA       -4
#define IPHONE_E_BAD_HEADER            -5
#define IPHONE_E_PLIST_ERROR           -6

typedef int16_t iphone_error_t;

struct iphone_device_int;
typedef struct iphone_device_int *iphone_device_t;

struct iphone_connection_int;
typedef struct iphone_connection_int *iphone_connection_t;

/* generic */
void iphone_set_debug_level(int level);

/* discovery (events/asynchronous) */
// event type
enum iphone_event_type {
	IPHONE_DEVICE_ADD = 1,
	IPHONE_DEVICE_REMOVE
};

// event data structure
typedef struct {
	enum iphone_event_type event;
	const char *uuid;
	int conn_type;
} iphone_event_t;

// event callback function prototype
typedef void (*iphone_event_cb_t) (const iphone_event_t *event, void *user_data);

// functions
iphone_error_t iphone_event_subscribe(iphone_event_cb_t callback, void *user_data);
iphone_error_t iphone_event_unsubscribe();

/* discovery (synchronous) */
iphone_error_t iphone_get_device_list(char ***devices, int *count);
iphone_error_t iphone_device_list_free(char **devices);

/* device structure creation and destruction */
iphone_error_t iphone_device_new(iphone_device_t *device, const char *uuid);
iphone_error_t iphone_device_free(iphone_device_t device);

/* connection/disconnection and communication */
iphone_error_t iphone_device_connect(iphone_device_t device, uint16_t dst_port, iphone_connection_t *connection);
iphone_error_t iphone_device_disconnect(iphone_connection_t connection);
iphone_error_t iphone_device_send(iphone_connection_t connection, const char *data, uint32_t len, uint32_t *sent_bytes);
iphone_error_t iphone_device_recv_timeout(iphone_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout);
iphone_error_t iphone_device_recv(iphone_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes);

/* misc */
iphone_error_t iphone_device_get_handle(iphone_device_t device, uint32_t *handle);
iphone_error_t iphone_device_get_uuid(iphone_device_t device, char **uuid);

#ifdef __cplusplus
}
#endif

#endif

