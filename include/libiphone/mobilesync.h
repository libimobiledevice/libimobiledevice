/*
 * mobilesync.h
 *
 * Copyright (c) 2009 Martin S. All Rights Reserved.
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

#ifndef IMOBILESYNC_H
#define IMOBILESYNC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libiphone/libiphone.h>

struct mobilesync_client_int;
typedef struct mobilesync_client_int *mobilesync_client_t;

iphone_error_t mobilesync_new_client(iphone_device_t device, int dst_port,
					   mobilesync_client_t * client);
iphone_error_t mobilesync_free_client(mobilesync_client_t client);
iphone_error_t mobilesync_recv(mobilesync_client_t client, plist_t *plist);
iphone_error_t mobilesync_send(mobilesync_client_t client, plist_t plist);

#ifdef __cplusplus
}
#endif

#endif
