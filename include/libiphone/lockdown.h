/*
 * lockdownd.h
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

#ifndef LOCKDOWN_H
#define LOCKDOWN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libiphone/libiphone.h>

struct lockdownd_client_int;
typedef struct lockdownd_client_int *lockdownd_client_t;

//lockdownd related functions
iphone_error_t lockdownd_new_client (iphone_device_t device, lockdownd_client_t *client);
iphone_error_t lockdownd_free_client(lockdownd_client_t client);
iphone_error_t lockdownd_query_type(lockdownd_client_t client);
iphone_error_t lockdownd_get_value(lockdownd_client_t client, const char *domain, const char *key, plist_t *value_node);
iphone_error_t lockdownd_start_service (lockdownd_client_t client, const char *service, int *port);
iphone_error_t lockdownd_stop_session(lockdownd_client_t client);
iphone_error_t lockdownd_send (lockdownd_client_t client, plist_t plist);
iphone_error_t lockdownd_recv (lockdownd_client_t client, plist_t *plist);
iphone_error_t lockdownd_pair(lockdownd_client_t client, char *uid, char *host_id);
iphone_error_t lockdownd_get_device_uid (lockdownd_client_t control, char **uid);
iphone_error_t lockdownd_get_device_name (lockdownd_client_t client, char **device_name);
iphone_error_t lockdownd_goodbye(lockdownd_client_t client);

#ifdef __cplusplus
}
#endif

#endif
