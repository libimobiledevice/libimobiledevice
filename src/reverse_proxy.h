/*
 * reverse_proxy.h
 * com.apple.PurpleReverseProxy service header file.
 *
 * Copyright (c) 2021 Nikias Bassen, All Rights Reserved.
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

#ifndef __REVERSE_PROXY_H
#define __REVERSE_PROXY_H

#include "idevice.h"
#include "libimobiledevice/reverse_proxy.h"
#include "service.h"

struct reverse_proxy_client_private {
	service_client_t parent;
	char* label;
	int type;
	int protoversion;
	THREAD_T th_ctrl;
	uint16_t conn_port;
	reverse_proxy_log_cb_t log_cb;
	void* log_cb_user_data;
	reverse_proxy_data_cb_t data_cb;
	void* data_cb_user_data;
	reverse_proxy_status_cb_t status_cb;
	void* status_cb_user_data;
};

reverse_proxy_error_t reverse_proxy_send(reverse_proxy_client_t client, const char* data, uint32_t len, uint32_t* sent);
reverse_proxy_error_t reverse_proxy_receive(reverse_proxy_client_t client, char* buffer, uint32_t len, uint32_t* received);
reverse_proxy_error_t reverse_proxy_receive_with_timeout(reverse_proxy_client_t client, char* buffer, uint32_t len, uint32_t* received, unsigned int timeout);
reverse_proxy_error_t reverse_proxy_send_plist(reverse_proxy_client_t client, plist_t plist);
reverse_proxy_error_t reverse_proxy_receive_plist(reverse_proxy_client_t client, plist_t* plist);
reverse_proxy_error_t reverse_proxy_receive_plist_with_timeout(reverse_proxy_client_t client, plist_t * plist, uint32_t timeout_ms);

#endif
