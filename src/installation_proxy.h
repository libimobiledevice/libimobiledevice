/*
 * installation_proxy.h
 * com.apple.mobile.installation_proxy service header file.
 *
 * Copyright (c) 2010-2015 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2010-2013 Nikias Bassen, All Rights Reserved.
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

#ifndef __INSTALLATION_PROXY_H
#define __INSTALLATION_PROXY_H

#include "libimobiledevice/installation_proxy.h"
#include "property_list_service.h"
#include "common/thread.h"

struct instproxy_client_private {
	property_list_service_client_t parent;
	mutex_t mutex;
	thread_t receive_status_thread;
};

#endif
