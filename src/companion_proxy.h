/*
 * companion_proxy.h
 * com.apple.companion_proxy service header file.
 *
 * Copyright (c) 2019-2020 Nikias Bassen, All Rights Reserved.
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

#ifndef __COMPANION_PROXY_H
#define __COMPANION_PROXY_H

#include "idevice.h"
#include "libimobiledevice/companion_proxy.h"
#include "property_list_service.h"
#include <libimobiledevice-glue/thread.h>

struct companion_proxy_client_private {
	property_list_service_client_t parent;
	THREAD_T event_thread;
};

#endif
