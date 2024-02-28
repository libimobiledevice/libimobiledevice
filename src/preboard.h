/*
 * preboard.h
 * com.apple.preboard_v2 service header file.
 *
 * Copyright (c) 2019 Nikias Bassen, All Rights Reserved.
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

#ifndef __PREBOARD_H
#define __PREBOARD_H

#include "idevice.h"
#include "libimobiledevice/preboard.h"
#include "property_list_service.h"
#include <libimobiledevice-glue/thread.h>

struct preboard_client_private {
	property_list_service_client_t parent;
	THREAD_T receive_status_thread;
};

#endif
