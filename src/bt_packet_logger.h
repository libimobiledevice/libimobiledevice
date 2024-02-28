/*
 * bt_packet_logger.h
 * com.apple.bluetooth.BTPacketLogger service header file.
 *
 * Copyright (c) 2021 Geoffrey Kruse, All Rights Reserved.
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

#ifndef _BR_PACKET_LOGGER_H
#define _BR_PACKET_LOGGER_H

#include "idevice.h"
#include "libimobiledevice/bt_packet_logger.h"
#include "service.h"
#include <libimobiledevice-glue/thread.h>

struct bt_packet_logger_client_private {
	service_client_t parent;
	THREAD_T worker;
};

void *bt_packet_logger_worker(void *arg);

#endif
