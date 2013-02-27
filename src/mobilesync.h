/* 
 * mobilesync.h
 * Definitions for the built-in MobileSync client
 * 
 * Copyright (c) 2010 Bryan Forbes All Rights Reserved.
 * Copyright (c) 2009 Jonathan Beck All Rights Reserved.
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

#ifndef __MOBILESYNC_H
#define __MOBILESYNC_H

#include "libimobiledevice/mobilesync.h"
#include "device_link_service.h"

typedef enum {
	MOBILESYNC_SYNC_DIR_DEVICE_TO_COMPUTER,
	MOBILESYNC_SYNC_DIR_COMPUTER_TO_DEVICE
} mobilesync_sync_direction_t;

struct mobilesync_client_private {
	device_link_service_client_t parent;
	mobilesync_sync_direction_t direction;
	char *data_class;
};

#endif
