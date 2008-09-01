/*
 * iphone.h
 * iPhone struct
 * 
 * Copyright (c) 2008 Zach C. All Rights Reserved.
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

#ifndef IPHONE_H
#define IPHONE_H

#ifndef USBMUX_H
#include "usbmux.h"
#warning usbmux not included?
#endif

#include <usb.h>
#include <libiphone/libiphone.h>

#define BULKIN 0x85
#define BULKOUT 0x04

struct iphone_device_int {
	char *buffer;
	struct usb_dev_handle *device;
	struct usb_device *__device;
};

// Function definitions
int send_to_phone(iphone_device_t phone, char *data, int datalen);
int recv_from_phone(iphone_device_t phone, char *data, int datalen);
#endif
