/*
 * iphone.h
 * iPhone struct
 * 
 * Copyright (c) 2008 Zack C. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. 
 */

#ifndef IPHONE_H
#define IPHONE_H

#ifndef USBMUX_H 
#include "usbmux.h"
#warning usbmux not included?
#endif

#include <usb.h>

#define BULKIN 0x85
#define BULKOUT 0x04

typedef struct {
	char *buffer;
	struct usb_dev_handle *device;
	struct usb_device *__device;
} iPhone;

// Function definitions
void free_iPhone(iPhone *victim);
iPhone *get_iPhone();
int send_to_phone(iPhone *phone, char *data, int datalen);
int recv_from_phone(iPhone *phone, char *data, int datalen);
#endif
