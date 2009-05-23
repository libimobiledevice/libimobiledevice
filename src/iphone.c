/* 
 * iphone.c
 * Functions for creating and initializing iPhone structures.
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

#include "iphone.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libiphone/libiphone.h>

/**
 * Retrieves a list of connected devices from usbmuxd and matches their
 * UUID with the given UUID. If the given UUID is NULL then the first
 * device reported by usbmuxd is used.
 *
 * @param device Upon calling this function, a pointer to a location of type
 *  iphone_device_t, which must have the value NULL. On return, this location
 *  will be filled with a handle to the device.
 * @param uuid The UUID to match.
 *
 * @return IPHONE_E_SUCCESS if ok, otherwise an error code.
 */
iphone_error_t iphone_get_device_by_uuid(iphone_device_t * device, const char *uuid)
{
	iphone_device_t phone;
	uint32_t handle = 0;
	char *serial_number = malloc(41);
	usbmuxd_scan_result *dev_list = NULL;
	int i;

	if (usbmuxd_scan(&dev_list) < 0) {
		log_debug_msg("%s: usbmuxd_scan returned an error, is usbmuxd running?\n", __func__);
	}
	if (dev_list && dev_list[0].handle > 0) {
		if (!uuid) {
			// select first device found if no UUID specified
			handle = dev_list[0].handle;
			strcpy(serial_number, dev_list[0].serial_number);
		} else {
			// otherwise walk through the list
			for (i = 0; dev_list[i].handle > 0; i++) {
				log_debug_msg("%s: device handle=%d, uuid=%s\n", __func__, dev_list[i].handle, dev_list[i].serial_number);
				if (strcasecmp(uuid, dev_list[i].serial_number) == 0) {
					handle = dev_list[i].handle;
					strcpy(serial_number, dev_list[i].serial_number);
					break;
				}
			}
		}
		free(dev_list);

		if (handle > 0) {
			phone = (iphone_device_t) malloc(sizeof(struct iphone_device_int));
			phone->handle = handle;
			phone->serial_number = serial_number;
			*device = phone;
			return IPHONE_E_SUCCESS;
		}
	}

	return IPHONE_E_NO_DEVICE;
}

/**
 * This function has the purpose to retrieve a handle to the first
 *  attached iPhone/iPod reported by usbmuxd.
 *
 * @param Upon calling this function, a pointer to a location of type
 *  iphone_device_t, which must have the value NULL. On return, this location
 *  will be filled with a handle to the device.
 *
 * @return IPHONE_E_SUCCESS if ok, otherwise an error code.
 */
iphone_error_t iphone_get_device(iphone_device_t * device)
{
	return iphone_get_device_by_uuid(device, NULL);
}

uint32_t iphone_get_device_handle(iphone_device_t device)
{
	if (device) {
		return device->handle;
	} else {
		return 0;
	}
}

char* iphone_get_uuid(iphone_device_t device)
{
	if (device) {
		return device->serial_number;
	} else {
		return NULL;
	}
}

/** Cleans up an iPhone structure, then frees the structure itself.  
 * This is a library-level function; deals directly with the iPhone to tear
 *  down relations, but otherwise is mostly internal.
 * 
 * @param phone A pointer to an iPhone structure.
 */
iphone_error_t iphone_free_device(iphone_device_t device)
{
	if (!device)
		return IPHONE_E_INVALID_ARG;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	ret = IPHONE_E_SUCCESS;

	free(device->serial_number);
	free(device);
	return ret;
}

