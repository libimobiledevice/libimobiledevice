/*
 * libiphone.h
 * Main include of libiphone
 *
 * Copyright (c) 2008 Jonathan Beck All Rights Reserved.
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

#ifndef LIBIPHONE_H
#define LIBIPHONE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <plist/plist.h>
#include <usbmuxd.h>

//general errors
#define IPHONE_E_SUCCESS                0
#define IPHONE_E_INVALID_ARG           -1
#define IPHONE_E_UNKNOWN_ERROR         -2
#define IPHONE_E_NO_DEVICE             -3
#define IPHONE_E_TIMEOUT               -4
#define IPHONE_E_NOT_ENOUGH_DATA       -5
#define IPHONE_E_BAD_HEADER            -6

//lockdownd specific error
#define IPHONE_E_INVALID_CONF          -7
#define IPHONE_E_PAIRING_FAILED        -8
#define IPHONE_E_SSL_ERROR             -9
#define IPHONE_E_PLIST_ERROR          -10
#define IPHONE_E_DICT_ERROR           -11
#define IPHONE_E_START_SERVICE_FAILED -12

//afc specific error
#define IPHONE_E_AFC_ERROR            -13

typedef int16_t iphone_error_t;

struct iphone_device_int;
typedef struct iphone_device_int *iphone_device_t;

/* Debugging */
#define DBGMASK_ALL        0xFFFF
#define DBGMASK_NONE       0x0000
#define DBGMASK_USBMUX     (1 << 1)
#define DBGMASK_LOCKDOWND  (1 << 2)
#define DBGMASK_MOBILESYNC (1 << 3)

void iphone_set_debug_mask(uint16_t mask);
void iphone_set_debug_level(int level);

//device related functions
iphone_error_t iphone_get_device(iphone_device_t *device);
iphone_error_t iphone_get_device_by_uuid(iphone_device_t *device, const char *uuid);
iphone_error_t iphone_free_device(iphone_device_t device);
uint32_t iphone_get_device_handle(iphone_device_t device);

#ifdef __cplusplus
}
#endif

#endif

