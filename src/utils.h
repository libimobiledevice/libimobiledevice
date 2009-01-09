/*
 * utils.h
 * contains utilitary methos for logging and debugging
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

#ifndef UTILS_H
#define UTILS_H

#include "libiphone/libiphone.h"

#define DBGMASK_USBMUX     (1 << 1)
#define DBGMASK_LOCKDOWND  (1 << 2)
#define DBGMASK_MOBILESYNC (1 << 3)

void iphone_set_debug_mask(uint16_t mask);

inline void log_debug_msg(const char *format, ...);
inline void log_dbg_msg(uint16_t id, const char *format, ...);

inline void log_debug_buffer(const char *data, const int length);
inline void dump_debug_buffer(const char *file, const char *data, const int length);
#endif
