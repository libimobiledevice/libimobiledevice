/*
 * debug.h
 * contains utilitary functions for debugging
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

#ifndef DEBUG_H
#define DEBUG_H

#include <glib.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L && !defined(STRIP_DEBUG_CODE)
#define debug_info(...) debug_info_real (__func__, __FILE__, __LINE__, __VA_ARGS__)
#elif defined(__GNUC__) && __GNUC__ >= 3 && !defined(STRIP_DEBUG_CODE)
#define debug_info(...) debug_info_real (__FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#else
#define debug_info(...)
#endif

G_GNUC_INTERNAL inline void debug_info_real(const char *func,
											const char *file,
											int	line,
											const char *format, ...);

G_GNUC_INTERNAL inline void debug_buffer(const char *data, const int length);
G_GNUC_INTERNAL inline void debug_buffer_to_file(const char *file, const char *data, const int length);

#endif
