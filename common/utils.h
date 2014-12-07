/*
 * utils.h
 * Miscellaneous utilities for string manipulation
 *
 * Copyright (c) 2013 Federico Mena Quintero
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

#ifndef __UTILS_H
#define __UTILS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WIN32
#include <windows.h>
#endif

#include <stdio.h>
#include <plist/plist.h>

#ifndef HAVE_STPCPY
char *stpcpy(char *s1, const char *s2);
#endif
char *string_concat(const char *str, ...);
char *string_build_path(const char *elem, ...);
char *string_format_size(uint64_t size);
char *string_toupper(char *str);
char *generate_uuid(void);

void buffer_read_from_filename(const char *filename, char **buffer, uint64_t *length);
void buffer_write_to_filename(const char *filename, const char *buffer, uint64_t length);

enum plist_format_t {
	PLIST_FORMAT_XML,
	PLIST_FORMAT_BINARY
};

int plist_read_from_filename(plist_t *plist, const char *filename);
int plist_write_to_filename(plist_t plist, const char *filename, enum plist_format_t format);

void plist_print_to_stream(plist_t plist, FILE* stream);

#endif
