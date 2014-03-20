/*
 * utils.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"

#ifndef HAVE_STPCPY
/**
 * Copy characters from one string into another
 *
 * @note: The strings should not overlap, as the behavior is undefined.
 *
 * @s1: The source string.
 * @s2: The destination string.
 *
 * @return a pointer to the terminating `\0' character of @s1,
 * or NULL if @s1 or @s2 is NULL.
 */
char *stpcpy(char * s1, const char * s2)
{
	if (s1 == NULL || s2 == NULL)
		return NULL;

	strcpy(s1, s2);

	return s1 + strlen(s2);
}
#endif

/**
 * Concatenate strings into a newly allocated string
 *
 * @note: Specify NULL for the last string in the varargs list
 *
 * @str: The first string in the list
 * @...: Subsequent strings.  Use NULL for the last item.
 *
 * @return a newly allocated string, or NULL if @str is NULL.  This will also
 * return NULL and set errno to ENOMEM if memory is exhausted.
 */
char *string_concat(const char *str, ...)
{
	size_t len;
	va_list args;
	char *s;
	char *result;
	char *dest;

	if (!str)
		return NULL;

	/* Compute final length */

	len = strlen(str) + 1; /* plus 1 for the null terminator */

	va_start(args, str);
	s = va_arg(args, char *);
	while (s) {
		len += strlen(s);
		s = va_arg(args, char*);
	}
	va_end(args);

	/* Concat each string */

	result = malloc(len);
	if (!result)
		return NULL; /* errno remains set */

	dest = result;

	dest = stpcpy(dest, str);

	va_start(args, str);
	s = va_arg(args, char *);
	while (s) {
		dest = stpcpy(dest, s);
		s = va_arg(args, char *);
	}
	va_end(args);

	return result;
}

static int get_rand(int min, int max)
{
	int retval = (rand() % (max - min)) + min;
	return retval;
}

char *generate_uuid()
{
	const char *chars = "ABCDEF0123456789";
	int i = 0;
	char *uuid = (char *) malloc(sizeof(char) * 37);

	srand(time(NULL));

	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			uuid[i] = '-';
			continue;
		} else {
			uuid[i] = chars[get_rand(0, 16)];
		}
	}

	/* make it a real string */
	uuid[36] = '\0';

	return uuid;
}

void buffer_read_from_filename(const char *filename, char **buffer, uint64_t *length)
{
	FILE *f;
	uint64_t size;

	*length = 0;

	f = fopen(filename, "rb");
	if (!f) {
		return;
	}

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	rewind(f);

	if (size == 0) {
		fclose(f);
		return;
	}

	*buffer = (char*)malloc(sizeof(char)*(size+1));
	fread(*buffer, sizeof(char), size, f);
	fclose(f);

	*length = size;
}

void buffer_write_to_filename(const char *filename, const char *buffer, uint64_t length)
{
	FILE *f;

	f = fopen(filename, "wb");
	if (f) {
		fwrite(buffer, sizeof(char), length, f);
		fclose(f);
	}
}

int plist_read_from_filename(plist_t *plist, const char *filename)
{
	char *buffer = NULL;
	uint64_t length;

	if (!filename)
		return 0;

	buffer_read_from_filename(filename, &buffer, &length);

	if (!buffer) {
		return 0;
	}

	if ((length > 8) && (memcmp(buffer, "bplist00", 8) == 0)) {
		plist_from_bin(buffer, length, plist);
	} else {
		plist_from_xml(buffer, length, plist);
	}

	free(buffer);

	return 1;
}

int plist_write_to_filename(plist_t plist, const char *filename, enum plist_format_t format)
{
	char *buffer = NULL;
	uint32_t length;

	if (!plist || !filename)
		return 0;

	if (format == PLIST_FORMAT_XML)
		plist_to_xml(plist, &buffer, &length);
	else if (format == PLIST_FORMAT_BINARY)
		plist_to_bin(plist, &buffer, &length);
	else
		return 0;

	buffer_write_to_filename(filename, buffer, length);

	free(buffer);

	return 1;
}
