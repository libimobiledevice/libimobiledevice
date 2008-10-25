/*
 * utils.c
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
#include <stdarg.h>
#include <stdio.h>
#include "utils.h"

int toto_debug = 0;

/**
 * Sets the level of debugging. Currently the only acceptable values are 0 and
 * 1.
 *
 * @param level Set to 0 for no debugging or 1 for debugging.
 */
void iphone_set_debug(int level)
{
	toto_debug = level;
}



void log_debug_msg(const char *format, ...)
{
#ifndef STRIP_DEBUG

	va_list args;
	/* run the real fprintf */
	va_start(args, format);

	if (toto_debug)
		fprintf(stderr, format, args);

	va_end(args);

#endif
}

inline void log_debug_buffer(const char *data, const int length)
{
#ifndef STRIP_DEBUG

	/* run the real fprintf */
	if (toto_debug)
		fwrite(data, 1, length, stderr);

#endif
}

inline void dump_debug_buffer(const char *file, const char *data, const int length)
{
#ifndef STRIP_DEBUG

	/* run the real fprintf */
	if (toto_debug) {
		FILE *my_ssl_packet = fopen(file, "w+");
		fwrite(data, 1, length, my_ssl_packet);
		fflush(my_ssl_packet);
		fprintf(stderr, "Wrote SSL packet to drive, too.\n");
		fclose(my_ssl_packet);
	}
#endif
}
