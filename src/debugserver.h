/*
 * debugserver.h
 * com.apple.debugserver service header file.
 *
 * Copyright (c) 2014 Martin Szulecki All Rights Reserved.
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

#ifndef _DEBUGSERVER_H
#define _DEBUGSERVER_H

#include "libimobiledevice/debugserver.h"
#include "service.h"

#define DEBUGSERVER_CHECKSUM_HASH_LENGTH 0x3

struct debugserver_client_private {
	service_client_t parent;
	int noack_mode;
};

struct debugserver_command_private {
	char* name;
	int argc;
	char** argv;
};

#endif
