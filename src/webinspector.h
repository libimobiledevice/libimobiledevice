/*
 * webinspector.h
 * com.apple.webinspector service header file.
 * 
 * Copyright (c) 2013 Yury Melnichek All Rights Reserved.
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

#ifndef __WEBINSPECTOR_H
#define __WEBINSPECTOR_H

#include "libimobiledevice/webinspector.h"
#include "property_list_service.h"

#define WEBINSPECTOR_PARTIAL_PACKET_CHUNK_SIZE 8096

struct webinspector_client_private {
	property_list_service_client_t parent;
};

#endif
