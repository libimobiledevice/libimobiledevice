/*
 * house_arrest.h
 * com.apple.mobile.house_arrest service header file.
 *
 * Copyright (c) 2010 Nikias Bassen, All Rights Reserved.
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

#ifndef __HOUSE_ARREST_H
#define __HOUSE_ARREST_H

#include "libimobiledevice/house_arrest.h"
#include "property_list_service.h"

enum house_arrest_client_mode {
	HOUSE_ARREST_CLIENT_MODE_NORMAL = 0,
	HOUSE_ARREST_CLIENT_MODE_AFC,
};

struct house_arrest_client_private {
	property_list_service_client_t parent;
	enum house_arrest_client_mode mode;
};

#endif
