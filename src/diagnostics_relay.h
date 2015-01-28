/*
 * diagnostics_relay.h
 * com.apple.mobile.diagnostics_relay service header file.
 *
 * Copyright (c) 2012 Martin Szulecki, All Rights Reserved.
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

#ifndef __DIAGNOSTICS_RELAY_H
#define __DIAGNOSTICS_RELAY_H

#include "libimobiledevice/diagnostics_relay.h"
#include "property_list_service.h"

struct diagnostics_relay_client_private {
	property_list_service_client_t parent;
};

#endif
