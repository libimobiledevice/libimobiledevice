/*
 * mobile_image_mounter.h
 * com.apple.mobile.mobile_image_mounter service header file.
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

#ifndef __MOBILE_IMAGE_MOUNTER_H
#define __MOBILE_IMAGE_MOUNTER_H

#include "idevice.h"
#include "libimobiledevice/mobile_image_mounter.h"
#include "property_list_service.h"
#include <libimobiledevice-glue/thread.h>

struct mobile_image_mounter_client_private {
	property_list_service_client_t parent;
	mutex_t mutex;
};

#endif
