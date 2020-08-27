/*
 * syslog_relay.h
 * com.apple.syslog_relay service header file.
 *
 * Copyright (c) 2013 Martin Szulecki All Rights Reserved.
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

#ifndef _SYSLOG_RELAY_H
#define _SYSLOG_RELAY_H

#include "libimobiledevice/syslog_relay.h"
#include "service.h"
#include "common/thread.h"

struct syslog_relay_client_private {
	service_client_t parent;
	THREAD_T worker;
};

void *syslog_relay_worker(void *arg);

#endif
