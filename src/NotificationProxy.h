/*
 * NotificationProxy.h
 * Notification Proxy header file.
 *
 * Copyright (c) 2009 Nikias Bassen, All Rights Reserved.
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
#include "libiphone/notification_proxy.h"

#include <glib.h>

struct np_client_int {
	int sfd;
	GMutex *mutex;
	GThread *notifier;
};

static const char *np_default_notifications[11] = {
	NP_SYNC_SUSPEND_REQUEST,
	NP_SYNC_RESUME_REQUEST,
	NP_PHONE_NUMBER_CHANGED,
	NP_SYNC_CANCEL_REQUEST,
	NP_DEVICE_NAME_CHANGED,
	NP_ATTEMPTACTIVATION,
	NP_DS_DOMAIN_CHANGED,
	NP_APP_INSTALLED,
	NP_APP_UNINSTALLED,
	NP_ITDBPREP_DID_END,
	NULL
};

gpointer np_notifier( gpointer arg );
