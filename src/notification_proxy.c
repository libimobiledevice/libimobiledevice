/*
 * notification_proxy.c
 * Notification Proxy implementation.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <plist/plist.h>

#include "notification_proxy.h"
#include "property_list_service.h"
#include "debug.h"

struct np_thread {
	np_client_t client;
	np_notify_cb_t cbfunc;
};

/** Locks an NP client, done for thread safety stuff.
 *
 * @param client The NP
 */
static void np_lock(np_client_t client)
{
	debug_info("NP: Locked");
	g_mutex_lock(client->mutex);
}

/** Unlocks an NP client, done for thread safety stuff.
 * 
 * @param client The NP
 */
static void np_unlock(np_client_t client)
{
	debug_info("NP: Unlocked");
	g_mutex_unlock(client->mutex);
}

/**
 * Convert a property_list_service_error_t value to an np_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err A property_list_service_error_t error code
 *
 * @return A matching np_error_t error code,
 *     NP_E_UNKNOWN_ERROR otherwise.
 */
static np_error_t np_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return NP_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return NP_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return NP_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return NP_E_CONN_FAILED;
		default:
			break;
	}
	return NP_E_UNKNOWN_ERROR;
}

/** Makes a connection to the NP service on the phone. 
 * 
 * @param device The device to connect to.
 * @param port Destination port (usually given by lockdownd_start_service).
 * @param client Pointer that will be set to a newly allocated np_client_t
 *    upon successful return.
 * 
 * @return NP_E_SUCCESS on success, NP_E_INVALID_ARG when device is NULL,
 *   or NP_E_CONN_FAILED when the connection to the device could not be
 *   established.
 */
np_error_t np_client_new(idevice_t device, uint16_t port, np_client_t *client)
{
	/* makes sure thread environment is available */
	if (!g_thread_supported())
		g_thread_init(NULL);

	if (!device)
		return NP_E_INVALID_ARG;

	property_list_service_client_t plistclient = NULL;
	if (property_list_service_client_new(device, port, &plistclient) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return NP_E_CONN_FAILED;
	}

	np_client_t client_loc = (np_client_t) malloc(sizeof(struct np_client_int));
	client_loc->parent = plistclient;

	client_loc->mutex = g_mutex_new();

	client_loc->notifier = NULL;

	*client = client_loc;
	return NP_E_SUCCESS;
}

/** Disconnects an NP client from the device.
 * 
 * @param client The client to disconnect.
 *
 * @return NP_E_SUCCESS on success, or NP_E_INVALID_ARG when client is NULL.
 */
np_error_t np_client_free(np_client_t client)
{
	if (!client)
		return NP_E_INVALID_ARG;

	property_list_service_client_free(client->parent);
	client->parent = NULL;
	if (client->notifier) {
		debug_info("joining np callback");
		g_thread_join(client->notifier);
	}
	if (client->mutex) {
		g_mutex_free(client->mutex);
	}
	free(client);

	return NP_E_SUCCESS;
}

/** Sends a notification to the device's Notification Proxy.
 *
 * @param client The client to send to
 * @param notification The notification message to send
 *
 * @return NP_E_SUCCESS on success, or an error returned by np_plist_send
 */
np_error_t np_post_notification(np_client_t client, const char *notification)
{
	if (!client || !notification) {
		return NP_E_INVALID_ARG;
	}
	np_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict,"Command", plist_new_string("PostNotification"));
	plist_dict_insert_item(dict,"Name", plist_new_string(notification));

	np_error_t res = np_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	dict = plist_new_dict();
	plist_dict_insert_item(dict,"Command", plist_new_string("Shutdown"));

	res = np_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != NP_E_SUCCESS) {
		debug_info("Error sending XML plist to device!");
	}

	np_unlock(client);
	return res;
}

/** Notifies the device to send a notification on the specified event.
 *
 * @param client The client to send to
 * @param notification The notifications that should be observed.
 *
 * @return NP_E_SUCCESS on success, NP_E_INVALID_ARG when client or
 *    notification are NULL, or an error returned by np_plist_send.
 */
np_error_t np_observe_notification( np_client_t client, const char *notification )
{
	if (!client || !notification) {
		return NP_E_INVALID_ARG;
	}
	np_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict,"Command", plist_new_string("ObserveNotification"));
	plist_dict_insert_item(dict,"Name", plist_new_string(notification));

	np_error_t res = np_error(property_list_service_send_xml_plist(client->parent, dict));
	if (res != NP_E_SUCCESS) {
		debug_info("Error sending XML plist to device!");
	}
	plist_free(dict);

	np_unlock(client);
	return res;
}

/** Notifies the device to send a notification on specified events.
 *
 * @param client The client to send to
 * @param notification_spec Specification of the notifications that should be
 *  observed. This is expected to be an array of const char* that MUST have a
 *  terminating NULL entry.
 *
 * @return NP_E_SUCCESS on success, NP_E_INVALID_ARG when client is null,
 *   or an error returned by np_observe_notification.
 */
np_error_t np_observe_notifications(np_client_t client, const char **notification_spec)
{
	int i = 0;
	np_error_t res = NP_E_UNKNOWN_ERROR;
	const char **notifications = notification_spec;

	if (!client) {
		return NP_E_INVALID_ARG;
	}

	if (!notifications) {
		return NP_E_INVALID_ARG;
	}

	while (notifications[i]) {
		res = np_observe_notification(client, notifications[i]);
		if (res != NP_E_SUCCESS) {
			break;
		}
		i++;
	}

	return res;
}

/**
 * Checks if a notification has been sent.
 *
 * @param client NP to get a notification from
 * @param notification Pointer to a buffer that will be allocated and filled
 *  with the notification that has been received.
 *
 * @return 0 if a notification has been received or nothing has been received,
 *         or a negative value if an error occured.
 *
 * @note You probably want to check out np_set_notify_callback
 * @see np_set_notify_callback
 */
static int np_get_notification(np_client_t client, char **notification)
{
	int res = 0;
	plist_t dict = NULL;

	if (!client || !client->parent || *notification)
		return -1;

	np_lock(client);

	property_list_service_receive_plist_with_timeout(client->parent, &dict, 500);
	if (!dict) {
		debug_info("NotificationProxy: no notification received!");
		res = 0;
	} else {
		char *cmd_value = NULL;
		plist_t cmd_value_node = plist_dict_get_item(dict, "Command");

		if (plist_get_node_type(cmd_value_node) == PLIST_STRING) {
			plist_get_string_val(cmd_value_node, &cmd_value);
		}

		if (cmd_value && !strcmp(cmd_value, "RelayNotification")) {
			char *name_value = NULL;
			plist_t name_value_node = plist_dict_get_item(dict, "Name");

			if (plist_get_node_type(name_value_node) == PLIST_STRING) {
				plist_get_string_val(name_value_node, &name_value);
			}

			res = -2;
			if (name_value_node && name_value) {
				*notification = name_value;
				debug_info("got notification %s\n", __func__, name_value);
				res = 0;
			}
		} else if (cmd_value && !strcmp(cmd_value, "ProxyDeath")) {
			debug_info("ERROR: NotificationProxy died!");
			res = -1;
		} else if (cmd_value) {
			debug_info("unknown NotificationProxy command '%s' received!", cmd_value);
			res = -1;
		} else {
			res = -2;
		}
		if (cmd_value) {
			free(cmd_value);
		}
		plist_free(dict);
		dict = NULL;
	}

	np_unlock(client);

	return res;
}

/**
 * Internally used thread function.
 */
gpointer np_notifier( gpointer arg )
{
	char *notification = NULL;
	struct np_thread *npt = (struct np_thread*)arg;

	if (!npt) return NULL;

	debug_info("starting callback.");
	while (npt->client->parent) {
		np_get_notification(npt->client, &notification);
		if (notification) {
			npt->cbfunc(notification);
			free(notification);
			notification = NULL;
		}
		sleep(1);
	}
	if (npt) {
		free(npt);
	}

	return NULL;
}

/**
 * This function allows an application to define a callback function that will
 * be called when a notification has been received.
 * It will start a thread that polls for notifications and calls the callback
 * function if a notification has been received.
 *
 * @param client the NP client
 * @param notify_cb pointer to a callback function or NULL to de-register a
 *        previously set callback function.
 *
 * @note Only one callback function can be registered at the same time;
 *       any previously set callback function will be removed automatically.
 *
 * @return NP_E_SUCCESS when the callback was successfully registered,
 *         NP_E_INVALID_ARG when client is NULL, or NP_E_UNKNOWN_ERROR when
 *         the callback thread could no be created.
 */
np_error_t np_set_notify_callback( np_client_t client, np_notify_cb_t notify_cb )
{
	if (!client)
		return NP_E_INVALID_ARG;

	np_error_t res = NP_E_UNKNOWN_ERROR;

	np_lock(client);
	if (client->notifier) {
		debug_info("callback already set, removing\n");
		property_list_service_client_t parent = client->parent;
		client->parent = NULL;
		g_thread_join(client->notifier);
		client->notifier = NULL;
		client->parent = parent;
	}

	if (notify_cb) {
		struct np_thread *npt = (struct np_thread*)malloc(sizeof(struct np_thread));
		if (npt) {
			npt->client = client;
			npt->cbfunc = notify_cb;

			client->notifier = g_thread_create(np_notifier, npt, TRUE, NULL);
			if (client->notifier) {
				res = NP_E_SUCCESS;
			}
		}
	} else {
		debug_info("no callback set");
	}
	np_unlock(client);

	return res;
}
