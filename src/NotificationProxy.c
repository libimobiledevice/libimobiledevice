/*
 * NotificationProxy.c
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

#include <stdio.h>
#include <plist/plist.h>
#include "NotificationProxy.h"
#include "utils.h"

/** Locks an NP client, done for thread safety stuff.
 *
 * @param client The NP
 */
static void np_lock(iphone_np_client_t client)
{
	log_debug_msg("NP: Locked\n");
	g_mutex_lock(client->mutex);
}

/** Unlocks an NP client, done for thread safety stuff.
 * 
 * @param client The NP
 */
static void np_unlock(iphone_np_client_t client)
{
	log_debug_msg("NP: Unlocked\n");
	g_mutex_unlock(client->mutex);
}

/** Makes a connection to the NP service on the phone. 
 * 
 * @param phone The iPhone to connect on.
 * @param s_port The source port. 
 * @param d_port The destination port. 
 * 
 * @return A handle to the newly-connected client or NULL upon error.
 */
iphone_error_t iphone_np_new_client(iphone_device_t device, int src_port, int dst_port, iphone_np_client_t * client)
{
	int ret = IPHONE_E_SUCCESS;

	//makes sure thread environment is available
	if (!g_thread_supported())
		g_thread_init(NULL);
	iphone_np_client_t client_loc = (iphone_np_client_t) malloc(sizeof(struct iphone_np_client_int));

	if (!device)
		return IPHONE_E_INVALID_ARG;

	// Attempt connection
	client_loc->connection = NULL;
	ret = iphone_mux_new_client(device, src_port, dst_port, &client_loc->connection);
	if (IPHONE_E_SUCCESS != ret || !client_loc->connection) {
		free(client_loc);
		return ret;
	}

	client_loc->mutex = g_mutex_new();

	*client = client_loc;
	return IPHONE_E_SUCCESS;
}

/** Disconnects an NP client from the phone.
 * 
 * @param client The client to disconnect.
 */
iphone_error_t iphone_np_free_client(iphone_np_client_t client)
{
	if (!client || !client->connection)
		return IPHONE_E_INVALID_ARG;

	iphone_mux_free_client(client->connection);
	free(client);
	return IPHONE_E_SUCCESS;
}

/** Sends a notification to the NP client.
 *
 * notification messages seen so far:
 *   com.apple.itunes-mobdev.syncWillStart
 *   com.apple.itunes-mobdev.syncDidStart
 *
 * @param client The client to send to
 * @param notification The notification Message
 */
iphone_error_t iphone_np_post_notification(iphone_np_client_t client, const char *notification)
{
	char *XML_content = NULL;
	uint32_t length = 0;
	int bytes = 0;
	iphone_error_t ret;
	unsigned char sndbuf[4096];
	int sndlen = 0;
	int nlen = 0;
	plist_t dict = NULL;

	if (!client || !notification) {
		return IPHONE_E_INVALID_ARG;
	}
	np_lock(client);

	dict = plist_new_dict();
	plist_add_sub_key_el(dict, "Command");
	plist_add_sub_string_el(dict, "PostNotification");
	plist_add_sub_key_el(dict, "Name");
	plist_add_sub_string_el(dict, notification);
	plist_to_xml(dict, &XML_content, &length);

	nlen = htonl(length);

	memcpy(sndbuf + sndlen, &nlen, 4);
	sndlen += 4;
	memcpy(sndbuf + sndlen, XML_content, length);
	sndlen += length;

	plist_free(dict);
	dict = NULL;
	free(XML_content);
	XML_content = NULL;

	dict = plist_new_dict();
	plist_add_sub_key_el(dict, "Command");
	plist_add_sub_string_el(dict, "Shutdown");
	plist_to_xml(dict, &XML_content, &length);

	nlen = htonl(length);

	memcpy(sndbuf + sndlen, &nlen, 4);
	sndlen += 4;

	memcpy(sndbuf + sndlen, XML_content, length);
	sndlen += length;

	plist_free(dict);
	dict = NULL;
	free(XML_content);
	XML_content = NULL;

	log_debug_buffer(sndbuf, sndlen);

	iphone_mux_send(client->connection, sndbuf, sndlen, &bytes);
	if (bytes <= 0) {
		np_unlock(client);
		return bytes;
	}

	np_unlock(client);
	return bytes;
}

/** Notifies the iphone to send a notification on certain events.
 *
 * observation messages seen so far:
 *   com.apple.itunes-client.syncCancelRequest
 *   com.apple.itunes-client.syncSuspendRequest
 *   com.apple.itunes-client.syncResumeRequest
 *   com.apple.mobile.lockdown.phone_number_changed
 *   com.apple.mobile.lockdown.device_name_changed
 *   com.apple.springboard.attemptactivation
 *   com.apple.mobile.data_sync.domain_changed
 *   com.apple.mobile.application_installed
 *   com.apple.mobile.application_uninstalled
 *
 * @param client The client to send to
 */
iphone_error_t iphone_np_observe_notification(iphone_np_client_t client)
{
	plist_t dict = NULL;
	char *XML_content = NULL;
	uint32_t length = 0;
	int bytes = 0;
	iphone_error_t ret;
	unsigned char sndbuf[4096];
	int sndlen = 0;
	int nlen = 0;
	int i = 0;
	const char *notifications[10] = {
		"com.apple.itunes-client.syncCancelRequest",
		"com.apple.itunes-client.syncSuspendRequest",
		"com.apple.itunes-client.syncResumeRequest",
		"com.apple.mobile.lockdown.phone_number_changed",
		"com.apple.mobile.lockdown.device_name_changed",
		"com.apple.springboard.attemptactivation",
		"com.apple.mobile.data_sync.domain_changed",
		"com.apple.mobile.application_installed",
		"com.apple.mobile.application_uninstalled",
		NULL
	};

	sndlen = 0;

	if (!client) {
		return IPHONE_E_INVALID_ARG;
	}
	np_lock(client);

	while (notifications[i]) {

		dict = plist_new_dict();
		plist_add_sub_key_el(dict, "Command");
		plist_add_sub_string_el(dict, "ObserveNotification");
		plist_add_sub_key_el(dict, "Name");
		plist_add_sub_string_el(dict, notifications[i++]);
		plist_to_xml(dict, &XML_content, &length);

		nlen = htonl(length);
		memcpy(sndbuf + sndlen, &nlen, 4);
		sndlen += 4;
		memcpy(sndbuf + sndlen, XML_content, length);
		sndlen += length;

		plist_free(dict);
		dict = NULL;
		free(XML_content);
		XML_content = NULL;
	}

	dict = plist_new_dict();
	plist_add_sub_key_el(dict, "Command");
	plist_add_sub_string_el(dict, "Shutdown");
	plist_to_xml(dict, &XML_content, &length);

	nlen = htonl(length);

	memcpy(sndbuf + sndlen, &nlen, 4);
	sndlen += 4;

	memcpy(sndbuf + sndlen, XML_content, length);
	sndlen += length;

	plist_free(dict);
	dict = NULL;
	free(XML_content);
	XML_content = NULL;

	log_debug_buffer(sndbuf, sndlen);

	iphone_mux_send(client->connection, sndbuf, sndlen, &bytes);
	if (bytes <= 0) {
		np_unlock(client);
		return bytes;
	}

	np_unlock(client);
	return bytes;
}
