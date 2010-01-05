/*
 * SBServices.c
 * SpringBoard Services implementation.
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
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <plist/plist.h>

#include "SBServices.h"
#include "iphone.h"
#include "utils.h"

/** Locks an sbservices client, done for thread safety stuff.
 *
 * @param client The sbservices client to lock.
 */
static void sbs_lock(sbservices_client_t client)
{
	log_debug_msg("SBServices: Locked\n");
	g_mutex_lock(client->mutex);
}

/** Unlocks an sbservices client, done for thread safety stuff.
 * 
 * @param client The sbservices client to unlock
 */
static void sbs_unlock(sbservices_client_t client)
{
	log_debug_msg("SBServices: Unlocked\n");
	g_mutex_unlock(client->mutex);
}

sbservices_error_t sbservices_client_new(iphone_device_t device, int dst_port, sbservices_client_t *client)
{
	/* makes sure thread environment is available */
	if (!g_thread_supported())
		g_thread_init(NULL);

	if (!device)
		return SBSERVICES_E_INVALID_ARG;

	/* Attempt connection */
	iphone_connection_t connection = NULL;
	if (iphone_device_connect(device, dst_port, &connection) != IPHONE_E_SUCCESS) {
		return SBSERVICES_E_CONN_FAILED;
	}

	sbservices_client_t client_loc = (sbservices_client_t) malloc(sizeof(struct sbservices_client_int));
	client_loc->connection = connection;
	client_loc->mutex = g_mutex_new();

	*client = client_loc;
	return SBSERVICES_E_SUCCESS;
}

sbservices_error_t sbservices_client_free(sbservices_client_t client)
{
	if (!client)
		return SBSERVICES_E_INVALID_ARG;

	iphone_device_disconnect(client->connection);
	client->connection = NULL;
	if (client->mutex) {
		g_mutex_free(client->mutex);
	}
	free(client);

	return SBSERVICES_E_SUCCESS;
}

/**
 * Sends a binary plist to the device using the connection specified in client.
 * This function is only used internally.
 *
 * @param client InstallationProxy to send data to
 * @param dict plist to send
 *
 * @return SBSERVICES_E_SUCCESS on success, SBSERVICES_E_INVALID_ARG when
 *     client or dict are NULL, SBSERVICES_E_PLIST_ERROR when dict is not a
 *     valid plist, or SBSERVICES_E_UNKNOWN_ERROR when an unspecified error
 *     occurs.
 */
static sbservices_error_t sbservices_plist_send(sbservices_client_t client, plist_t dict)
{
	char *content = NULL;
	uint32_t length = 0;
	uint32_t nlen = 0;
	int bytes = 0;
	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	if (!client || !dict) {
		return SBSERVICES_E_INVALID_ARG;
	}

	plist_to_bin(dict, &content, &length);

	if (!content || length == 0) {
		return SBSERVICES_E_PLIST_ERROR;
	}

	nlen = htonl(length);
	log_debug_msg("%s: sending %d bytes\n", __func__, length);
	iphone_device_send(client->connection, (const char*)&nlen, sizeof(nlen), (uint32_t*)&bytes);
	if (bytes == sizeof(nlen)) {
		iphone_device_send(client->connection, content, length, (uint32_t*)&bytes);
		if (bytes > 0) {
			if ((uint32_t)bytes == length) {
				res = SBSERVICES_E_SUCCESS;
			} else {
				log_debug_msg("%s: ERROR: Could not send all data (%d of %d)!\n", __func__, bytes, length);
			}
		}
	}
	if (bytes <= 0) {
		log_debug_msg("%s: ERROR: sending to device failed.\n", __func__);
	}

	free(content);

	return res;
}

sbservices_error_t sbservices_get_icon_state(sbservices_client_t client, plist_t *state)
{
	if (!client || !client->connection || !state)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;
	uint32_t pktlen = 0;
	uint32_t bytes = 0;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("getIconState"));

	sbs_lock(client);

	res = sbservices_plist_send(client, dict);
	plist_free(dict);
	if (res != SBSERVICES_E_SUCCESS) {
		log_debug_msg("%s: could not send plist\n", __func__);
		goto leave_unlock;
	}

	iphone_device_recv(client->connection, (char*)&pktlen, sizeof(pktlen), &bytes);
	log_debug_msg("%s: initial read=%i\n", __func__, bytes);
	if (bytes < 4) {
		log_debug_msg("%s: initial read failed!\n");
		res = 0;
	} else {
		if ((char)pktlen == 0) {
			char *content = NULL;
			uint32_t curlen = 0;
			pktlen = ntohl(pktlen);
			log_debug_msg("%s: %d bytes following\n", __func__, pktlen);
			content = (char*)malloc(pktlen);
			log_debug_msg("pointer %p\n", content);

			while (curlen < pktlen) {
				iphone_device_recv(client->connection, content+curlen, pktlen-curlen, &bytes);
				if (bytes <= 0) {
					res = SBSERVICES_E_UNKNOWN_ERROR;
					break;
				}
				log_debug_msg("%s: received %d bytes\n", __func__, bytes);
				curlen += bytes;
			}
			log_debug_buffer(content, pktlen);
			plist_from_bin(content, pktlen, state);
			res = SBSERVICES_E_SUCCESS;
			free(content);
		} else {
			res = SBSERVICES_E_UNKNOWN_ERROR;
		}
	}

leave_unlock:
	sbs_unlock(client);
	return res;
}

sbservices_error_t sbservices_set_icon_state(sbservices_client_t client, plist_t newstate)
{
	if (!client || !client->connection || !newstate)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("setIconState"));
	plist_dict_insert_item(dict, "iconState", plist_copy(newstate));

	sbs_lock(client);

	res = sbservices_plist_send(client, dict);
	plist_free(dict);
	if (res != SBSERVICES_E_SUCCESS) {
		log_debug_msg("%s: could not send plist\n", __func__);
		goto leave_unlock;
	}
	// NO RESPONSE

leave_unlock:
	sbs_unlock(client);
	return res;
}

sbservices_error_t sbservices_get_icon_pngdata(sbservices_client_t client, const char *bundleId, char **pngdata, uint64_t *pngsize)
{
	if (!client || !client->connection || !pngdata)
		return SBSERVICES_E_INVALID_ARG;

	sbservices_error_t res = SBSERVICES_E_UNKNOWN_ERROR;
	uint32_t pktlen = 0;
	uint32_t bytes = 0;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "command", plist_new_string("getIconPNGData"));
	plist_dict_insert_item(dict, "bundleId", plist_new_string(bundleId));

	sbs_lock(client);

	res = sbservices_plist_send(client, dict);
	plist_free(dict);
	if (res != SBSERVICES_E_SUCCESS) {
		log_debug_msg("%s: could not send plist\n", __func__);
		goto leave_unlock;
	}

	iphone_device_recv(client->connection, (char*)&pktlen, sizeof(pktlen), &bytes);
	log_debug_msg("%s: initial read=%i\n", __func__, bytes);
	if (bytes < 4) {
		log_debug_msg("%s: initial read failed!\n");
		res = 0;
	} else {
		if ((char)pktlen == 0) {
			char *content = NULL;
			uint32_t curlen = 0;
			pktlen = ntohl(pktlen);
			log_debug_msg("%s: %d bytes following\n", __func__, pktlen);
			content = (char*)malloc(pktlen);
			log_debug_msg("pointer %p\n", content);

			while (curlen < pktlen) {
				iphone_device_recv(client->connection, content+curlen, pktlen-curlen, &bytes);
				if (bytes <= 0) {
					res = SBSERVICES_E_UNKNOWN_ERROR;
					break;
				}
				log_debug_msg("%s: received %d bytes\n", __func__, bytes);
				curlen += bytes;
			}
			log_debug_buffer(content, pktlen);
			plist_t pngdict = NULL;
			plist_from_bin(content, pktlen, &pngdict);
			plist_t node = plist_dict_get_item(pngdict, "pngData");
			if (node) {
				plist_get_data_val(node, pngdata, pngsize);
			}
			plist_free(pngdict);
			res = SBSERVICES_E_SUCCESS;
			free(content);
		} else {
			res = SBSERVICES_E_UNKNOWN_ERROR;
		}
	}

leave_unlock:
	sbs_unlock(client);
	return res;

}

