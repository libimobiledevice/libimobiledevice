/*
 * MobileSync.c 
 * Contains functions for the built-in MobileSync client.
 * 
 * Copyright (c) 2009 Jonathan Beck All Rights Reserved.
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

#include "MobileSync.h"
#include <plist/plist.h>
#include <string.h>

#define MSYNC_VERSION_INT1 100
#define MSYNC_VERSION_INT2 100

iphone_error_t iphone_msync_new_client(iphone_device_t device, int src_port, int dst_port,
									   iphone_msync_client_t * client)
{
	if (!device || src_port == 0 || dst_port == 0 || !client || *client)
		return IPHONE_E_INVALID_ARG;

	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	iphone_msync_client_t client_loc = (iphone_msync_client_t) malloc(sizeof(struct iphone_msync_client_int));

	// Attempt connection
	client_loc->connection = NULL;
	ret = iphone_mux_new_client(device, src_port, dst_port, &client_loc->connection);
	if (IPHONE_E_SUCCESS != ret || !client_loc->connection) {
		free(client_loc);
		return ret;
	}
	//perform handshake
	int bytes = 0;
	char *content = NULL;
	uint32_t length = 0;
	plist_t array = NULL;

	//first receive version
	ret = iphone_msync_recv(client_loc, &content, &bytes);
	log_debug_msg("Receive msg :\nsize : %i\nbuffer :\n", bytes);
	log_debug_buffer(content, bytes);
	plist_from_bin(content, bytes, &array);

	free(content);
	content = NULL;

	plist_t msg_node =
		plist_find_node(array, PLIST_STRING, "DLMessageVersionExchange", strlen("DLMessageVersionExchange"));
	plist_t ver_1 = plist_get_next_sibling(msg_node);
	plist_t ver_2 = plist_get_next_sibling(ver_1);

	plist_type ver_1_type = plist_get_node_type(ver_1);
	plist_type ver_2_type = plist_get_node_type(ver_2);

	if (PLIST_UINT == ver_1_type && PLIST_UINT == ver_2_type) {

		uint64_t ver_1_val = 0;
		uint64_t ver_2_val = 0;

		plist_get_uint_val(ver_1, &ver_1_val);
		plist_get_uint_val(ver_2, &ver_2_val);

		plist_free(array);
		array = NULL;

		if (ver_1_type == PLIST_UINT && ver_2_type == PLIST_UINT && ver_1_val == MSYNC_VERSION_INT1
			&& ver_2_val == MSYNC_VERSION_INT2) {

			array = plist_new_array();
			plist_add_sub_string_el(array, "DLMessageVersionExchange");
			plist_add_sub_string_el(array, "DLVersionsOk");

			plist_to_bin(array, &content, &length);
			log_debug_msg("Send msg :\nsize : %i\nbuffer :\n", length);
			log_debug_buffer(content, length);
			ret = iphone_msync_send(client_loc, content, length, &bytes);

			free(content);
			content = NULL;
			plist_free(array);
			array = NULL;

			ret = iphone_msync_recv(client_loc, &content, &bytes);
			log_debug_msg("Receive msg :\nsize : %i\nbuffer :\n", bytes);
			log_debug_buffer(content, bytes);
			plist_from_bin(content, bytes, &array);

			free(content);
			content = NULL;

			plist_t rep_node =
				plist_find_node(array, PLIST_STRING, "DLMessageDeviceReady", strlen("DLMessageDeviceReady"));

			if (rep_node) {
				ret = IPHONE_E_SUCCESS;
				*client = client_loc;
			}
		}
	}

	if (IPHONE_E_SUCCESS != ret)
		iphone_msync_free_client(client_loc);

	return ret;
}

static void iphone_msync_stop_session(iphone_msync_client_t client)
{
	if (!client)
		return;

	int bytes = 0;
	char *content = NULL;
	uint32_t length = 0;

	plist_t array = plist_new_array();
	plist_add_sub_string_el(array, "DLMessageDisconnect");
	plist_add_sub_string_el(array, "All done, thanks for the memories");

	plist_to_bin(array, &content, &length);
	log_debug_msg("Send msg :\nsize : %i\nbuffer :\n", length);
	log_debug_buffer(content, length);
	iphone_msync_send(client, content, length, &bytes);

	free(content);
	content = NULL;
	plist_free(array);
	array = NULL;
}

void iphone_msync_free_client(iphone_msync_client_t client)
{
	iphone_msync_stop_session(client);

	iphone_mux_free_client(client->connection);
}

/** Polls the iPhone for MobileSync data.
 *
 * @param client The MobileSync client
 * @param dump_data The pointer to the location of the buffer in which to store
 *                  the received data
 * @param recv_byhtes The number of bytes received
 *
 * @return an error code
 */
iphone_error_t iphone_msync_recv(iphone_msync_client_t client, char **dump_data, uint32_t * recv_bytes)
{
	if (!client || !dump_data || !recv_bytes)
		return IPHONE_E_INVALID_ARG;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	char *receive;
	uint32_t datalen = 0, bytes = 0;

	ret = iphone_mux_recv(client->connection, (char *) &datalen, sizeof(datalen), &bytes);
	datalen = ntohl(datalen);

	receive = (char *) malloc(sizeof(char) * datalen);
	ret = iphone_mux_recv(client->connection, receive, datalen, &bytes);

	*dump_data = receive;
	*recv_bytes = bytes;
	return ret;
}

/** Sends MobileSync data to the iPhone
 * 
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The MobileSync client
 * @param raw_data The null terminated string buffer to send
 * @param length The length of data to send
 * @param sent_bytes The number of bytes sent
 *
 * @return an error code
 */
iphone_error_t iphone_msync_send(iphone_msync_client_t client, char *raw_data, uint32_t length, uint32_t * sent_bytes)
{
	if (!client || !raw_data || length == 0 || !sent_bytes)
		return IPHONE_E_INVALID_ARG;
	char *real_query;
	int bytes;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	real_query = (char *) malloc(sizeof(char) * (length + 4));
	length = htonl(length);
	memcpy(real_query, &length, sizeof(length));
	memcpy(real_query + 4, raw_data, ntohl(length));

	ret = iphone_mux_send(client->connection, real_query, ntohl(length) + sizeof(length), &bytes);
	free(real_query);
	*sent_bytes = bytes;
	return ret;
}

