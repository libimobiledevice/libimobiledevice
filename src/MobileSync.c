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
#include <stdlib.h>
#include <arpa/inet.h>


#define MSYNC_VERSION_INT1 100
#define MSYNC_VERSION_INT2 100

iphone_error_t iphone_msync_new_client(iphone_device_t device, int dst_port,
									   iphone_msync_client_t * client)
{
	if (!device || dst_port == 0 || !client || *client)
		return IPHONE_E_INVALID_ARG;

	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	// Attempt connection
	int sfd = usbmuxd_connect(device->handle, dst_port);
	if (sfd < 0) {
		return ret;
	}

	iphone_msync_client_t client_loc = (iphone_msync_client_t) malloc(sizeof(struct iphone_msync_client_int));
	client_loc->sfd = sfd;

	//perform handshake
	plist_t array = NULL;

	//first receive version
	ret = iphone_msync_recv(client_loc, &array);

	plist_t msg_node = plist_find_node_by_string(array, "DLMessageVersionExchange");
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

			ret = iphone_msync_send(client_loc, array);

			plist_free(array);
			array = NULL;

			ret = iphone_msync_recv(client_loc, &array);
			plist_t rep_node = plist_find_node_by_string(array, "DLMessageDeviceReady");

			if (rep_node) {
				ret = IPHONE_E_SUCCESS;
				*client = client_loc;
			}
			plist_free(array);
			array = NULL;

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

	plist_t array = plist_new_array();
	plist_add_sub_string_el(array, "DLMessageDisconnect");
	plist_add_sub_string_el(array, "All done, thanks for the memories");

	iphone_msync_send(client, array);
	plist_free(array);
	array = NULL;
}

iphone_error_t iphone_msync_free_client(iphone_msync_client_t client)
{
	if (!client)
		return IPHONE_E_INVALID_ARG;

	iphone_msync_stop_session(client);
	return usbmuxd_disconnect(client->sfd);
}

/** Polls the iPhone for MobileSync data.
 *
 * @param client The MobileSync client
 * @param plist A pointer to the location where the plist should be stored
 *
 * @return an error code
 */
iphone_error_t iphone_msync_recv(iphone_msync_client_t client, plist_t * plist)
{
	if (!client || !plist || (plist && *plist))
		return IPHONE_E_INVALID_ARG;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	char *receive = NULL;
	uint32_t datalen = 0, bytes = 0, received_bytes = 0;

	ret = usbmuxd_recv(client->sfd, (char *) &datalen, sizeof(datalen), &bytes);
	datalen = ntohl(datalen);

	receive = (char *) malloc(sizeof(char) * datalen);

	/* fill buffer and request more packets if needed */
	while ((received_bytes < datalen) && (ret == IPHONE_E_SUCCESS)) {
		ret = usbmuxd_recv(client->sfd, receive + received_bytes, datalen - received_bytes, &bytes);
		received_bytes += bytes;
	}

	if (ret != IPHONE_E_SUCCESS) {
		free(receive);
		return ret;
	}

	plist_from_bin(receive, received_bytes, plist);
	free(receive);

	char *XMLContent = NULL;
	uint32_t length = 0;
	plist_to_xml(*plist, &XMLContent, &length);
	log_dbg_msg(DBGMASK_MOBILESYNC, "Recv msg :\nsize : %i\nbuffer :\n%s\n", length, XMLContent);
	free(XMLContent);

	return ret;
}

/** Sends MobileSync data to the iPhone
 * 
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The MobileSync client
 * @param plist The location of the plist to send
 *
 * @return an error code
 */
iphone_error_t iphone_msync_send(iphone_msync_client_t client, plist_t plist)
{
	if (!client || !plist)
		return IPHONE_E_INVALID_ARG;

	char *XMLContent = NULL;
	uint32_t length = 0;
	plist_to_xml(plist, &XMLContent, &length);
	log_dbg_msg(DBGMASK_MOBILESYNC, "Send msg :\nsize : %i\nbuffer :\n%s\n", length, XMLContent);
	free(XMLContent);

	char *content = NULL;
	length = 0;

	plist_to_bin(plist, &content, &length);

	char *real_query;
	int bytes;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	real_query = (char *) malloc(sizeof(char) * (length + 4));
	length = htonl(length);
	memcpy(real_query, &length, sizeof(length));
	memcpy(real_query + 4, content, ntohl(length));

	ret = usbmuxd_send(client->sfd, real_query, ntohl(length) + sizeof(length), (uint32_t*)&bytes);
	free(real_query);
	return ret;
}

iphone_error_t iphone_msync_get_all_contacts(iphone_msync_client_t client)
{
	if (!client)
		return IPHONE_E_INVALID_ARG;

	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	plist_t array = NULL;

	array = plist_new_array();
	plist_add_sub_string_el(array, "SDMessageSyncDataClassWithDevice");
	plist_add_sub_string_el(array, "com.apple.Contacts");
	plist_add_sub_string_el(array, "---");
	plist_add_sub_string_el(array, "2009-01-09 18:03:58 +0100");
	plist_add_sub_uint_el(array, 106);
	plist_add_sub_string_el(array, "___EmptyParameterString___");

	ret = iphone_msync_send(client, array);
	plist_free(array);
	array = NULL;

	ret = iphone_msync_recv(client, &array);

	plist_t rep_node = plist_find_node_by_string(array, "SDSyncTypeSlow");

	if (!rep_node)
		return ret;

	plist_free(array);
	array = NULL;

	array = plist_new_array();
	plist_add_sub_string_el(array, "SDMessageGetAllRecordsFromDevice");
	plist_add_sub_string_el(array, "com.apple.Contacts");


	ret = iphone_msync_send(client, array);
	plist_free(array);
	array = NULL;

	ret = iphone_msync_recv(client, &array);

	plist_t contact_node;
	plist_t switch_node;

	contact_node = plist_find_node_by_string(array, "com.apple.Contacts");
	switch_node = plist_find_node_by_string(array, "SDMessageDeviceReadyToReceiveChanges");

	while (NULL == switch_node) {

		plist_free(array);
		array = NULL;

		array = plist_new_array();
		plist_add_sub_string_el(array, "SDMessageAcknowledgeChangesFromDevice");
		plist_add_sub_string_el(array, "com.apple.Contacts");

		ret = iphone_msync_send(client, array);
		plist_free(array);
		array = NULL;

		ret = iphone_msync_recv(client, &array);

		contact_node = plist_find_node_by_string(array, "com.apple.Contacts");
		switch_node = plist_find_node_by_string(array, "SDMessageDeviceReadyToReceiveChanges");
	}

	array = plist_new_array();
	plist_add_sub_string_el(array, "DLMessagePing");
	plist_add_sub_string_el(array, "Preparing to get changes for device");

	ret = iphone_msync_send(client, array);
	plist_free(array);
	array = NULL;

	array = plist_new_array();
	plist_add_sub_string_el(array, "SDMessageProcessChanges");
	plist_add_sub_string_el(array, "com.apple.Contacts");
	plist_add_sub_node(array, plist_new_dict());
	plist_add_sub_bool_el(array, 0);
	plist_t dict = plist_new_dict();
	plist_add_sub_node(array, dict);
	plist_add_sub_key_el(dict, "SyncDeviceLinkEntityNamesKey");
	plist_t array2 = plist_new_array();
	plist_add_sub_string_el(array2, "com.apple.contacts.Contact");
	plist_add_sub_string_el(array2, "com.apple.contacts.Group");
	plist_add_sub_key_el(dict, "SyncDeviceLinkAllRecordsOfPulledEntityTypeSentKey");
	plist_add_sub_bool_el(dict, 0);

	ret = iphone_msync_send(client, array);
	plist_free(array);
	array = NULL;

	ret = iphone_msync_recv(client, &array);
	plist_free(array);
	array = NULL;


	return ret;
}
