/*
 * msyncclient.c
 * Rudimentary interface to the MobileSync iPhone
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

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <libiphone/libiphone.h>
#include <libiphone/lockdown.h>
#include <libiphone/mobilesync.h>

static mobilesync_error_t mobilesync_get_all_contacts(mobilesync_client_t client)
{
	if (!client)
		return MOBILESYNC_E_INVALID_ARG;

	mobilesync_error_t ret = MOBILESYNC_E_UNKNOWN_ERROR;
	plist_t array = NULL;

	array = plist_new_array();
	plist_array_append_item(array, plist_new_string("SDMessageSyncDataClassWithDevice"));
	plist_array_append_item(array, plist_new_string("com.apple.Contacts"));
	plist_array_append_item(array, plist_new_string("---"));
	plist_array_append_item(array, plist_new_string("2009-01-09 18:03:58 +0100"));
	plist_array_append_item(array, plist_new_uint(106));
	plist_array_append_item(array, plist_new_string("___EmptyParameterString___"));

	ret = mobilesync_send(client, array);
	plist_free(array);
	array = NULL;

	ret = mobilesync_recv(client, &array);

	plist_t rep_node = plist_find_node_by_string(array, "SDSyncTypeSlow");

	if (!rep_node)
		return ret;

	plist_free(array);
	array = NULL;

	array = plist_new_array();
	plist_array_append_item(array, plist_new_string("SDMessageGetAllRecordsFromDevice"));
	plist_array_append_item(array, plist_new_string("com.apple.Contacts"));

	ret = mobilesync_send(client, array);
	plist_free(array);
	array = NULL;

	ret = mobilesync_recv(client, &array);

	plist_t contact_node;
	plist_t switch_node;

	contact_node = plist_find_node_by_string(array, "com.apple.Contacts");
	switch_node = plist_find_node_by_string(array, "SDMessageDeviceReadyToReceiveChanges");

	while (NULL == switch_node) {

		plist_free(array);
		array = NULL;

		array = plist_new_array();
		plist_array_append_item(array, plist_new_string("SDMessageAcknowledgeChangesFromDevice"));
		plist_array_append_item(array, plist_new_string("com.apple.Contacts"));

		ret = mobilesync_send(client, array);
		plist_free(array);
		array = NULL;

		ret = mobilesync_recv(client, &array);

		contact_node = plist_find_node_by_string(array, "com.apple.Contacts");
		switch_node = plist_find_node_by_string(array, "SDMessageDeviceReadyToReceiveChanges");
	}

	array = plist_new_array();
	plist_array_append_item(array, plist_new_string("DLMessagePing"));
	plist_array_append_item(array, plist_new_string("Preparing to get changes for device"));

	ret = mobilesync_send(client, array);
	plist_free(array);
	array = NULL;

	array = plist_new_array();
	plist_array_append_item(array, plist_new_string("SDMessageProcessChanges"));
	plist_array_append_item(array, plist_new_string("com.apple.Contacts"));
	plist_array_append_item(array, plist_new_dict());
	plist_array_append_item(array, plist_new_bool(0));

	plist_t dict = plist_new_dict();
	plist_array_append_item(array, dict);
	plist_t array2 = plist_new_array();
	plist_dict_insert_item(dict, "SyncDeviceLinkEntityNamesKey", array2);
	plist_array_append_item(array2, plist_new_string("com.apple.contacts.Contact"));
	plist_array_append_item(array2, plist_new_string("com.apple.contacts.Group"));
	plist_dict_insert_item(dict, "SyncDeviceLinkAllRecordsOfPulledEntityTypeSentKey", plist_new_bool(0));

	ret = mobilesync_send(client, array);
	plist_free(array);
	array = NULL;

	ret = mobilesync_recv(client, &array);
	plist_free(array);
	array = NULL;

	return ret;
}

int main(int argc, char *argv[])
{
	int port = 0;
	lockdownd_client_t client = NULL;
	iphone_device_t phone = NULL;

	if (argc > 1 && !strcasecmp(argv[1], "--debug"))
		iphone_set_debug_mask(DBGMASK_MOBILESYNC);

	if (IPHONE_E_SUCCESS != iphone_device_new(&phone, NULL)) {
		printf("No iPhone found, is it plugged in?\n");
		return -1;
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new(phone, &client)) {
		iphone_device_free(phone);
		return -1;
	}

	lockdownd_start_service(client, "com.apple.mobilesync", &port);

	if (port) {
		mobilesync_client_t msync = NULL;
		mobilesync_client_new(phone, port, &msync);
		if (msync) {
			mobilesync_get_all_contacts(msync);
			mobilesync_client_free(msync);
		}
	} else {
		printf("Start service failure.\n");
	}

	printf("All done.\n");

	lockdownd_client_free(client);
	iphone_device_free(phone);

	return 0;
}
