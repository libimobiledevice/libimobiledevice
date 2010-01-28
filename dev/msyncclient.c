/*
 * msyncclient.c
 * Rudimentary interface to the MobileSync service.
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

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/mobilesync.h>

static char check_string(plist_t node, char* string)
{
	char ret = 1;
	char* msg = NULL;
	plist_type type = plist_get_node_type(node);
	if (PLIST_STRING == type) {
		plist_get_string_val(node, &msg);
	}
	if (PLIST_STRING != type || strcmp(msg, string)) {
		printf("%s: ERROR: MobileSync client did not find %s !\n", __func__, string);
		ret = 0;
	}
	free(msg);
	msg = NULL;
	return ret;
}

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

	ret = mobilesync_receive(client, &array);

	plist_free(array);
	array = NULL;

	array = plist_new_array();
	plist_array_append_item(array, plist_new_string("SDMessageGetAllRecordsFromDevice"));
	plist_array_append_item(array, plist_new_string("com.apple.Contacts"));

	ret = mobilesync_send(client, array);
	plist_free(array);
	array = NULL;

	ret = mobilesync_receive(client, &array);

	plist_t contact_node;
	plist_t switch_node;

	contact_node = plist_array_get_item(array, 0);
	switch_node = plist_array_get_item(array, 0);

	while (NULL == switch_node
	    && check_string(contact_node, "com.apple.Contacts")
	    && check_string(switch_node, "SDMessageDeviceReadyToReceiveChanges")) {

		plist_free(array);
		array = NULL;

		array = plist_new_array();
		plist_array_append_item(array, plist_new_string("SDMessageAcknowledgeChangesFromDevice"));
		plist_array_append_item(array, plist_new_string("com.apple.Contacts"));

		ret = mobilesync_send(client, array);
		plist_free(array);
		array = NULL;

		ret = mobilesync_receive(client, &array);

		contact_node = plist_array_get_item(array, 0);
		switch_node = plist_array_get_item(array, 0);
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

	ret = mobilesync_receive(client, &array);
	plist_free(array);
	array = NULL;

	return ret;
}

int main(int argc, char *argv[])
{
	uint16_t port = 0;
	lockdownd_client_t client = NULL;
	idevice_t phone = NULL;

	if (argc > 1 && !strcasecmp(argv[1], "--debug"))
		idevice_set_debug_level(1);

	if (IDEVICE_E_SUCCESS != idevice_new(&phone, NULL)) {
		printf("No device found, is it plugged in?\n");
		return -1;
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(phone, &client, "msyncclient")) {
		idevice_free(phone);
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
	idevice_free(phone);

	return 0;
}
