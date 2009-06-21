/*
 * iphoneinfo.c
 * Simple utility to show information about an attached device
 *
 * Copyright (c) 2009 Martin Szulecki All Rights Reserved.
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
#include <stdlib.h>

#include <libiphone/libiphone.h>

void print_usage(int argc, char **argv);
void print_lckd_request_info(iphone_lckd_client_t control, const char *domain, const char *request, const char *key);
void plist_node_to_string(plist_t *node);
void plist_children_to_string(plist_t *node);

int main(int argc, char *argv[])
{
	iphone_lckd_client_t control = NULL;
	iphone_device_t phone = NULL;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	int i;
	char uuid[41];
	uuid[0] = 0;

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			iphone_set_debug_mask(DBGMASK_ALL);
			iphone_set_debug(1);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--uuid")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) != 40)) {
				print_usage(argc, argv);
				return 0;
			}
			strcpy(uuid, argv[i]);
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
		else {
			print_usage(argc, argv);
			return 0;
		}
	}

	if (uuid[0] != 0) {
		ret = iphone_get_device_by_uuid(&phone, uuid);
		if (ret != IPHONE_E_SUCCESS) {
			printf("No device found with uuid %s, is it plugged in?\n", uuid);
			return -1;
		}
	}
	else
	{
		ret = iphone_get_device(&phone);
		if (ret != IPHONE_E_SUCCESS) {
			printf("No device found, is it plugged in?\n");
			return -1;
		}
	}

	if (IPHONE_E_SUCCESS != iphone_lckd_new_client(phone, &control)) {
		iphone_free_device(phone);
		return -1;
	}

	/* dump all information we can retrieve */
	printf("# general\n");
	print_lckd_request_info(control, NULL, "GetValue", NULL);
	print_lckd_request_info(control, "com.apple.disk_usage", "GetValue", NULL);
	print_lckd_request_info(control, "com.apple.mobile.battery", "GetValue", NULL);
	/* FIXME: For some reason lockdownd segfaults on this, works sometimes though
	print_lckd_request_info(control, "com.apple.mobile.debug", "GetValue", NULL);
	*/
	print_lckd_request_info(control, "com.apple.xcode.developerdomain", "GetValue", NULL);
	print_lckd_request_info(control, "com.apple.international", "GetValue", NULL);
	print_lckd_request_info(control, "com.apple.mobile.sync_data_class", "GetValue", NULL);
	print_lckd_request_info(control, "com.apple.iTunes", "GetValue", NULL);
	print_lckd_request_info(control, "com.apple.mobile.iTunes.store", "GetValue", NULL);
	print_lckd_request_info(control, "com.apple.mobile.iTunes", "GetValue", NULL);

	iphone_lckd_free_client(control);
	iphone_free_device(phone);

	return 0;
}

void print_usage(int argc, char **argv)
{
	printf("Usage: %s [OPTIONS]\n", (strrchr(argv[0], '/') + 1));
	printf("Show information about the first connected iPhone/iPod Touch.\n\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --uuid UUID\ttarget specific device by its 40-digit device UUID\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
}

void plist_node_to_string(plist_t *node)
{
	char *s = NULL;
	double d;
	uint8_t b;

	uint64_t u = 0;

	plist_type t;

	if (!node)
		return;

	t = plist_get_node_type(node);

	switch (t) {
	case PLIST_BOOLEAN:
		plist_get_bool_val(node, &b);
		printf("%s\n", (b ? "true" : "false"));
		break;

	case PLIST_UINT:
		plist_get_uint_val(node, &u);
		printf("%llu\n", u);
		break;

	case PLIST_REAL:
		plist_get_real_val(node, &d);
		printf("%f\n", d);
		break;

	case PLIST_STRING:
		plist_get_string_val(node, &s);
		printf("%s\n", s);
		free(s);
		break;

	case PLIST_KEY:
		plist_get_key_val(node, &s);
		printf("%s: ", s);
		free(s);
		break;

	case PLIST_DATA:
		printf("\n");
		break;
	case PLIST_DATE:
		printf("\n");
		break;
	case PLIST_ARRAY:
	case PLIST_DICT:
		printf("\n");
		plist_children_to_string(node);
		break;
	default:
		break;
	}
}

void plist_children_to_string(plist_t *node)
{
	/* iterate over key/value pairs */
	for (
		node = plist_get_first_child(node);
		node != NULL;
		node = plist_get_next_sibling(node)
	) {
		plist_node_to_string(node);
	}
}

void print_lckd_request_info(iphone_lckd_client_t control, const char *domain, const char *request, const char *key) {
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	
	plist_t node = plist_new_dict();
	if (domain) {
		plist_add_sub_key_el(node, "Domain");
		plist_add_sub_string_el(node, domain);
		printf("# %s\n", domain);
	}
	if (key) {
		plist_add_sub_key_el(node, "Key");
		plist_add_sub_string_el(node, key);
	}
	plist_add_sub_key_el(node, "Request");
	plist_add_sub_string_el(node, request);

	ret = iphone_lckd_send(control, node);
	if (ret == IPHONE_E_SUCCESS) {
		plist_free(node);
		node = NULL;
		ret = iphone_lckd_recv(control, &node);
		if (ret == IPHONE_E_SUCCESS) {
			/* seek to first dict node */
			for (
				node = plist_get_first_child(node);
				node && (plist_get_node_type(node) != PLIST_DICT);
				node = plist_get_next_sibling(node)
			) {
			}
			if(plist_get_first_child(node))
				plist_children_to_string(node);
		}
	}
	if (node)
		plist_free(node);
	node = NULL;
}

