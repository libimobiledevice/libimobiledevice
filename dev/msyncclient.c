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
#include <usb.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <libiphone/libiphone.h>


int main(int argc, char *argv[])
{
	int bytes = 0, port = 0, i = 0;
	iphone_lckd_client_t control = NULL;
	iphone_device_t phone = NULL;

	if (argc > 1 && !strcasecmp(argv[1], "--debug"))
		iphone_set_debug_mask(DBGMASK_MOBILESYNC);


	if (IPHONE_E_SUCCESS != iphone_get_device(&phone)) {
		printf("No iPhone found, is it plugged in?\n");
		return -1;
	}

	if (IPHONE_E_SUCCESS != iphone_lckd_new_client(phone, &control)) {
		iphone_free_device(phone);
		return -1;
	}

	iphone_lckd_start_service(control, "com.apple.mobilesync", &port);

	if (port) {
		iphone_msync_client_t msync = NULL;
		iphone_msync_new_client(phone, 3432, port, &msync);
		if (msync) {
			iphone_msync_get_all_contacts(msync);
			iphone_msync_free_client(msync);
		}
	} else {
		printf("Start service failure.\n");
	}

	printf("All done.\n");

	iphone_lckd_free_client(control);
	iphone_free_device(phone);

	return 0;
}
