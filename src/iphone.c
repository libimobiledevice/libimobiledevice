/* 
 * iphone.c
 * Functions for creating and initializing iPhone structures.
 *
 * Copyright (c) 2008 Zach C. All Rights Reserved.
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

#include "usbmux.h"
#include "iphone.h"
#include <arpa/inet.h>
#include <usb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int debug; 

/** Gets a handle to an iPhone
 * 
 * @return A structure with data on the first iPhone it finds.  (Or NULL, on
 *         error)
 */
int  iphone_get_device ( iphone_device_t *device  ){
	//check we can actually write in device
	if (!device || (device && *device))
		return IPHONE_E_INVALID_ARG;

	struct usb_bus *bus, *busses;
	struct usb_device *dev;
	iphone_device_t phone = (iphone_device_t)malloc(sizeof(struct iphone_device_int));
	
	// Initialize the struct
	phone->device = NULL;
	phone->__device = NULL;
        phone->buffer = NULL;
	
	// Initialize libusb
	usb_init();
	usb_find_busses();
	usb_find_devices();
	busses = usb_get_busses();

	
	// Set the device configuration
	for (bus = busses; bus; bus = bus->next) { 
		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->descriptor.idVendor == 0x05ac && 
				(dev->descriptor.idProduct == 0x1290 ||
				 dev->descriptor.idProduct == 0x1291 ||
				 dev->descriptor.idProduct == 0x1292
				)
			    ) {
				phone->__device = dev;
				phone->device = usb_open(phone->__device);
				usb_set_configuration(phone->device, 3);
				usb_claim_interface(phone->device, 1);
				break;
			}
		}
		if (phone->__device && phone->device) break;
	}
	
	// Check to see if we are connected
	if (!phone->device || !phone->__device) {
		iphone_free_device(phone);
		if (debug) fprintf(stderr, "get_iPhone(): iPhone not found\n");
		return IPHONE_E_NO_DEVICE;
	}

	// Send the version command to the phone
	int bytes = 0;
	usbmux_version_header *version = version_header();
	bytes = usb_bulk_write(phone->device, BULKOUT, (char*)version, sizeof(*version), 800);
	if (bytes < 20 && debug) {
		fprintf(stderr, "get_iPhone(): libusb did NOT send enough!\n");
		if (bytes < 0) {
			fprintf(stderr, "get_iPhone(): libusb gave me the error %d: %s (%s)\n",
					bytes, usb_strerror(), strerror(-bytes));
		}
	}

	// Read the phone's response
	bytes = usb_bulk_read(phone->device, BULKIN, (char*)version, sizeof(*version), 800);
	
	// Check for bad response
	if (bytes < 20) {
		free(version);
		iphone_free_device(phone);
		if (debug) fprintf(stderr, "get_iPhone(): Invalid version message -- header too short.\n");
		if (debug && bytes < 0) fprintf(stderr, "get_iPhone(): libusb error message %d: %s (%s)\n",
			       			bytes, usb_strerror(), strerror(-bytes));
		return IPHONE_E_NOT_ENOUGH_DATA;
	}

	// Check for correct version
	if (ntohl(version->major) == 1 && ntohl(version->minor) == 0) {
		// We're all ready to roll.
		fprintf(stderr, "get_iPhone() success\n");
		free(version);
		*device = phone;
		return IPHONE_E_SUCCESS;
	} else {
		// Bad header
		iphone_free_device(phone);
		free(version);
		if (debug) fprintf(stderr, "get_iPhone(): Received a bad header/invalid version number.");
		return IPHONE_E_BAD_HEADER;
	}

	// If it got to this point it's gotta be bad
	if (debug) fprintf(stderr, "get_iPhone(): Unknown error.\n");
	iphone_free_device(phone);
	free(version);
	return IPHONE_E_UNKNOWN_ERROR; // if it got to this point it's gotta be bad
}

/** Cleans up an iPhone structure, then frees the structure itself.  
 * This is a library-level function; deals directly with the iPhone to tear
 *  down relations, but otherwise is mostly internal.
 * 
 * @param phone A pointer to an iPhone structure.
 */
void iphone_free_device ( iphone_device_t device ) {
	if (device->buffer) free(device->buffer);	
	if (device->device) {
		usb_release_interface(device->device, 1);
		usb_reset(device->device);
		usb_close(device->device);
	}
	free(device);
}
 
/** Sends data to the phone
 * This is a low-level (i.e. directly to phone) function.
 * 
 * @param phone The iPhone to send data to
 * @param data The data to send to the iPhone
 * @param datalen The length of the data
 * @return The number of bytes sent, or -1 on error or something.
 */
int send_to_phone(iphone_device_t phone, char *data, int datalen) {
	if (!phone) return -1;
	int bytes = 0;
	
	if (!phone) return -1;
	if (debug) fprintf(stderr, "send_to_phone: Attempting to send datalen = %i data = %p\n", datalen, data);

	bytes = usb_bulk_write(phone->device, BULKOUT, data, datalen, 800);
	if (bytes < datalen) {
		if(debug && bytes < 0)
			fprintf(stderr, "send_to_iphone(): libusb gave me the error %d: %s - %s\n", bytes, usb_strerror(), strerror(-bytes));
		return -1;
	} else {
		return bytes;
	}
	
	return -1;
}

/** This function is a low-level (i.e. direct to iPhone) function.
 * 
 * @param phone The iPhone to receive data from
 * @param data Where to put data read
 * @param datalen How much data to read in
 * 
 * @return How many bytes were read in, or -1 on error.
 */
int recv_from_phone(iphone_device_t phone, char *data, int datalen) {
	if (!phone) return -1;
	int bytes = 0;
	
	if (!phone) return -1;
	if (debug) fprintf(stderr, "recv_from_phone(): attempting to receive %i bytes\n", datalen);
	
	bytes = usb_bulk_read(phone->device, BULKIN, data, datalen, 3500);
	if (bytes < 0) {
		if(debug) fprintf(stderr, "recv_from_phone(): libusb gave me the error %d: %s (%s)\n", bytes, usb_strerror(), strerror(-bytes));
		return -1;
	}
	
	return bytes;
}
