/*
 * usbmux.c
 * Interprets the usb multiplexing protocol used by the iPhone.
 *
 * Copyright (c) 2008 Zack C. All Rights Reserved.
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

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "usbmux.h"

extern int debug;

usbmux_tcp_header *new_mux_packet(uint16 s_port, uint16 d_port) {
	usbmux_tcp_header *conn = (usbmux_tcp_header*)malloc(sizeof(usbmux_tcp_header));
	conn->type = htonl(6);
	conn->length = 28;
	conn->sport = htons(s_port);
	conn->dport = htons(d_port);
	conn->scnt = 0;
	conn->ocnt = 0;
	conn->offset = 0x50;
	conn->window = htons(0x0200);
	conn->nullnull = 0x0000;
	conn->length16 = 28;
	return conn;
}

usbmux_version_header *version_header() {
	usbmux_version_header *version = (usbmux_version_header*)malloc(sizeof(usbmux_version_header));
	version->type = 0;
	version->length = htonl(20);
	version->major = htonl(1);
	version->minor = 0;
	version->allnull = 0;
	return version;
}

/* mux_connect(phone, s_port, d_port)
 * This is a higher-level USBMuxTCP-type function.
 * 	phone: the iPhone to initialize a connection on.
 * 	s_port: the source port
 * 	d_port: the destination port -- 0xf27e for lockdownd. 
 * Initializes a connection on phone, with source port s_port and destination port d_port
 * 
 * Returns a mux TCP header for the connection which is used for tracking and data transfer.
 */ 

usbmux_tcp_header *mux_connect(iPhone *phone, uint16 s_port, uint16 d_port) {
	if (!phone || !s_port || !d_port) return NULL;
	int bytes = 0;
	// Initialize connection stuff
	usbmux_tcp_header *new_connection;
	new_connection = new_mux_packet(s_port, d_port);
	usbmux_tcp_header *response;
	response = (usbmux_tcp_header*)malloc(sizeof(usbmux_tcp_header));
	// blargg
	if (new_connection) {
		new_connection->tcp_flags = 0x02;
		new_connection->length = htonl(new_connection->length);
		new_connection->length16 = htons(new_connection->length16);
		
		if (send_to_phone(phone, (char*)new_connection, sizeof(*new_connection)) >= 0) {
			bytes = recv_from_phone(phone, (char*)response, sizeof(*response));
			if (response->tcp_flags != 0x12) return NULL;
			else {
				new_connection->tcp_flags = 0x10;
				new_connection->scnt = 1;
				new_connection->ocnt = 1;
				return new_connection;
			}
		} else {
			return NULL;
		}
	}
	
	// if we get to this point it's probably bad
	return NULL;
}

/* mux_close_connection(phone, connection)
 * This is a higher-level USBmuxTCP-type function.
 * 	phone: the iPhone to close a connection with.
 * 	connection: the connection to close.
 * 
 * Doesn't return anything; WILL FREE THE CONNECTION'S MEMORY!!!
 */
void mux_close_connection(iPhone *phone, usbmux_tcp_header *connection) {
	if (!phone || !connection) return;
	
	connection->tcp_flags = 0x04;
	connection->scnt = htonl(connection->scnt);
	connection->ocnt = htonl(connection->ocnt);
	int bytes = 0;
	
	bytes = usb_bulk_write(phone->device, BULKOUT, (char*)connection, sizeof(*connection), 800);
	if(debug && bytes < 0)
		printf("mux_close_connection(): when writing, libusb gave me the error: %s\n", usb_strerror());

	bytes = usb_bulk_read(phone->device, BULKIN, (char*)connection, sizeof(*connection), 800);
	if(debug && bytes < 0)
		printf("get_iPhone(): when reading, libusb gave me the error: %s\n", usb_strerror());
	
	free(connection);
}

/* mux_send(phone, connection, data, datalen)
 * This is a higher-level USBMuxTCP-like function.
 * 	phone: the iPhone to send to.
 * 	connection: the connection we're sending data on.
 * 	data: a pointer to the data to send.
 * 	datalen: how much data we're sending.
 * 
 * Returns number of bytes sent, minus the header (28), or -1 on error.
 */
int mux_send(iPhone *phone, usbmux_tcp_header *connection, char *data, uint32 datalen) {
	if (!phone || !connection || !data || datalen == 0) return -1;
	// connection->scnt and connection->ocnt should already be in host notation...
	// we don't need to change them juuuust yet. 
	int bytes = 0;
	if (debug) printf("mux_send(): client wants to send %i bytes\n", datalen);
	char *buffer = (char*)malloc(sizeof(*connection) + datalen + 2); // allow 2 bytes of safety padding
	// Set the length and pre-emptively htonl/htons it
	connection->length = htonl(sizeof(*connection) + datalen);
	connection->length16 = htons(sizeof(*connection) + datalen);
	
	// Put scnt and ocnt into big-endian notation
	connection->scnt = htonl(connection->scnt);
	connection->ocnt = htonl(connection->ocnt);
	// Concatenation of stuff in the buffer.
	memcpy(buffer, connection, sizeof(*connection));
	memcpy(buffer+sizeof(*connection)/*+sizeof(datalen)*/, data, datalen);
	
	// We have a buffer full of data, we should now send it to the phone.
	if (debug) printf("actually sending %i bytes of data at %x\n", sizeof(*connection)+datalen, buffer);

	
	bytes = send_to_phone(phone, buffer, sizeof(*connection)+datalen);
	
	// Now that we've sent it off, we can clean up after our sloppy selves.
	free(buffer);
	
	// Re-calculate scnt and ocnt
	connection->scnt = ntohl(connection->scnt) + datalen;
	connection->ocnt = ntohl(connection->ocnt);
	
	// Revert lengths
	connection->length = ntohl(connection->length);
	connection->length16 = ntohs(connection->length16);
	
	// Now return the bytes.
	if (bytes < sizeof(*connection)+datalen) {
		return -1; // blah
	} else {
		return bytes - 28; // actual length sent. :/
	}
	
	return bytes; // or something
}

/* mux_recv(phone, connection, data, datalen)
 * This is a higher-level USBMuxTCP-like function
 * 	phone: the phone to receive data from.
 * 	connection: the connection to receive data on.
 * 	data: where to put the data we receive. 
 * 	datalen: how much data to read.
 * 
 * Returns: how many bytes were read, or -1 if something bad happens.
 */

int mux_recv(iPhone *phone, usbmux_tcp_header *connection, char *data, uint32 datalen) {
	char *buffer = (char*)malloc(sizeof(*connection) + sizeof(datalen) + datalen);
	int bytes = 0, my_datalen = 0;
	if (debug) printf("mux_recv: datalen == %i\n", datalen);
	bytes = recv_from_phone(phone, buffer, sizeof(*connection) + datalen);
	if (debug) printf("mux_recv: bytes == %i\n", bytes);
	if (bytes < datalen) {
		if (bytes < 28) {
			// if they didn't do that annoying thing, something else mighta happened.
			if (debug) printf("mux_recv: bytes too low anyway!\n");
			free(buffer);
			return -1;
		} else if (bytes == 28) { // no data...
			free(buffer);
			return 0;
		} else { // bytes > 28
			my_datalen = ntohl(buffer[4]) - 28;
			connection->ocnt += my_datalen;
			memcpy(data, buffer+28, bytes - 28);
			free(buffer);
			if (debug) printf("mux_recv: bytes received: %i\n", bytes - 28);
			return bytes - 28;
		}
	} else {// all's good, they didn't do anything bonky.
		my_datalen = ntohl(buffer[4]) - 28; 
		connection->ocnt += my_datalen;
		if (bytes == (datalen+28)) memcpy(data, buffer+28, datalen); 
		else if (bytes == datalen) memcpy(data, buffer+28, datalen-28);
		free(buffer);
		if (debug) printf("mux_recv: bytes received: %i\n", bytes - 28);
		return bytes - 28;
	}
	
	return bytes;
}

