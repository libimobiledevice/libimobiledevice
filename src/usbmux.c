/*
 * usbmux.c
 * Interprets the usb multiplexing protocol used by the iPhone.
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

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "usbmux.h"

extern int debug;

static usbmux_connection **connlist = NULL;
static int connections = 0;

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


// Maintenance functions.

/* delete_connection(connection)
 * 	connection: the connection to delete from the tracking list.
 * Removes a connection from the list of connections made.
 * The list of connections is necessary for buffering.
 */

void delete_connection(usbmux_connection *connection) {
	usbmux_connection **newlist = (usbmux_connection**)malloc(sizeof(usbmux_connection*) * (connections - 1));
	int i = 0, j = 0;
	for (i = 0; i < connections; i++) {
		if (connlist[i] == connection) continue;
		else {
			newlist[j] = connlist[i];
			j++;
		}
	}
	free(connlist);
	connlist = newlist;
	connections--;
	if (connection->recv_buffer) free(connection->recv_buffer);
	if (connection->header) free(connection->header);
	connection->r_len = 0;
	free(connection);
}

/* add_connection(connection)
 * 	connection: the connection to add to the global list of connections.
 * Adds a connection to the list of connections made.
 * The connection list is necessary for buffering.
 */

void add_connection(usbmux_connection *connection) {
	usbmux_connection **newlist = (usbmux_connection**)realloc(connlist, sizeof(usbmux_connection*) * (connections+1));
	newlist[connections] = connection;
	connlist = newlist;
	connections++;
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

usbmux_connection *mux_connect(iPhone *phone, uint16 s_port, uint16 d_port) {
	if (!phone || !s_port || !d_port) return NULL;
	int bytes = 0;
	// Initialize connection stuff
	usbmux_connection *new_connection = (usbmux_connection*)malloc(sizeof(usbmux_connection));
	new_connection->header = new_mux_packet(s_port, d_port);
	usbmux_tcp_header *response;
	response = (usbmux_tcp_header*)malloc(sizeof(usbmux_tcp_header));
	// blargg
	if (new_connection && new_connection->header) {
		new_connection->header->tcp_flags = 0x02;
		new_connection->header->length = htonl(new_connection->header->length);
		new_connection->header->length16 = htons(new_connection->header->length16);
		
		if (send_to_phone(phone, (char*)new_connection->header, sizeof(usbmux_tcp_header)) >= 0) {
			bytes = recv_from_phone(phone, (char*)response, sizeof(*response));
			if (response->tcp_flags != 0x12) return NULL;
			else {
				if (debug) printf("mux_connect: connection success\n");
				new_connection->header->tcp_flags = 0x10;
				new_connection->header->scnt = 1;
				new_connection->header->ocnt = 1;
				add_connection(new_connection);
				new_connection->phone = phone;
				new_connection->recv_buffer = NULL;
				new_connection->r_len = 0;
				add_connection(new_connection);
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

void mux_close_connection(usbmux_connection *connection) {
	if (!connection || !connection->phone) return;
	
	connection->header->tcp_flags = 0x04;
	connection->header->scnt = htonl(connection->header->scnt);
	connection->header->ocnt = htonl(connection->header->ocnt);
	int bytes = 0;
	
	bytes = usb_bulk_write(connection->phone->device, BULKOUT, (char*)connection->header, sizeof(usbmux_tcp_header), 800);
	if(debug && bytes < 0)
		printf("mux_close_connection(): when writing, libusb gave me the error: %s\n", usb_strerror());

	bytes = usb_bulk_read(connection->phone->device, BULKIN, (char*)connection->header, sizeof(usbmux_tcp_header), 800);
	if(debug && bytes < 0)
		printf("get_iPhone(): when reading, libusb gave me the error: %s\n", usb_strerror());
	
	delete_connection(connection);
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
int mux_send(usbmux_connection *connection, const char *data, uint32 datalen) {
	if (!connection->phone || !connection || !data || datalen == 0) return -1;
	// connection->scnt and connection->ocnt should already be in host notation...
	// we don't need to change them juuuust yet. 
	int bytes = 0;
	if (debug) printf("mux_send(): client wants to send %i bytes\n", datalen);
	char *buffer = (char*)malloc(sizeof(usbmux_tcp_header) + datalen + 2); // allow 2 bytes of safety padding
	// Set the length and pre-emptively htonl/htons it
	connection->header->length = htonl(sizeof(usbmux_tcp_header) + datalen);
	connection->header->length16 = htons(sizeof(usbmux_tcp_header) + datalen);
	
	// Put scnt and ocnt into big-endian notation
	connection->header->scnt = htonl(connection->header->scnt);
	connection->header->ocnt = htonl(connection->header->ocnt);
	// Concatenation of stuff in the buffer.
	memcpy(buffer, connection->header, sizeof(usbmux_tcp_header));
	memcpy(buffer+sizeof(usbmux_tcp_header), data, datalen);
	
	// We have a buffer full of data, we should now send it to the phone.
	if (debug) printf("actually sending %i bytes of data at %x\n", sizeof(usbmux_tcp_header)+datalen, buffer);

	
	bytes = send_to_phone(connection->phone, buffer, sizeof(usbmux_tcp_header)+datalen);
	if (debug) printf("mux_send: sent %i bytes!\n", bytes);
	// Now that we've sent it off, we can clean up after our sloppy selves.
	if (debug) {
		FILE *packet = fopen("packet", "a+");
		fwrite(buffer, 1, bytes, packet);
		fclose(packet);
		printf("\n");
	}
	
	if (buffer) free(buffer);
	// Re-calculate scnt and ocnt
	connection->header->scnt = ntohl(connection->header->scnt) + datalen;
	connection->header->ocnt = ntohl(connection->header->ocnt);
	
	// Revert lengths
	connection->header->length = ntohl(connection->header->length);
	connection->header->length16 = ntohs(connection->header->length16);
	
	// Now return the bytes.
	if (bytes < sizeof(usbmux_tcp_header)+datalen) {
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

int mux_recv(usbmux_connection *connection, char *data, uint32 datalen) {
	/*
	 * Order of operation:
	 * 1.) Check if the connection has a pre-received buffer.
	 * 2.) If so, fill data with the buffer, as much as needed.
	 * 	a.) Return quickly if the buffer has enough
	 * 	b.) If the buffer is only part of the datalen, get the rest of datalen (and if we can't, just return)
	 * 3.) If not, receive directly from the phone. 
	 * 	a.) Check incoming packet's ports. If proper, follow proper buffering and receiving operation.
	 * 	b.) If not, find the connection the ports belong to and fill that connection's buffer, then return mux_recv with the same args to try again.
	 */
	if (debug) printf("mux_recv: datalen == %i\n", datalen);
	int bytes = 0, i = 0, complex = 0, offset = 0;
	char *buffer = NULL;
	usbmux_tcp_header *header = NULL;
		
	if (connection->recv_buffer) {
		if (connection->r_len >= datalen) {
			memcpy(data, connection->recv_buffer, datalen);
			if (connection->r_len == datalen) {
				// reset everything
				free(connection->recv_buffer);
				connection->r_len = 0;
				connection->recv_buffer = NULL;
			} else {
				buffer = (char*)malloc(sizeof(char) * (connection->r_len - datalen));
				memcpy(buffer, connection->recv_buffer+datalen, (connection->r_len - datalen));
				connection->r_len -= datalen;
				free(connection->recv_buffer);
				connection->recv_buffer = buffer;
			}
			
			// Since we were able to fill the data straight from our buffer, we can just return datalen. See 2a above.
			return datalen;
		} else {
			memcpy(data, connection->recv_buffer, connection->r_len);
			free(connection->recv_buffer); // don't need to deal with anymore, but...
			offset = connection->r_len; // see #2b, above
			connection->r_len = 0;
		}
	} // End of what to do if we have a pre-buffer. See #1 and #2 above. 
	
	buffer = (char*)malloc(sizeof(char) * 131072); // make sure we get enough ;)
	
	// See #3.
	bytes = recv_from_phone(connection->phone, buffer, 131072);
	if (bytes < 28) {
		free(buffer);
		if (debug) printf("mux_recv: Did not even get the header.\n");
		return -1;
	}
	
	header = (usbmux_tcp_header*)buffer;
	if (header->sport != connection->header->dport || header->dport != connection->header->sport) {
		// Ooooops -- we got someone else's packet.
		// We gotta stick it in their buffer. (Take that any old way you want ;) )
		for (i = 0; i < connections; i++) {
			if (connlist[i]->header->sport == header->dport && connlist[i]->header->dport == header->sport) {
				// we have a winner.
				connlist[i]->r_len += bytes - 28;
				connlist[i]->recv_buffer = (char*)realloc(connlist[i]->recv_buffer, sizeof(char) * connection->r_len); // grow their buffer
				complex = connlist[i]->r_len - (bytes - 28);
				memcpy(connlist[i]->recv_buffer+complex, buffer+28, bytes-28); // paste into their buffer
				connlist[i]->header->ocnt += bytes-28;
			}
		}
		// If it wasn't ours, it's been handled by this point... or forgotten.
		// Free our buffer and continue.
		free(buffer);
		buffer = NULL;
		return mux_recv(connection, data, datalen); // recurse back in to try again
	}

	// The packet was absolutely meant for us if it hits this point.
	// The pre-buffer has been taken care of, so, again, if we're at this point we have to read from the phone.
	
	if ((bytes-28) > datalen) {
		// Copy what we need into the data, buffer the rest because we can.
		memcpy(data+offset, buffer+28, datalen); // data+offset: see #2b, above
		complex = connection->r_len + (bytes-28) - datalen;
		connection->recv_buffer = (char*)realloc(connection->recv_buffer, (sizeof(char) * complex));
		connection->r_len = complex;
		complex = connection->r_len - (bytes-28) - datalen;
		memcpy(connection->recv_buffer+complex, buffer+28+datalen, (bytes-28) - datalen);
		free(buffer);
		connection->header->ocnt += bytes-28;
		return datalen;
	} else {
		// Fill the data with what we have, and just return.
		memcpy(data+offset, buffer+28, bytes-28); // data+offset: see #2b, above
		connection->header->ocnt += bytes-28;
		free(buffer);
		return (bytes-28);
	}
	
	// If we get to this point, 'tis probably bad.
	if (debug) printf("mux_recv: Heisenbug: bytes and datalen not matching up\n");
	return -1;
}

