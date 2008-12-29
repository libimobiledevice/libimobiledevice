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
#include "utils.h"

static iphone_umux_client_t *connlist = NULL;
static int clients = 0;

/** Creates a USBMux packet for the given set of ports.
 * 
 * @param s_port The source port for the connection.
 * @param d_port The destination port for the connection.
 *
 * @return A USBMux packet
 */
usbmux_tcp_header *new_mux_packet(uint16 s_port, uint16 d_port)
{
	usbmux_tcp_header *conn = (usbmux_tcp_header *) malloc(sizeof(usbmux_tcp_header));
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

/** Creates a USBMux header containing version information
 * 
 * @return A USBMux header
 */
usbmux_version_header *version_header()
{
	usbmux_version_header *version = (usbmux_version_header *) malloc(sizeof(usbmux_version_header));
	version->type = 0;
	version->length = htonl(20);
	version->major = htonl(1);
	version->minor = 0;
	version->allnull = 0;
	return version;
}


// Maintenance functions.

/** Removes a connection from the list of connections made.
 * The list of connections is necessary for buffering.
 * 
 * @param connection The connection to delete from the tracking list.
 */
void delete_connection(iphone_umux_client_t connection)
{
	iphone_umux_client_t *newlist = (iphone_umux_client_t *) malloc(sizeof(iphone_umux_client_t) * (clients - 1));
	int i = 0, j = 0;
	for (i = 0; i < clients; i++) {
		if (connlist[i] == connection)
			continue;
		else {
			newlist[j] = connlist[i];
			j++;
		}
	}
	free(connlist);
	connlist = newlist;
	clients--;
	if (connection->recv_buffer)
		free(connection->recv_buffer);
	if (connection->header)
		free(connection->header);
	connection->r_len = 0;
	free(connection);
}

/** Adds a connection to the list of connections made.
 * The connection list is necessary for buffering.
 *
 * @param connection The connection to add to the global list of connections.
 */

void add_connection(iphone_umux_client_t connection)
{
	iphone_umux_client_t *newlist =
		(iphone_umux_client_t *) realloc(connlist, sizeof(iphone_umux_client_t) * (clients + 1));
	newlist[clients] = connection;
	connlist = newlist;
	clients++;
}

/** Initializes a connection on phone, with source port s_port and destination port d_port
 *
 * @param device The iPhone to initialize a connection on.
 * @param src_port The source port
 * @param dst_port The destination port -- 0xf27e for lockdownd. 
 * @param client A mux TCP header for the connection which is used for tracking and data transfer.
 * @return IPHONE_E_SUCCESS on success, an error code otherwise.
 */
iphone_error_t iphone_mux_new_client(iphone_device_t device, uint16_t src_port, uint16_t dst_port,
									 iphone_umux_client_t * client)
{
	if (!device || !src_port || !dst_port)
		return IPHONE_E_INVALID_ARG;

	int bytes = 0;
	// Initialize connection stuff
	iphone_umux_client_t new_connection = (iphone_umux_client_t) malloc(sizeof(struct iphone_umux_client_int));
	new_connection->header = new_mux_packet(src_port, dst_port);

	// blargg
	if (new_connection && new_connection->header) {
		new_connection->header->tcp_flags = 0x02;
		new_connection->header->length = htonl(new_connection->header->length);
		new_connection->header->length16 = htons(new_connection->header->length16);

		if (send_to_phone(device, (char *) new_connection->header, sizeof(usbmux_tcp_header)) >= 0) {
			usbmux_tcp_header *response;
			response = (usbmux_tcp_header *) malloc(sizeof(usbmux_tcp_header));
			bytes = recv_from_phone(device, (char *) response, sizeof(*response));
			if (response->tcp_flags != 0x12) {
				free(response);
				return IPHONE_E_UNKNOWN_ERROR;
			} else {
				free(response);

				log_debug_msg("mux_connect: connection success\n");
				new_connection->header->tcp_flags = 0x10;
				new_connection->header->scnt = 1;
				new_connection->header->ocnt = 1;
				new_connection->phone = device;
				new_connection->recv_buffer = NULL;
				new_connection->r_len = 0;
				add_connection(new_connection);
				*client = new_connection;
				return IPHONE_E_SUCCESS;
			}
		} else {
			return IPHONE_E_NOT_ENOUGH_DATA;
		}
	}
	// if we get to this point it's probably bad
	return IPHONE_E_UNKNOWN_ERROR;
}

/** Cleans up the given USBMux connection.
 * @note Once a connection is closed it may not be used again.
 * 
 * @param connection The connection to close.
 *
 * @return IPHONE_E_SUCCESS on success.
 */
iphone_error_t iphone_mux_free_client(iphone_umux_client_t client)
{
	if (!client || !client->phone)
		return;

	client->header->tcp_flags = 0x04;
	client->header->scnt = htonl(client->header->scnt);
	client->header->ocnt = htonl(client->header->ocnt);
	int bytes = 0;

	bytes = usb_bulk_write(client->phone->device, BULKOUT, (char *) client->header, sizeof(usbmux_tcp_header), 800);
	if (bytes < 0)
		log_debug_msg("iphone_muxèfree_client(): when writing, libusb gave me the error: %s\n", usb_strerror());

	bytes = usb_bulk_read(client->phone->device, BULKIN, (char *) client->header, sizeof(usbmux_tcp_header), 800);
	if (bytes < 0)
		log_debug_msg("get_iPhone(): when reading, libusb gave me the error: %s\n", usb_strerror());

	delete_connection(client);

	return IPHONE_E_SUCCESS;
}


/** Sends the given data over the selected connection.
 *
 * @param phone The iPhone to send to.
 * @param client The client we're sending data on.
 * @param data A pointer to the data to send.
 * @param datalen How much data we're sending.
 * @param sent_bytes The number of bytes sent, minus the header (28)
 *
 * @return IPHONE_E_SUCCESS on success.
 */

iphone_error_t iphone_mux_send(iphone_umux_client_t client, const char *data, uint32_t datalen, uint32_t * sent_bytes)
{
	if (!client->phone || !client || !data || datalen == 0 || !sent_bytes)
		return IPHONE_E_INVALID_ARG;
	// client->scnt and client->ocnt should already be in host notation...
	// we don't need to change them juuuust yet. 
	*sent_bytes = 0;
	log_debug_msg("mux_send(): client wants to send %i bytes\n", datalen);
	char *buffer = (char *) malloc(sizeof(usbmux_tcp_header) + datalen + 2);	// allow 2 bytes of safety padding
	// Set the length and pre-emptively htonl/htons it
	client->header->length = htonl(sizeof(usbmux_tcp_header) + datalen);
	client->header->length16 = htons(sizeof(usbmux_tcp_header) + datalen);

	// Put scnt and ocnt into big-endian notation
	client->header->scnt = htonl(client->header->scnt);
	client->header->ocnt = htonl(client->header->ocnt);
	// Concatenation of stuff in the buffer.
	memcpy(buffer, client->header, sizeof(usbmux_tcp_header));
	memcpy(buffer + sizeof(usbmux_tcp_header), data, datalen);

	// We have a buffer full of data, we should now send it to the phone.
	log_debug_msg("actually sending %zi bytes of data at %p\n", sizeof(usbmux_tcp_header) + datalen, buffer);


	*sent_bytes = send_to_phone(client->phone, buffer, sizeof(usbmux_tcp_header) + datalen);
	log_debug_msg("mux_send: sent %i bytes!\n", *sent_bytes);
	// Now that we've sent it off, we can clean up after our sloppy selves.
	dump_debug_buffer("packet", buffer, *sent_bytes);
	if (buffer)
		free(buffer);
	// Re-calculate scnt and ocnt
	client->header->scnt = ntohl(client->header->scnt) + datalen;
	client->header->ocnt = ntohl(client->header->ocnt);

	// Revert lengths
	client->header->length = ntohl(client->header->length);
	client->header->length16 = ntohs(client->header->length16);

	// Now return the bytes.
	if (*sent_bytes < sizeof(usbmux_tcp_header) + datalen) {
		*sent_bytes = 0;
		return IPHONE_E_NOT_ENOUGH_DATA;
	} else {
		*sent_bytes = *sent_bytes - 28;	// actual length sent. :/
	}

	return IPHONE_E_SUCCESS;
}

/** This is a higher-level USBMuxTCP-like function
 *
 * @param connection The connection to receive data on.
 * @param data Where to put the data we receive. 
 * @param datalen How much data to read.
 *
 * @return How many bytes were read, or -1 if something bad happens.
 */
iphone_error_t iphone_mux_recv(iphone_umux_client_t client, char *data, uint32_t datalen, uint32_t * recv_bytes)
{

	if (!client || !data || datalen == 0 || !recv_bytes)
		return IPHONE_E_INVALID_ARG;
	/*
	 * Order of operation:
	 * 1.) Check if the client has a pre-received buffer.
	 * 2.) If so, fill data with the buffer, as much as needed.
	 *      a.) Return quickly if the buffer has enough
	 *      b.) If the buffer is only part of the datalen, get the rest of datalen (and if we can't, just return)
	 * 3.) If not, receive directly from the phone. 
	 *      a.) Check incoming packet's ports. If proper, follow proper buffering and receiving operation.
	 *      b.) If not, find the client the ports belong to and fill that client's buffer, then return mux_recv with the same args to try again.
	 */
	log_debug_msg("mux_recv: datalen == %i\n", datalen);
	int bytes = 0, i = 0, complex = 0, offset = 0;
	*recv_bytes = 0;
	char *buffer = NULL;
	usbmux_tcp_header *header = NULL;

	if (client->recv_buffer) {
		if (client->r_len >= datalen) {
			memcpy(data, client->recv_buffer, datalen);
			if (client->r_len == datalen) {
				// reset everything
				free(client->recv_buffer);
				client->r_len = 0;
				client->recv_buffer = NULL;
			} else {
				buffer = (char *) malloc(sizeof(char) * (client->r_len - datalen));
				memcpy(buffer, client->recv_buffer + datalen, (client->r_len - datalen));
				client->r_len -= datalen;
				free(client->recv_buffer);
				client->recv_buffer = buffer;
			}

			// Since we were able to fill the data straight from our buffer, we can just return datalen. See 2a above.
			return datalen;
		} else {
			memcpy(data, client->recv_buffer, client->r_len);
			free(client->recv_buffer);	// don't need to deal with anymore, but...
			offset = client->r_len;	// see #2b, above
			client->r_len = 0;
		}
	}							// End of what to do if we have a pre-buffer. See #1 and #2 above. 

	buffer = (char *) malloc(sizeof(char) * 131072);	// make sure we get enough ;)

	// See #3.
	bytes = recv_from_phone(client->phone, buffer, 131072);
	if (bytes < 28) {
		free(buffer);
		log_debug_msg("mux_recv: Did not even get the header.\n");
		return IPHONE_E_NOT_ENOUGH_DATA;
	}

	header = (usbmux_tcp_header *) buffer;
	if (header->sport != client->header->dport || header->dport != client->header->sport) {
		// Ooooops -- we got someone else's packet.
		// We gotta stick it in their buffer. (Take that any old way you want ;) )
		for (i = 0; i < clients; i++) {
			if (connlist[i]->header->sport == header->dport && connlist[i]->header->dport == header->sport) {
				// we have a winner.
				char *nfb = (char *) malloc(sizeof(char) * (connlist[i]->r_len + (bytes - 28)));
				if (connlist[i]->recv_buffer && connlist[i]->r_len) {
					memcpy(nfb, connlist[i]->recv_buffer, connlist[i]->r_len);
					free(connlist[i]->recv_buffer);
				}
				connlist[i]->r_len += bytes - 28;
				//connlist[i]->recv_buffer = (char*)realloc(connlist[i]->recv_buffer, sizeof(char) * client->r_len); // grow their buffer
				connlist[i]->recv_buffer = nfb;
				nfb = NULL;		// A cookie for you if you can guess what "nfb" means. 
				complex = connlist[i]->r_len - (bytes - 28);
				memcpy(connlist[i]->recv_buffer + complex, buffer + 28, bytes - 28);	// paste into their buffer
				connlist[i]->header->ocnt += bytes - 28;
			}
		}
		// If it wasn't ours, it's been handled by this point... or forgotten.
		// Free our buffer and continue.
		free(buffer);
		buffer = NULL;
		return iphone_mux_recv(client, data, datalen, recv_bytes);	// recurse back in to try again
	}
	// The packet was absolutely meant for us if it hits this point.
	// The pre-buffer has been taken care of, so, again, if we're at this point we have to read from the phone.

	if ((bytes - 28) > datalen) {
		// Copy what we need into the data, buffer the rest because we can.
		memcpy(data + offset, buffer + 28, datalen);	// data+offset: see #2b, above
		complex = client->r_len + (bytes - 28) - datalen;
		client->recv_buffer = (char *) realloc(client->recv_buffer, (sizeof(char) * complex));
		client->r_len = complex;
		complex = client->r_len - (bytes - 28) - datalen;
		memcpy(client->recv_buffer + complex, buffer + 28 + datalen, (bytes - 28) - datalen);
		free(buffer);
		client->header->ocnt += bytes - 28;
		*recv_bytes = datalen;
		return IPHONE_E_SUCCESS;
	} else {
		// Fill the data with what we have, and just return.
		memcpy(data + offset, buffer + 28, bytes - 28);	// data+offset: see #2b, above
		client->header->ocnt += bytes - 28;
		free(buffer);
		*recv_bytes = bytes - 28;
		return IPHONE_E_SUCCESS;
	}

	// If we get to this point, 'tis probably bad.
	log_debug_msg("mux_recv: Heisenbug: bytes and datalen not matching up\n");
	return IPHONE_E_UNKNOWN_ERROR;
}
