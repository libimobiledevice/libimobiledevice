/*
 * afc.c 
 * Contains functions for the built-in AFC client.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "afc.h"
#include "idevice.h"
#include "debug.h"
#include "endianness.h"

/** The maximum size an AFC data packet can be */
static const int MAXIMUM_PACKET_SIZE = (2 << 15);

/**
 * Locks an AFC client, done for thread safety stuff
 * 
 * @param client The AFC client connection to lock
 */
static void afc_lock(afc_client_t client)
{
	debug_info("Locked");
#ifdef WIN32
	EnterCriticalSection(&client->mutex);
#else
	pthread_mutex_lock(&client->mutex);
#endif
}

/**
 * Unlocks an AFC client, done for thread safety stuff.
 * 
 * @param client The AFC 
 */
static void afc_unlock(afc_client_t client)
{
	debug_info("Unlocked");
#ifdef WIN32
	LeaveCriticalSection(&client->mutex);
#else
	pthread_mutex_unlock(&client->mutex);
#endif
}

/**
 * Makes a connection to the AFC service on the device using the given
 * connection.
 *
 * @param connection An idevice_connection_t that must have been previously
 *     connected using idevice_connect(). Note that this connection will
 *     not be closed by calling afc_client_free().
 * @param client Pointer that will be set to a newly allocated afc_client_t
 *     upon successful return.
 * 
 * @return AFC_E_SUCCESS on success, AFC_E_INVALID_ARG if connection is
 *  invalid, or AFC_E_NO_MEM if there is a memory allocation problem.
 */

afc_error_t afc_client_new_from_connection(idevice_connection_t connection, afc_client_t *client)
{
	if (!connection)
		return AFC_E_INVALID_ARG;

	afc_client_t client_loc = (afc_client_t) malloc(sizeof(struct afc_client_private));
	client_loc->connection = connection;
	client_loc->own_connection = 0;

	/* allocate a packet */
	client_loc->afc_packet = (AFCPacket *) malloc(sizeof(AFCPacket));
	if (!client_loc->afc_packet) {
		free(client_loc);
		return AFC_E_NO_MEM;
	}

	client_loc->afc_packet->packet_num = 0;
	client_loc->afc_packet->entire_length = 0;
	client_loc->afc_packet->this_length = 0;
	memcpy(client_loc->afc_packet->magic, AFC_MAGIC, AFC_MAGIC_LEN);
	client_loc->file_handle = 0;
	client_loc->lock = 0;
#ifdef WIN32
	InitializeCriticalSection(&client_loc->mutex);
#else
	pthread_mutex_init(&client_loc->mutex, NULL);
#endif

	*client = client_loc;
	return AFC_E_SUCCESS;
}

/**
 * Makes a connection to the AFC service on the device.
 * This function calls afc_client_new_from_connection() after creating
 * a connection to the specified device and port.
 *
 * @see afc_client_new_from_connection
 * 
 * @param device The device to connect to.
 * @param port The destination port.
 * @param client Pointer that will be set to a newly allocated afc_client_t
 *     upon successful return.
 * 
 * @return AFC_E_SUCCESS on success, AFC_E_INVALID_ARG if device or port is
 *  invalid, AFC_E_MUX_ERROR if the connection cannot be established,
 *  or AFC_E_NO_MEM if there is a memory allocation problem.
 */
afc_error_t afc_client_new(idevice_t device, uint16_t port, afc_client_t * client)
{
	if (!device || port==0)
		return AFC_E_INVALID_ARG;

	/* attempt connection */
	idevice_connection_t connection = NULL;
	if (idevice_connect(device, port, &connection) != IDEVICE_E_SUCCESS) {
		return AFC_E_MUX_ERROR;
	}

	afc_error_t err = afc_client_new_from_connection(connection, client);
	if (err != AFC_E_SUCCESS) {
		idevice_disconnect(connection);
	} else {
		(*client)->own_connection = 1;
	}
	return err;
}

/**
 * Frees up an AFC client. If the connection was created by the
 * client itself, the connection will be closed.
 * 
 * @param client The client to free.
 */
afc_error_t afc_client_free(afc_client_t client)
{
	if (!client || !client->afc_packet)
		return AFC_E_INVALID_ARG;

	if (client->own_connection && client->connection) {
		idevice_disconnect(client->connection);
		client->connection = NULL;
	}
	free(client->afc_packet);
#ifdef WIN32
	DeleteCriticalSection(&client->mutex);
#else
	pthread_mutex_destroy(&client->mutex);
#endif
	free(client);
	return AFC_E_SUCCESS;
}

/**
 * Dispatches an AFC packet over a client.
 * 
 * @param client The client to send data through.
 * @param data The data to send.
 * @param length The length to send.
 * @param bytes_sent The number of bytes actually sent.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 * 
 * @warning set client->afc_packet->this_length and
 *          client->afc_packet->entire_length to 0 before calling this.  The
 *          reason is that if you set them to different values, it indicates
 *          you want to send the data as two packets.
 */
static afc_error_t afc_dispatch_packet(afc_client_t client, const char *data, uint32_t length, uint32_t *bytes_sent)
{
	uint32_t offset = 0;
	uint32_t sent = 0;

	if (!client || !client->connection || !client->afc_packet)
		return AFC_E_INVALID_ARG;

	*bytes_sent = 0;

	if (!data || !length)
		length = 0;

	client->afc_packet->packet_num++;
	if (!client->afc_packet->entire_length) {
		client->afc_packet->entire_length = (length) ? sizeof(AFCPacket) + length : sizeof(AFCPacket);
		client->afc_packet->this_length = client->afc_packet->entire_length;
	}
	if (!client->afc_packet->this_length) {
		client->afc_packet->this_length = sizeof(AFCPacket);
	}
	/* We want to send two segments; buffer+sizeof(AFCPacket) to this_length
	   is the parameters and everything beyond that is the next packet.
	   (for writing) */
	if (client->afc_packet->this_length != client->afc_packet->entire_length) {
		offset = client->afc_packet->this_length - sizeof(AFCPacket);

		debug_info("Offset: %i", offset);
		if ((length) < (client->afc_packet->entire_length - client->afc_packet->this_length)) {
			debug_info("Length did not resemble what it was supposed to based on packet");
			debug_info("length minus offset: %i", length - offset);
			debug_info("rest of packet: %i\n", client->afc_packet->entire_length - client->afc_packet->this_length);
			return AFC_E_INTERNAL_ERROR;
		}

		/* send AFC packet header */
		AFCPacket_to_LE(client->afc_packet);
		sent = 0;
		idevice_connection_send(client->connection, (void*)client->afc_packet, sizeof(AFCPacket), &sent);
		AFCPacket_from_LE(client->afc_packet);
		if (sent == 0) {
			/* FIXME: should this be handled as success?! */
			return AFC_E_SUCCESS;
		}
		*bytes_sent += sent;

		/* send AFC packet data */
		sent = 0;
		idevice_connection_send(client->connection, data, offset, &sent);
		if (sent == 0) {
			return AFC_E_SUCCESS;
		}
		*bytes_sent += sent;

		debug_info("sent the first now go with the second");
		debug_info("Length: %i", length - offset);
		debug_info("Buffer: ");
		debug_buffer(data + offset, length - offset);

		sent = 0;
		idevice_connection_send(client->connection, data + offset, length - offset, &sent);

		*bytes_sent = sent;
		return AFC_E_SUCCESS;
	} else {
		debug_info("doin things the old way");
		debug_info("packet length = %i", client->afc_packet->this_length);

		debug_buffer((char*)client->afc_packet, sizeof(AFCPacket));

		/* send AFC packet header */
		AFCPacket_to_LE(client->afc_packet);
		sent = 0;
		idevice_connection_send(client->connection, (void*)client->afc_packet, sizeof(AFCPacket), &sent);
		AFCPacket_from_LE(client->afc_packet);
		if (sent == 0) {
			return AFC_E_SUCCESS;
		}
		*bytes_sent += sent;
		/* send AFC packet data (if there's data to send) */
		if (length > 0) {
			debug_info("packet data follows");

			debug_buffer(data, length);
			idevice_connection_send(client->connection, data, length, &sent);
			*bytes_sent += sent;
		}
		return AFC_E_SUCCESS;
	}
	return AFC_E_INTERNAL_ERROR;
}

/**
 * Receives data through an AFC client and sets a variable to the received data.
 * 
 * @param client The client to receive data on.
 * @param dump_here The char* to point to the newly-received data.
 * @param bytes_recv How much data was received.
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
static afc_error_t afc_receive_data(afc_client_t client, char **dump_here, uint32_t *bytes_recv)
{
	AFCPacket header;
	uint32_t entire_len = 0;
	uint32_t this_len = 0;
	uint32_t current_count = 0;
	uint64_t param1 = -1;

	*bytes_recv = 0;

	/* first, read the AFC header */
	idevice_connection_receive(client->connection, (char*)&header, sizeof(AFCPacket), bytes_recv);
	AFCPacket_from_LE(&header);
	if (*bytes_recv == 0) {
		debug_info("Just didn't get enough.");
		*dump_here = NULL;
		return AFC_E_MUX_ERROR;
	} else if (*bytes_recv < sizeof(AFCPacket)) {
		debug_info("Did not even get the AFCPacket header");
		*dump_here = NULL;
		return AFC_E_MUX_ERROR;
	}

	/* check if it's a valid AFC header */
	if (strncmp(header.magic, AFC_MAGIC, AFC_MAGIC_LEN)) {
		debug_info("Invalid AFC packet received (magic != " AFC_MAGIC ")!");
	}

	/* check if it has the correct packet number */
	if (header.packet_num != client->afc_packet->packet_num) {
		/* otherwise print a warning but do not abort */
		debug_info("ERROR: Unexpected packet number (%lld != %lld) aborting.", header.packet_num, client->afc_packet->packet_num);
		*dump_here = NULL;
		return AFC_E_OP_HEADER_INVALID;
	}

	/* then, read the attached packet */
	if (header.this_length < sizeof(AFCPacket)) {
		debug_info("Invalid AFCPacket header received!");
		*dump_here = NULL;
		return AFC_E_OP_HEADER_INVALID;
	} else if ((header.this_length == header.entire_length)
			&& header.entire_length == sizeof(AFCPacket)) {
		debug_info("Empty AFCPacket received!");
		*dump_here = NULL;
		*bytes_recv = 0;
		if (header.operation == AFC_OP_DATA) {
			return AFC_E_SUCCESS;
		} else {
			return AFC_E_IO_ERROR;
		}
	}

	debug_info("received AFC packet, full len=%lld, this len=%lld, operation=0x%llx", header.entire_length, header.this_length, header.operation);

	entire_len = (uint32_t)header.entire_length - sizeof(AFCPacket);
	this_len = (uint32_t)header.this_length - sizeof(AFCPacket);

	/* this is here as a check (perhaps a different upper limit is good?) */
	if (entire_len > (uint32_t)MAXIMUM_PACKET_SIZE) {
		fprintf(stderr, "%s: entire_len is larger than MAXIMUM_PACKET_SIZE, (%d > %d)!", __func__, entire_len, MAXIMUM_PACKET_SIZE);
	}

	*dump_here = (char*)malloc(entire_len);
	if (this_len > 0) {
		idevice_connection_receive(client->connection, *dump_here, this_len, bytes_recv);
		if (*bytes_recv <= 0) {
			free(*dump_here);
			*dump_here = NULL;
			debug_info("Did not get packet contents!");
			return AFC_E_NOT_ENOUGH_DATA;
		} else if (*bytes_recv < this_len) {
			free(*dump_here);
			*dump_here = NULL;
			debug_info("Could not receive this_len=%d bytes", this_len);
			return AFC_E_NOT_ENOUGH_DATA;
		}
	}

	current_count = this_len;

	if (entire_len > this_len) {
		while (current_count < entire_len) {
			idevice_connection_receive(client->connection, (*dump_here)+current_count, entire_len - current_count, bytes_recv);
			if (*bytes_recv <= 0) {
				debug_info("Error receiving data (recv returned %d)", *bytes_recv);
				break;
			}
			current_count += *bytes_recv;
		}
		if (current_count < entire_len) {
			debug_info("WARNING: could not receive full packet (read %s, size %d)", current_count, entire_len);
		}
	}

	if (current_count >= sizeof(uint64_t)) {
		param1 = le64toh(*(uint64_t*)(*dump_here));
	}

	debug_info("packet data size = %i", current_count);
	debug_info("packet data follows");
	debug_buffer(*dump_here, current_count);

	/* check operation types */
	if (header.operation == AFC_OP_STATUS) {
		/* status response */
		debug_info("got a status response, code=%lld", param1);

		if (param1 != AFC_E_SUCCESS) {
			/* error status */
			/* free buffer */
			free(*dump_here);
			*dump_here = NULL;
			return (afc_error_t)param1;
		}
	} else if (header.operation == AFC_OP_DATA) {
		/* data response */
		debug_info("got a data response");
	} else if (header.operation == AFC_OP_FILE_OPEN_RES) {
		/* file handle response */
		debug_info("got a file handle response, handle=%lld", param1);
	} else if (header.operation == AFC_OP_FILE_TELL_RES) {
		/* tell response */
		debug_info("got a tell response, position=%lld", param1);
	} else {
		/* unknown operation code received */
		free(*dump_here);
		*dump_here = NULL;
		*bytes_recv = 0;

		debug_info("WARNING: Unknown operation code received 0x%llx param1=%lld", header.operation, param1);
#ifndef WIN32
		fprintf(stderr, "%s: WARNING: Unknown operation code received 0x%llx param1=%lld", __func__, (long long)header.operation, (long long)param1);
#endif

		return AFC_E_OP_NOT_SUPPORTED;
	}

	*bytes_recv = current_count;
	return AFC_E_SUCCESS;
}

/**
 * Returns counts of null characters within a string.
 */
static uint32_t count_nullspaces(char *string, uint32_t number)
{
	uint32_t i = 0, nulls = 0;

	for (i = 0; i < number; i++) {
		if (string[i] == '\0')
			nulls++;
	}

	return nulls;
}

/**
 * Splits a string of tokens by null characters and returns each token in a
 * char array/list.
 *
 * @param tokens The characters to split into a list.
 * @param length The length of the tokens string.
 *
 * @return A char ** list with each token found in the string. The caller is
 *  responsible for freeing the memory.
 */
static char **make_strings_list(char *tokens, uint32_t length)
{
	uint32_t nulls = 0, i = 0, j = 0;
	char **list = NULL;

	if (!tokens || !length)
		return NULL;

	nulls = count_nullspaces(tokens, length);
	list = (char **) malloc(sizeof(char *) * (nulls + 1));
	for (i = 0; i < nulls; i++) {
		list[i] = strdup(tokens + j);
		j += strlen(list[i]) + 1;
	}
	list[i] = NULL;

	return list;
}

/**
 * Gets a directory listing of the directory requested.
 * 
 * @param client The client to get a directory listing from.
 * @param dir The directory to list. (must be a fully-qualified path)
 * @param list A char list of files in that directory, terminated by an empty
 *         string or NULL if there was an error.
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_read_directory(afc_client_t client, const char *dir, char ***list)
{
	uint32_t bytes = 0;
	char *data = NULL, **list_loc = NULL;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !dir || !list || (list && *list))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send the command */
	client->afc_packet->operation = AFC_OP_READ_DIR;
	client->afc_packet->entire_length = 0;
	client->afc_packet->this_length = 0;
	ret = afc_dispatch_packet(client, dir, strlen(dir)+1, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive the data */
	ret = afc_receive_data(client, &data, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return ret;
	}
	/* Parse the data */
	list_loc = make_strings_list(data, bytes);
	if (data)
		free(data);

	afc_unlock(client);
	*list = list_loc;

	return ret;
}

/**
 * Get device info for a client connection to phone. The device information
 * returned is the device model as well as the free space, the total capacity
 * and blocksize on the accessed disk partition.
 * 
 * @param client The client to get device info for.
 * @param infos A char ** list of parameters as given by AFC or NULL if there
 *  was an error.
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_get_device_info(afc_client_t client, char ***infos)
{
	uint32_t bytes = 0;
	char *data = NULL, **list = NULL;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !infos)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send the command */
	client->afc_packet->operation = AFC_OP_GET_DEVINFO;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	ret = afc_dispatch_packet(client, NULL, 0, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive the data */
	ret = afc_receive_data(client, &data, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return ret;
	}
	/* Parse the data */
	list = make_strings_list(data, bytes);
	if (data)
		free(data);

	afc_unlock(client);

	*infos = list;

	return ret;
}

/**
 * Get a specific key of the device info list for a client connection.
 * Known key values are: Model, FSTotalBytes, FSFreeBytes and FSBlockSize.
 * This is a helper function for afc_get_device_info().
 *
 * @param client The client to get device info for.
 * @param key The key to get the value of.
 * @param value The value for the key if successful or NULL otherwise.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_get_device_info_key(afc_client_t client, const char *key, char **value)
{
	afc_error_t ret = AFC_E_INTERNAL_ERROR;
	char **kvps, **ptr;

	*value = NULL;
	if (key == NULL)
		return AFC_E_INVALID_ARG;

	ret = afc_get_device_info(client, &kvps);
	if (ret != AFC_E_SUCCESS)
		return ret;

	for (ptr = kvps; *ptr; ptr++) {
		if (!strcmp(*ptr, key)) {
			*value = strdup(*(ptr+1));
			break;
		}
	}
	for (ptr = kvps; *ptr; ptr++) {
		free(*ptr);
	}
	free(kvps);

	return ret;
}

/**
 * Deletes a file or directory.
 * 
 * @param client The client to use.
 * @param path The path to delete. (must be a fully-qualified path)
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_remove_path(afc_client_t client, const char *path)
{
	char *response = NULL;
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !path || !client->afc_packet || !client->connection)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	client->afc_packet->operation = AFC_OP_REMOVE_PATH;
	ret = afc_dispatch_packet(client, path, strlen(path)+1, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, &response, &bytes);
	if (response)
		free(response);

	/* special case; unknown error actually means directory not empty */
	if (ret == AFC_E_UNKNOWN_ERROR)
		ret = AFC_E_DIR_NOT_EMPTY;

	afc_unlock(client);

	return ret;
}

/**
 * Renames a file or directory on the phone.
 * 
 * @param client The client to have rename.
 * @param from The name to rename from. (must be a fully-qualified path)
 * @param to The new name. (must also be a fully-qualified path)
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_rename_path(afc_client_t client, const char *from, const char *to)
{
	char *response = NULL;
	char *send = (char *) malloc(sizeof(char) * (strlen(from) + strlen(to) + 1 + sizeof(uint32_t)));
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !from || !to || !client->afc_packet || !client->connection)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	memcpy(send, from, strlen(from) + 1);
	memcpy(send + strlen(from) + 1, to, strlen(to) + 1);
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	client->afc_packet->operation = AFC_OP_RENAME_PATH;
	ret = afc_dispatch_packet(client, send, strlen(to)+1 + strlen(from)+1, &bytes);
	free(send);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, &response, &bytes);
	if (response)
		free(response);

	afc_unlock(client);

	return ret;
}

/**
 * Creates a directory on the phone.
 * 
 * @param client The client to use to make a directory.
 * @param dir The directory's path. (must be a fully-qualified path, I assume
 *        all other mkdir restrictions apply as well)
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_make_directory(afc_client_t client, const char *dir)
{
	uint32_t bytes = 0;
	char *response = NULL;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	client->afc_packet->operation = AFC_OP_MAKE_DIR;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	ret = afc_dispatch_packet(client, dir, strlen(dir)+1, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, &response, &bytes);
	if (response)
		free(response);

	afc_unlock(client);

	return ret;
}

/**
 * Gets information about a specific file.
 * 
 * @param client The client to use to get the information of the file.
 * @param path The fully-qualified path to the file. 
 * @param infolist Pointer to a buffer that will be filled with a NULL-terminated
 *                 list of strings with the file information.
 *                 Set to NULL before calling this function.
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_get_file_info(afc_client_t client, const char *path, char ***infolist)
{
	char *received = NULL;
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !path || !infolist)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	client->afc_packet->operation = AFC_OP_GET_FILE_INFO;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	ret = afc_dispatch_packet(client, path, strlen(path)+1, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}

	/* Receive data */
	ret = afc_receive_data(client, &received, &bytes);
	if (received) {
		*infolist = make_strings_list(received, bytes);
		free(received);
	}

	afc_unlock(client);

	return ret;
}

/**
 * Opens a file on the phone.
 * 
 * @param client The client to use to open the file. 
 * @param filename The file to open. (must be a fully-qualified path)
 * @param file_mode The mode to use to open the file. Can be AFC_FILE_READ or
 * 		    AFC_FILE_WRITE; the former lets you read and write,
 * 		    however, and the second one will *create* the file,
 * 		    destroying anything previously there.
 * @param handle Pointer to a uint64_t that will hold the handle of the file
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
idevice_error_t
afc_file_open(afc_client_t client, const char *filename,
					 afc_file_mode_t file_mode, uint64_t *handle)
{
	uint64_t file_mode_loc = htole64(file_mode);
	uint32_t bytes = 0;
	char *data = (char *) malloc(sizeof(char) * (8 + strlen(filename) + 1));
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	/* set handle to 0 so in case an error occurs, the handle is invalid */
	*handle = 0;

	if (!client || !client->connection || !client->afc_packet)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	memcpy(data, &file_mode_loc, 8);
	memcpy(data + 8, filename, strlen(filename));
	data[8 + strlen(filename)] = '\0';
	client->afc_packet->operation = AFC_OP_FILE_OPEN;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	ret = afc_dispatch_packet(client, data, 8 + strlen(filename) + 1, &bytes);
	free(data);

	if (ret != AFC_E_SUCCESS) {
		debug_info("Didn't receive a response to the command");
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive the data */
	ret = afc_receive_data(client, &data, &bytes);
	if ((ret == AFC_E_SUCCESS) && (bytes > 0) && data) {
		afc_unlock(client);

		/* Get the file handle */
		memcpy(handle, data, sizeof(uint64_t));
		free(data);
		return ret;
	}

	debug_info("Didn't get any further data");

	afc_unlock(client);

	return ret;
}

/**
 * Attempts to the read the given number of bytes from the given file.
 * 
 * @param client The relevant AFC client
 * @param handle File handle of a previously opened file
 * @param data The pointer to the memory region to store the read data
 * @param length The number of bytes to read
 * @param bytes_read The number of bytes actually read.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
idevice_error_t
afc_file_read(afc_client_t client, uint64_t handle, char *data, uint32_t length, uint32_t *bytes_read)
{
	char *input = NULL;
	uint32_t current_count = 0, bytes_loc = 0;
	const uint32_t MAXIMUM_READ_SIZE = 1 << 16;
	afc_error_t ret = AFC_E_SUCCESS;

	if (!client || !client->afc_packet || !client->connection || handle == 0)
		return AFC_E_INVALID_ARG;
	debug_info("called for length %i", length);

	afc_lock(client);

	/* Looping here to get around the maximum amount of data that
	   afc_receive_data can handle */
	while (current_count < length) {
		debug_info("current count is %i but length is %i", current_count, length);

		/* Send the read command */
		AFCFilePacket *packet = (AFCFilePacket *) malloc(sizeof(AFCFilePacket));
		packet->filehandle = handle;
		packet->size = htole64(((length - current_count) < MAXIMUM_READ_SIZE) ? (length - current_count) : MAXIMUM_READ_SIZE);
		client->afc_packet->operation = AFC_OP_READ;
		client->afc_packet->entire_length = client->afc_packet->this_length = 0;
		ret = afc_dispatch_packet(client, (char *) packet, sizeof(AFCFilePacket), &bytes_loc);
		free(packet);

		if (ret != AFC_E_SUCCESS) {
			afc_unlock(client);
			return AFC_E_NOT_ENOUGH_DATA;
		}
		/* Receive the data */
		ret = afc_receive_data(client, &input, &bytes_loc);
		debug_info("afc_receive_data returned error: %d", ret);
		debug_info("bytes returned: %i", bytes_loc);
		if (ret != AFC_E_SUCCESS) {
			afc_unlock(client);
			return ret;
		} else if (bytes_loc == 0) {
			if (input)
				free(input);
			afc_unlock(client);
			*bytes_read = current_count;
			/* FIXME: check that's actually a success */
			return ret;
		} else {
			if (input) {
				debug_info("%d", bytes_loc);
				memcpy(data + current_count, input, (bytes_loc > length) ? length : bytes_loc);
				free(input);
				input = NULL;
				current_count += (bytes_loc > length) ? length : bytes_loc;
			}
		}
	}
	debug_info("returning current_count as %i", current_count);

	afc_unlock(client);
	*bytes_read = current_count;
	return ret;
}

/**
 * Writes a given number of bytes to a file.
 * 
 * @param client The client to use to write to the file.
 * @param handle File handle of previously opened file. 
 * @param data The data to write to the file.
 * @param length How much data to write.
 * @param bytes_written The number of bytes actually written to the file.
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
idevice_error_t
afc_file_write(afc_client_t client, uint64_t handle, const char *data, uint32_t length, uint32_t *bytes_written)
{
	char *acknowledgement = NULL;
	const uint32_t MAXIMUM_WRITE_SIZE = 1 << 15;
	uint32_t current_count = 0, i = 0;
	uint32_t segments = (length / MAXIMUM_WRITE_SIZE);
	uint32_t bytes_loc = 0;
	char *out_buffer = NULL;
	afc_error_t ret = AFC_E_SUCCESS;

	if (!client || !client->afc_packet || !client->connection || !bytes_written || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	debug_info("Write length: %i", length);

	/* Divide the file into segments. */
	for (i = 0; i < segments; i++) {
		/* Send the segment */
		client->afc_packet->this_length = sizeof(AFCPacket) + 8;
		client->afc_packet->entire_length = client->afc_packet->this_length + MAXIMUM_WRITE_SIZE;
		client->afc_packet->operation = AFC_OP_WRITE;
		out_buffer = (char *) malloc(sizeof(char) * client->afc_packet->entire_length - sizeof(AFCPacket));
		memcpy(out_buffer, (char *)&handle, sizeof(uint64_t));
		memcpy(out_buffer + 8, data + current_count, MAXIMUM_WRITE_SIZE);
		ret = afc_dispatch_packet(client, out_buffer, MAXIMUM_WRITE_SIZE + 8, &bytes_loc);
		if (ret != AFC_E_SUCCESS) {
			afc_unlock(client);
			return AFC_E_NOT_ENOUGH_DATA;
		}
		free(out_buffer);
		out_buffer = NULL;

		current_count += bytes_loc;
		ret = afc_receive_data(client, &acknowledgement, &bytes_loc);
		if (ret != AFC_E_SUCCESS) {
			afc_unlock(client);
			return ret;
		} else {
			free(acknowledgement);
		}
	}

	/* By this point, we should be at the end. i.e. the last segment that didn't
	   get sent in the for loop. This length is fine because it's always
	   sizeof(AFCPacket) + 8, but to be sure we do it again */
	if (current_count == length) {
		afc_unlock(client);
		*bytes_written = current_count;
		return ret;
	}

	client->afc_packet->this_length = sizeof(AFCPacket) + 8;
	client->afc_packet->entire_length = client->afc_packet->this_length + (length - current_count);
	client->afc_packet->operation = AFC_OP_WRITE;
	out_buffer = (char *) malloc(sizeof(char) * client->afc_packet->entire_length - sizeof(AFCPacket));
	memcpy(out_buffer, (char *) &handle, sizeof(uint64_t));
	memcpy(out_buffer + 8, data + current_count, (length - current_count));
	ret = afc_dispatch_packet(client, out_buffer, (length - current_count) + 8, &bytes_loc);
	free(out_buffer);
	out_buffer = NULL;

	current_count += bytes_loc;

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		*bytes_written = current_count;
		return AFC_E_SUCCESS;
	}

	ret = afc_receive_data(client, &acknowledgement, &bytes_loc);
	afc_unlock(client);
	if (ret != AFC_E_SUCCESS) {
		debug_info("uh oh?");
	} else {
		free(acknowledgement);
	}
	*bytes_written = current_count;
	return ret;
}

/**
 * Closes a file on the phone.
 * 
 * @param client The client to close the file with.
 * @param handle File handle of a previously opened file.
 */
afc_error_t afc_file_close(afc_client_t client, uint64_t handle)
{
	char *buffer = malloc(sizeof(char) * 8);
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	debug_info("File handle %i", handle);

	/* Send command */
	memcpy(buffer, &handle, sizeof(uint64_t));
	client->afc_packet->operation = AFC_OP_FILE_CLOSE;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	ret = afc_dispatch_packet(client, buffer, 8, &bytes);
	free(buffer);
	buffer = NULL;

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_UNKNOWN_ERROR;
	}

	/* Receive the response */
	ret = afc_receive_data(client, &buffer, &bytes);
	if (buffer)
		free(buffer);

	afc_unlock(client);

	return ret;
}

/**
 * Locks or unlocks a file on the phone. 
 *
 * makes use of flock on the device, see
 * http://developer.apple.com/documentation/Darwin/Reference/ManPages/man2/flock.2.html
 *
 * @param client The client to lock the file with.
 * @param handle File handle of a previously opened file.
 * @param operation the lock or unlock operation to perform, this is one of
 *        AFC_LOCK_SH (shared lock), AFC_LOCK_EX (exclusive lock),
 *        or AFC_LOCK_UN (unlock).
 */
afc_error_t afc_file_lock(afc_client_t client, uint64_t handle, afc_lock_op_t operation)
{
	char *buffer = malloc(16);
	uint32_t bytes = 0;
	uint64_t op = htole64(operation);
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	debug_info("file handle %i", handle);

	/* Send command */
	memcpy(buffer, &handle, sizeof(uint64_t));
	memcpy(buffer + 8, &op, 8);

	client->afc_packet->operation = AFC_OP_FILE_LOCK;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	ret = afc_dispatch_packet(client, buffer, 16, &bytes);
	free(buffer);
	buffer = NULL;

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		debug_info("could not send lock command");
		return AFC_E_UNKNOWN_ERROR;
	}
	/* Receive the response */
	ret = afc_receive_data(client, &buffer, &bytes);
	if (buffer) {
		debug_buffer(buffer, bytes);
		free(buffer);
	}
	afc_unlock(client);

	return ret;
}

/**
 * Seeks to a given position of a pre-opened file on the phone. 
 * 
 * @param client The client to use to seek to the position.
 * @param handle File handle of a previously opened.
 * @param offset Seek offset.
 * @param whence Seeking direction, one of SEEK_SET, SEEK_CUR, or SEEK_END.
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_file_seek(afc_client_t client, uint64_t handle, int64_t offset, int whence)
{
	char *buffer = (char *) malloc(sizeof(char) * 24);
	int64_t offset_loc = (int64_t)htole64(offset);
	uint64_t whence_loc = htole64(whence);
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send the command */
	memcpy(buffer, &handle, sizeof(uint64_t));	/* handle */
	memcpy(buffer + 8, &whence_loc, sizeof(uint64_t));	/* fromwhere */
	memcpy(buffer + 16, &offset_loc, sizeof(uint64_t));	/* offset */
	client->afc_packet->operation = AFC_OP_FILE_SEEK;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	ret = afc_dispatch_packet(client, buffer, 24, &bytes);
	free(buffer);
	buffer = NULL;

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, &buffer, &bytes);
	if (buffer)
		free(buffer);

	afc_unlock(client);

	return ret;
}

/**
 * Returns current position in a pre-opened file on the phone.
 * 
 * @param client The client to use.
 * @param handle File handle of a previously opened file.
 * @param position Position in bytes of indicator
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_file_tell(afc_client_t client, uint64_t handle, uint64_t *position)
{
	char *buffer = (char *) malloc(sizeof(char) * 8);
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send the command */
	memcpy(buffer, &handle, sizeof(uint64_t));	/* handle */
	client->afc_packet->operation = AFC_OP_FILE_TELL;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	ret = afc_dispatch_packet(client, buffer, 8, &bytes);
	free(buffer);
	buffer = NULL;

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}

	/* Receive the data */
	ret = afc_receive_data(client, &buffer, &bytes);
	if (bytes > 0 && buffer) {
		/* Get the position */
		memcpy(position, buffer, sizeof(uint64_t));
		*position = le64toh(*position);
	}
	if (buffer)
		free(buffer);

	afc_unlock(client);

	return ret;
}

/**
 * Sets the size of a file on the phone.
 * 
 * @param client The client to use to set the file size.
 * @param handle File handle of a previously opened file.
 * @param newsize The size to set the file to. 
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 * 
 * @note This function is more akin to ftruncate than truncate, and truncate
 *       calls would have to open the file before calling this, sadly.
 */
afc_error_t afc_file_truncate(afc_client_t client, uint64_t handle, uint64_t newsize)
{
	char *buffer = (char *) malloc(sizeof(char) * 16);
	uint32_t bytes = 0;
	uint64_t newsize_loc = htole64(newsize);
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	memcpy(buffer, &handle, sizeof(uint64_t));	/* handle */
	memcpy(buffer + 8, &newsize_loc, sizeof(uint64_t));	/* newsize */
	client->afc_packet->operation = AFC_OP_FILE_SET_SIZE;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	ret = afc_dispatch_packet(client, buffer, 16, &bytes);
	free(buffer);
	buffer = NULL;

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, &buffer, &bytes);
	if (buffer)
		free(buffer);

	afc_unlock(client);

	return ret;
}

/**
 * Sets the size of a file on the phone without prior opening it.
 * 
 * @param client The client to use to set the file size.
 * @param path The path of the file to be truncated.
 * @param newsize The size to set the file to. 
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_truncate(afc_client_t client, const char *path, uint64_t newsize)
{
	char *response = NULL;
	char *send = (char *) malloc(sizeof(char) * (strlen(path) + 1 + 8));
	uint32_t bytes = 0;
	uint64_t size_requested = htole64(newsize);
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !path || !client->afc_packet || !client->connection)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	memcpy(send, &size_requested, 8);
	memcpy(send + 8, path, strlen(path) + 1);
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	client->afc_packet->operation = AFC_OP_TRUNCATE;
	ret = afc_dispatch_packet(client, send, 8 + strlen(path) + 1, &bytes);
	free(send);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, &response, &bytes);
	if (response)
		free(response);

	afc_unlock(client);

	return ret;
}

/**
 * Creates a hard link or symbolic link on the device. 
 * 
 * @param client The client to use for making a link
 * @param linktype 1 = hard link, 2 = symlink
 * @param target The file to be linked.
 * @param linkname The name of link.
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_make_link(afc_client_t client, afc_link_type_t linktype, const char *target, const char *linkname)
{
	char *response = NULL;
	char *send = (char *) malloc(sizeof(char) * (strlen(target)+1 + strlen(linkname)+1 + 8));
	uint32_t bytes = 0;
	uint64_t type = htole64(linktype);
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !target || !linkname || !client->afc_packet || !client->connection)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	debug_info("link type: %lld", type);
	debug_info("target: %s, length:%d", target, strlen(target));
	debug_info("linkname: %s, length:%d", linkname, strlen(linkname));

	/* Send command */
	memcpy(send, &type, 8);
	memcpy(send + 8, target, strlen(target) + 1);
	memcpy(send + 8 + strlen(target) + 1, linkname, strlen(linkname) + 1);
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	client->afc_packet->operation = AFC_OP_MAKE_LINK;
	ret = afc_dispatch_packet(client, send, 8 + strlen(linkname) + 1 + strlen(target) + 1, &bytes);
	free(send);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, &response, &bytes);
	if (response)
		free(response);

	afc_unlock(client);

	return ret;
}

/**
 * Sets the modification time of a file on the phone.
 * 
 * @param client The client to use to set the file size.
 * @param path Path of the file for which the modification time should be set.
 * @param mtime The modification time to set in nanoseconds since epoch.
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
afc_error_t afc_set_file_time(afc_client_t client, const char *path, uint64_t mtime)
{
	char *response = NULL;
	char *send = (char *) malloc(sizeof(char) * (strlen(path) + 1 + 8));
	uint32_t bytes = 0;
	uint64_t mtime_loc = htole64(mtime);
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !path || !client->afc_packet || !client->connection)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	memcpy(send, &mtime_loc, 8);
	memcpy(send + 8, path, strlen(path) + 1);
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	client->afc_packet->operation = AFC_OP_SET_FILE_TIME;
	ret = afc_dispatch_packet(client, send, 8 + strlen(path) + 1, &bytes);
	free(send);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, &response, &bytes);
	if (response)
		free(response);

	afc_unlock(client);

	return ret;
}

