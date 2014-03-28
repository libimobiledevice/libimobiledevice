/*
 * afc.c 
 * Contains functions for the built-in AFC client.
 * 
 * Copyright (c) 2009-2014 Nikias Bassen. All Rights Reserved.
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
#include "common/debug.h"
#include "endianness.h"

/**
 * Locks an AFC client, done for thread safety stuff
 * 
 * @param client The AFC client connection to lock
 */
static void afc_lock(afc_client_t client)
{
	debug_info("Locked");
	mutex_lock(&client->mutex);
}

/**
 * Unlocks an AFC client, done for thread safety stuff.
 * 
 * @param client The AFC 
 */
static void afc_unlock(afc_client_t client)
{
	debug_info("Unlocked");
	mutex_unlock(&client->mutex);
}

/**
 * Makes a connection to the AFC service on the device using the given
 * connection.
 *
 * @param service_client A connected service client
 * @param client Pointer that will be set to a newly allocated afc_client_t
 *     upon successful return.
 * 
 * @return AFC_E_SUCCESS on success, AFC_E_INVALID_ARG if connection is
 *  invalid, or AFC_E_NO_MEM if there is a memory allocation problem.
 */

afc_error_t afc_client_new_with_service_client(service_client_t service_client, afc_client_t *client)
{
	if (!service_client)
		return AFC_E_INVALID_ARG;

	afc_client_t client_loc = (afc_client_t) malloc(sizeof(struct afc_client_private));
	client_loc->parent = service_client;
	client_loc->free_parent = 0;

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
	mutex_init(&client_loc->mutex);

	*client = client_loc;
	return AFC_E_SUCCESS;
}

afc_error_t afc_client_new(idevice_t device, lockdownd_service_descriptor_t service, afc_client_t * client)
{
	if (!device || !service || service->port == 0)
		return AFC_E_INVALID_ARG;

	service_client_t parent = NULL;
	if (service_client_new(device, service, &parent) != SERVICE_E_SUCCESS) {
		return AFC_E_MUX_ERROR;
	}

	afc_error_t err = afc_client_new_with_service_client(parent, client);
	if (err != AFC_E_SUCCESS) {
		service_client_free(parent);
	} else {
		(*client)->free_parent = 1;
	}
	return err;
}

afc_error_t afc_client_start_service(idevice_t device, afc_client_t * client, const char* label)
{
	afc_error_t err = AFC_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, AFC_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(afc_client_new), &err);
	return err;
}

afc_error_t afc_client_free(afc_client_t client)
{
	if (!client || !client->afc_packet)
		return AFC_E_INVALID_ARG;

	if (client->free_parent && client->parent) {
		service_client_free(client->parent);
		client->parent = NULL;
	}
	free(client->afc_packet);
	mutex_destroy(&client->mutex);
	free(client);
	return AFC_E_SUCCESS;
}

/**
 * Dispatches an AFC packet over a client.
 * 
 * @param client The client to send data through.
 * @param operation The operation to perform.
 * @param data The data to send together with the header.
 * @param data_length The length of the data to send with the header.
 * @param payload The data to send after the header has been sent.
 * @param payload_length The length of data to send after the header.
 * @param bytes_sent The total number of bytes actually sent.
 *
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
static afc_error_t afc_dispatch_packet(afc_client_t client, uint64_t operation, const char *data, uint32_t data_length, const char* payload, uint32_t payload_length, uint32_t *bytes_sent)
{
	uint32_t sent = 0;

	if (!client || !client->parent || !client->afc_packet)
		return AFC_E_INVALID_ARG;

	*bytes_sent = 0;

	if (!data || !data_length)
		data_length = 0;
	if (!payload || !payload_length)
		payload_length = 0;

	client->afc_packet->packet_num++;
	client->afc_packet->operation = operation;
	client->afc_packet->entire_length = sizeof(AFCPacket) + data_length + payload_length;
	client->afc_packet->this_length = sizeof(AFCPacket) + data_length;

	debug_info("packet length = %i", client->afc_packet->this_length);

	debug_buffer((char*)client->afc_packet, sizeof(AFCPacket));

	/* send AFC packet header */
	AFCPacket_to_LE(client->afc_packet);
	sent = 0;
	service_send(client->parent, (void*)client->afc_packet, sizeof(AFCPacket), &sent);
	AFCPacket_from_LE(client->afc_packet);
	*bytes_sent += sent;
	if (sent < sizeof(AFCPacket)) {
		return AFC_E_SUCCESS;
	}

	/* send AFC packet data (if there's data to send) */
	sent = 0;
	if (data_length > 0) {
		debug_info("packet data follows");
		debug_buffer(data, data_length);
		service_send(client->parent, data, data_length, &sent);
	}
	*bytes_sent += sent;
	if (sent < data_length) {
		return AFC_E_SUCCESS;
	}

	sent = 0;
	if (payload_length > 0) {
		debug_info("packet payload follows");
		debug_buffer(payload, payload_length);
		service_send(client->parent, payload, payload_length, &sent);
	}
	*bytes_sent += sent;
	if (sent < payload_length) {
		return AFC_E_SUCCESS;
	}

	return AFC_E_SUCCESS;
}

/**
 * Receives data through an AFC client and sets a variable to the received data.
 * 
 * @param client The client to receive data on.
 * @param bytes The char* to point to the newly-received data.
 * @param bytes_recv How much data was received.
 * 
 * @return AFC_E_SUCCESS on success or an AFC_E_* error value.
 */
static afc_error_t afc_receive_data(afc_client_t client, char **bytes, uint32_t *bytes_recv)
{
	AFCPacket header;
	uint32_t entire_len = 0;
	uint32_t this_len = 0;
	uint32_t current_count = 0;
	uint64_t param1 = -1;
	char* dump_here = NULL;

	if (bytes_recv) {
		*bytes_recv = 0;
	}
	if (bytes) {
		*bytes = NULL;
	}

	/* first, read the AFC header */
	service_receive(client->parent, (char*)&header, sizeof(AFCPacket), bytes_recv);
	AFCPacket_from_LE(&header);
	if (*bytes_recv == 0) {
		debug_info("Just didn't get enough.");
		return AFC_E_MUX_ERROR;
	} else if (*bytes_recv < sizeof(AFCPacket)) {
		debug_info("Did not even get the AFCPacket header");
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
		return AFC_E_OP_HEADER_INVALID;
	}

	/* then, read the attached packet */
	if (header.this_length < sizeof(AFCPacket)) {
		debug_info("Invalid AFCPacket header received!");
		return AFC_E_OP_HEADER_INVALID;
	} else if ((header.this_length == header.entire_length)
			&& header.entire_length == sizeof(AFCPacket)) {
		debug_info("Empty AFCPacket received!");
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

	dump_here = (char*)malloc(entire_len);
	if (this_len > 0) {
		service_receive(client->parent, dump_here, this_len, bytes_recv);
		if (*bytes_recv <= 0) {
			free(dump_here);
			debug_info("Did not get packet contents!");
			return AFC_E_NOT_ENOUGH_DATA;
		} else if (*bytes_recv < this_len) {
			free(dump_here);
			debug_info("Could not receive this_len=%d bytes", this_len);
			return AFC_E_NOT_ENOUGH_DATA;
		}
	}

	current_count = this_len;

	if (entire_len > this_len) {
		while (current_count < entire_len) {
			service_receive(client->parent, dump_here+current_count, entire_len - current_count, bytes_recv);
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
		param1 = le64toh(*(uint64_t*)(dump_here));
	}

	debug_info("packet data size = %i", current_count);
	debug_info("packet data follows");
	debug_buffer(dump_here, current_count);

	/* check operation types */
	if (header.operation == AFC_OP_STATUS) {
		/* status response */
		debug_info("got a status response, code=%lld", param1);

		if (param1 != AFC_E_SUCCESS) {
			/* error status */
			/* free buffer */
			free(dump_here);
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
		free(dump_here);
		*bytes_recv = 0;

		debug_info("WARNING: Unknown operation code received 0x%llx param1=%lld", header.operation, param1);
#ifndef WIN32
		fprintf(stderr, "%s: WARNING: Unknown operation code received 0x%llx param1=%lld", __func__, (long long)header.operation, (long long)param1);
#endif

		return AFC_E_OP_NOT_SUPPORTED;
	}

	if (bytes) {
		*bytes = dump_here;
	} else {
		free(dump_here);
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

afc_error_t afc_read_directory(afc_client_t client, const char *dir, char ***list)
{
	uint32_t bytes = 0;
	char *data = NULL, **list_loc = NULL;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !dir || !list || (list && *list))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send the command */
	ret = afc_dispatch_packet(client, AFC_OP_READ_DIR, dir, strlen(dir)+1, NULL, 0, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive the data */
	ret = afc_receive_data(client, &data, &bytes);
	if (ret != AFC_E_SUCCESS) {
		if (data)
			free(data);
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

afc_error_t afc_get_device_info(afc_client_t client, char ***infos)
{
	uint32_t bytes = 0;
	char *data = NULL, **list = NULL;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !infos)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send the command */
	ret = afc_dispatch_packet(client, AFC_OP_GET_DEVINFO, NULL, 0, NULL, 0, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive the data */
	ret = afc_receive_data(client, &data, &bytes);
	if (ret != AFC_E_SUCCESS) {
		if (data)
			free(data);
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

afc_error_t afc_remove_path(afc_client_t client, const char *path)
{
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !path || !client->afc_packet || !client->parent)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	ret = afc_dispatch_packet(client, AFC_OP_REMOVE_PATH, path, strlen(path)+1, NULL, 0, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, NULL, &bytes);

	/* special case; unknown error actually means directory not empty */
	if (ret == AFC_E_UNKNOWN_ERROR)
		ret = AFC_E_DIR_NOT_EMPTY;

	afc_unlock(client);

	return ret;
}

afc_error_t afc_rename_path(afc_client_t client, const char *from, const char *to)
{
	char *buffer = (char *) malloc(sizeof(char) * (strlen(from) + strlen(to) + 1 + sizeof(uint32_t)));
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !from || !to || !client->afc_packet || !client->parent)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	memcpy(buffer, from, strlen(from) + 1);
	memcpy(buffer + strlen(from) + 1, to, strlen(to) + 1);
	ret = afc_dispatch_packet(client, AFC_OP_RENAME_PATH, buffer, strlen(to)+1 + strlen(from)+1, NULL, 0, &bytes);
	free(buffer);

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, NULL, &bytes);

	afc_unlock(client);

	return ret;
}

afc_error_t afc_make_directory(afc_client_t client, const char *dir)
{
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	ret = afc_dispatch_packet(client, AFC_OP_MAKE_DIR, dir, strlen(dir)+1, NULL, 0, &bytes);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, NULL, &bytes);

	afc_unlock(client);

	return ret;
}

afc_error_t afc_get_file_info(afc_client_t client, const char *path, char ***infolist)
{
	char *received = NULL;
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !path || !infolist)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	ret = afc_dispatch_packet(client, AFC_OP_GET_FILE_INFO, path, strlen(path)+1, NULL, 0, &bytes);
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

	if (!client || !client->parent || !client->afc_packet)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	memcpy(data, &file_mode_loc, 8);
	memcpy(data + 8, filename, strlen(filename));
	data[8 + strlen(filename)] = '\0';
	ret = afc_dispatch_packet(client, AFC_OP_FILE_OPEN, data, 8 + strlen(filename) + 1, NULL, 0, &bytes);
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

idevice_error_t
afc_file_read(afc_client_t client, uint64_t handle, char *data, uint32_t length, uint32_t *bytes_read)
{
	char *input = NULL;
	uint32_t current_count = 0, bytes_loc = 0;
	afc_error_t ret = AFC_E_SUCCESS;

	if (!client || !client->afc_packet || !client->parent || handle == 0)
		return AFC_E_INVALID_ARG;
	debug_info("called for length %i", length);

	afc_lock(client);

	/* Send the read command */
	struct {
		uint64_t handle;
		uint64_t size;
	} readinfo;
	readinfo.handle = handle;
	readinfo.size = htole64(length);
	ret = afc_dispatch_packet(client, AFC_OP_READ, (const char*)&readinfo, sizeof(readinfo), NULL, 0, &bytes_loc);

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
	afc_unlock(client);
	*bytes_read = current_count;
	return ret;
}

idevice_error_t
afc_file_write(afc_client_t client, uint64_t handle, const char *data, uint32_t length, uint32_t *bytes_written)
{
	uint32_t current_count = 0;
	uint32_t bytes_loc = 0;
	afc_error_t ret = AFC_E_SUCCESS;

	if (!client || !client->afc_packet || !client->parent || !bytes_written || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	debug_info("Write length: %i", length);

	ret = afc_dispatch_packet(client, AFC_OP_WRITE, (const char*)&handle, 8, data, length, &bytes_loc);

	current_count += bytes_loc - (sizeof(AFCPacket) + 8);

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		*bytes_written = current_count;
		return AFC_E_SUCCESS;
	}

	ret = afc_receive_data(client, NULL, &bytes_loc);
	afc_unlock(client);
	if (ret != AFC_E_SUCCESS) {
		debug_info("uh oh?");
	}
	*bytes_written = current_count;
	return ret;
}

afc_error_t afc_file_close(afc_client_t client, uint64_t handle)
{
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	debug_info("File handle %i", handle);

	/* Send command */
	ret = afc_dispatch_packet(client, AFC_OP_FILE_CLOSE, (const char*)&handle, 8, NULL, 0, &bytes);

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_UNKNOWN_ERROR;
	}

	/* Receive the response */
	ret = afc_receive_data(client, NULL, &bytes);

	afc_unlock(client);

	return ret;
}

afc_error_t afc_file_lock(afc_client_t client, uint64_t handle, afc_lock_op_t operation)
{
	uint32_t bytes = 0;
	struct {
		uint64_t handle;
		uint64_t op;
	} lockinfo;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	debug_info("file handle %i", handle);

	/* Send command */
	lockinfo.handle = handle;
	lockinfo.op = htole64(operation);
	ret = afc_dispatch_packet(client, AFC_OP_FILE_LOCK, (const char*)&lockinfo, sizeof(lockinfo), NULL, 0, &bytes);

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		debug_info("could not send lock command");
		return AFC_E_UNKNOWN_ERROR;
	}
	/* Receive the response */
	ret = afc_receive_data(client, NULL, &bytes);

	afc_unlock(client);

	return ret;
}

afc_error_t afc_file_seek(afc_client_t client, uint64_t handle, int64_t offset, int whence)
{
	uint32_t bytes = 0;
	struct {
		uint64_t handle;
		uint64_t whence;
		int64_t offset;
	} seekinfo;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send the command */
	seekinfo.handle = handle;
	seekinfo.whence = htole64(whence);
	seekinfo.offset = (int64_t)htole64(offset);
	ret = afc_dispatch_packet(client, AFC_OP_FILE_SEEK, (const char*)&seekinfo, sizeof(seekinfo), NULL, 0, &bytes);

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, NULL, &bytes);

	afc_unlock(client);

	return ret;
}

afc_error_t afc_file_tell(afc_client_t client, uint64_t handle, uint64_t *position)
{
	char *buffer = (char *) malloc(sizeof(char) * 8);
	uint32_t bytes = 0;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send the command */
	ret = afc_dispatch_packet(client, AFC_OP_FILE_TELL, (const char*)&handle, 8, NULL, 0, &bytes);

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

afc_error_t afc_file_truncate(afc_client_t client, uint64_t handle, uint64_t newsize)
{
	uint32_t bytes = 0;
	struct {
		uint64_t handle;
		uint64_t newsize;
	} truncinfo;
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || (handle == 0))
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	truncinfo.handle = handle;
	truncinfo.newsize = htole64(newsize);
	ret = afc_dispatch_packet(client, AFC_OP_FILE_SET_SIZE, (const char*)&truncinfo, sizeof(truncinfo), NULL, 0, &bytes);

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, NULL, &bytes);

	afc_unlock(client);

	return ret;
}

afc_error_t afc_truncate(afc_client_t client, const char *path, uint64_t newsize)
{
	char *buffer = (char *) malloc(sizeof(char) * (strlen(path) + 1 + 8));
	uint32_t bytes = 0;
	uint64_t size_requested = htole64(newsize);
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !path || !client->afc_packet || !client->parent)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	memcpy(buffer, &size_requested, 8);
	memcpy(buffer + 8, path, strlen(path) + 1);
	ret = afc_dispatch_packet(client, AFC_OP_TRUNCATE, buffer, 8 + strlen(path) + 1, NULL, 0, &bytes);
	free(buffer);

	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, NULL, &bytes);

	afc_unlock(client);

	return ret;
}

afc_error_t afc_make_link(afc_client_t client, afc_link_type_t linktype, const char *target, const char *linkname)
{
	char *buffer = (char *) malloc(sizeof(char) * (strlen(target)+1 + strlen(linkname)+1 + 8));
	uint32_t bytes = 0;
	uint64_t type = htole64(linktype);
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !target || !linkname || !client->afc_packet || !client->parent)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	debug_info("link type: %lld", type);
	debug_info("target: %s, length:%d", target, strlen(target));
	debug_info("linkname: %s, length:%d", linkname, strlen(linkname));

	/* Send command */
	memcpy(buffer, &type, 8);
	memcpy(buffer + 8, target, strlen(target) + 1);
	memcpy(buffer + 8 + strlen(target) + 1, linkname, strlen(linkname) + 1);
	ret = afc_dispatch_packet(client, AFC_OP_MAKE_LINK, buffer, 8 + strlen(linkname) + 1 + strlen(target) + 1, NULL, 0, &bytes);
	free(buffer);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, NULL, &bytes);

	afc_unlock(client);

	return ret;
}

afc_error_t afc_set_file_time(afc_client_t client, const char *path, uint64_t mtime)
{
	char *buffer = (char *) malloc(sizeof(char) * (strlen(path) + 1 + 8));
	uint32_t bytes = 0;
	uint64_t mtime_loc = htole64(mtime);
	afc_error_t ret = AFC_E_UNKNOWN_ERROR;

	if (!client || !path || !client->afc_packet || !client->parent)
		return AFC_E_INVALID_ARG;

	afc_lock(client);

	/* Send command */
	memcpy(buffer, &mtime_loc, 8);
	memcpy(buffer + 8, path, strlen(path) + 1);
	ret = afc_dispatch_packet(client, AFC_OP_SET_FILE_TIME, buffer, 8 + strlen(path) + 1, NULL, 0, &bytes);
	free(buffer);
	if (ret != AFC_E_SUCCESS) {
		afc_unlock(client);
		return AFC_E_NOT_ENOUGH_DATA;
	}
	/* Receive response */
	ret = afc_receive_data(client, NULL, &bytes);

	afc_unlock(client);

	return ret;
}

afc_error_t afc_dictionary_free(char **dictionary)
{
	int i = 0;

	if (!dictionary)
		return AFC_E_INVALID_ARG;

	for (i = 0; dictionary[i]; i++) {
		free(dictionary[i]);
	}
	free(dictionary);

	return AFC_E_SUCCESS;
}
