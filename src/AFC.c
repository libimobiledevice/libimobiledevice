/*
 * AFC.c 
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

#include <stdio.h>
#include <errno.h>
#include "AFC.h"
#include "utils.h"


// This is the maximum size an AFC data packet can be
const int MAXIMUM_PACKET_SIZE = (2 << 15);

/** Locks an AFC client, done for thread safety stuff
 * 
 * @param client The AFC client connection to lock
 */
static void afc_lock(iphone_afc_client_t client)
{
	log_debug_msg("Locked\n");
	/*while (client->lock) {
	   usleep(500);         // they say it's obsolete, but whatever
	   }
	   client->lock = 1; */
	g_mutex_lock(client->mutex);
}

/** Unlocks an AFC client, done for thread safety stuff.
 * 
 * @param client The AFC 
 */
static void afc_unlock(iphone_afc_client_t client)
{								// just to be pretty 
	log_debug_msg("Unlocked\n");
	//client->lock = 0;
	g_mutex_unlock(client->mutex);
}

/** Makes a connection to the AFC service on the phone. 
 * 
 * @param phone The iPhone to connect on.
 * @param s_port The source port. 
 * @param d_port The destination port. 
 * 
 * @return A handle to the newly-connected client or NULL upon error.
 */
iphone_error_t iphone_afc_new_client(iphone_device_t device, int src_port, int dst_port, iphone_afc_client_t * client)
{
	int ret = IPHONE_E_SUCCESS;

	//makes sure thread environment is available
	if (!g_thread_supported())
		g_thread_init(NULL);
	iphone_afc_client_t client_loc = (iphone_afc_client_t) malloc(sizeof(struct iphone_afc_client_int));

	if (!device)
		return IPHONE_E_INVALID_ARG;

	// Attempt connection
	client_loc->connection = NULL;
	ret = iphone_mux_new_client(device, src_port, dst_port, &client_loc->connection);
	if (IPHONE_E_SUCCESS != ret || !client_loc->connection) {
		free(client_loc);
		return ret;
	}
	// Allocate a packet
	client_loc->afc_packet = (AFCPacket *) malloc(sizeof(AFCPacket));
	if (!client_loc->afc_packet) {
		iphone_mux_free_client(client_loc->connection);
		free(client_loc);
		return IPHONE_E_UNKNOWN_ERROR;
	}

	client_loc->afc_packet->packet_num = 0;
	client_loc->afc_packet->entire_length = 0;
	client_loc->afc_packet->this_length = 0;
	memcpy(client_loc->afc_packet->magic, AFC_MAGIC, AFC_MAGIC_LEN);
	client_loc->file_handle = 0;
	client_loc->lock = 0;
	client_loc->mutex = g_mutex_new();

	*client = client_loc;
	return IPHONE_E_SUCCESS;
}

/** Disconnects an AFC client from the phone.
 * 
 * @param client The client to disconnect.
 */
iphone_error_t iphone_afc_free_client(iphone_afc_client_t client)
{
	if (!client || !client->connection || !client->afc_packet)
		return IPHONE_E_INVALID_ARG;

	iphone_mux_free_client(client->connection);
	free(client->afc_packet);
	if (client->mutex) {
		g_mutex_free(client->mutex);
	}
	free(client);
	return IPHONE_E_SUCCESS;
}

/**
 * Returns the AFC error code that has been sent by the device if 
 *  an error occured (set inside receive_AFC_data)
 *
 * @param client AFC client for that the error value is to be retrieved.
 *
 * @return AFC error code or -1 on error.
 */
int iphone_afc_get_afcerror(iphone_afc_client_t client)
{
	int res = -1;
	if (client) {
		afc_lock(client);
		res = client->afcerror;
		afc_unlock(client);
	}
	return res;
}

/** 
 * Tries to convert the AFC error value into a meaningful errno value.
 * Internally used by iphone_afc_get_errno.
 *
 * @param afcerror AFC error value to convert
 *
 * @return errno value or -1 if the errno could not be determined.
 *
 * @see iphone_afc_get_errno
 */
static int afcerror_to_errno(int afcerror)
{
	int res = -1;
	switch (afcerror) {
		case 0: // ERROR_SUCCESS, this means no error.
			res = 0;
			break;
		case 4: // occurs if you try to open a file as directory
			res = ENOTDIR;
			break;
		case 7: // occurs e.g. if you try to close a file handle that
			//  does not belong to an open file
			res = EINVAL;
			break;
		case 8: // occurs if you try to open a non-existent file
			res = ENOENT;
			break;
		case 9: // occurs if you try to open a directory as file
			res = EISDIR;
			break;
		case 10: // occurs if you try to open a file without permission
			res = EPERM;
			break;
		default: // we'll assume it's an errno value, but report it
			log_debug_msg("WARNING: unknown AFC error %d, perhaps it's '%s'?\n", afcerror, strerror(afcerror));
			res = afcerror;
			break;
	}

	log_debug_msg("Mapped AFC error %d to errno %d: %s\n", afcerror, res, strerror(res));

	return res;
}

/**
 * Returns the client's AFC error code converted to an errno value.
 *
 * @param client AFC client for that the errno value is to be retrieved.
 *
 * @return errno value or -1 on error.
 */
int iphone_afc_get_errno(iphone_afc_client_t client)
{
	int res = -1;
	if (client) {
		afc_lock(client);
		res = afcerror_to_errno(client->afcerror);
		afc_unlock(client);
	}
	return res;
}

/** Dispatches an AFC packet over a client.
 * 
 * @param client The client to send data through.
 * @param data The data to send.
 * @param length The length to send.
 * 
 * @return The number of bytes actually sent, or -1 on error. 
 * 
 * @warning set client->afc_packet->this_length and
 *          client->afc_packet->entire_length to 0 before calling this.  The
 *          reason is that if you set them to different values, it indicates
 *          you want to send the data as two packets.
 */
static int dispatch_AFC_packet(iphone_afc_client_t client, const char *data, int length)
{
	int bytes = 0, offset = 0;
	char *buffer;

	if (!client || !client->connection || !client->afc_packet)
		return 0;
	if (!data || !length)
		length = 0;

	client->afc_packet->packet_num++;
	if (!client->afc_packet->entire_length) {
		client->afc_packet->entire_length = (length) ? sizeof(AFCPacket) + length + 1 : sizeof(AFCPacket);
		client->afc_packet->this_length = client->afc_packet->entire_length;
	}
	if (!client->afc_packet->this_length) {
		client->afc_packet->this_length = sizeof(AFCPacket);
	}
	// We want to send two segments; buffer+sizeof(AFCPacket) to
	// this_length is the parameters
	// And everything beyond that is the next packet. (for writing)
	if (client->afc_packet->this_length != client->afc_packet->entire_length) {
		buffer = (char *) malloc(client->afc_packet->this_length);
		memcpy(buffer, (char *) client->afc_packet, sizeof(AFCPacket));
		offset = client->afc_packet->this_length - sizeof(AFCPacket);

		log_debug_msg("dispatch_AFC_packet: Offset: %i\n", offset);
		if ((length) < (client->afc_packet->entire_length - client->afc_packet->this_length)) {
			log_debug_msg("dispatch_AFC_packet: Length did not resemble what it was supposed");
			log_debug_msg("to based on the packet.\n");
			log_debug_msg("length minus offset: %i\n", length - offset);
			log_debug_msg("rest of packet: %i\n", client->afc_packet->entire_length - client->afc_packet->this_length);
			free(buffer);
			return -1;
		}
		memcpy(buffer + sizeof(AFCPacket), data, offset);
		iphone_mux_send(client->connection, buffer, client->afc_packet->this_length, (uint32_t*)&bytes);
		free(buffer);
		if (bytes <= 0) {
			return bytes;
		}

		log_debug_msg("dispatch_AFC_packet: sent the first now go with the second\n");
		log_debug_msg("Length: %i\n", length - offset);
		log_debug_msg("Buffer: \n");
		log_debug_buffer(data + offset, length - offset);

		iphone_mux_send(client->connection, data + offset, length - offset, (uint32_t*)&bytes);
		return bytes;
	} else {
		log_debug_msg("dispatch_AFC_packet doin things the old way\n");
		buffer = (char *) malloc(sizeof(char) * client->afc_packet->this_length);
		log_debug_msg("dispatch_AFC_packet packet length = %i\n", client->afc_packet->this_length);
		memcpy(buffer, (char *) client->afc_packet, sizeof(AFCPacket));
		log_debug_msg("dispatch_AFC_packet packet data follows\n");
		if (length > 0) {
			memcpy(buffer + sizeof(AFCPacket), data, length);
			buffer[sizeof(AFCPacket) + length] = '\0';
		}
		log_debug_buffer(buffer, client->afc_packet->this_length);
		log_debug_msg("\n");
		iphone_mux_send(client->connection, buffer, client->afc_packet->this_length, (uint32_t*)&bytes);

		if (buffer) {
			free(buffer);
			buffer = NULL;
		}
		return bytes;
	}
	return -1;
}

/** Receives data through an AFC client and sets a variable to the received data.
 * 
 * @param client The client to receive data on.
 * @param dump_here The char* to point to the newly-received data.
 * 
 * @return How much data was received, 0 on successful receive with no errors,
 *         -1 if there was an error involved with receiving or if the packet
 *         received raised a non-trivial error condition (i.e. non-zero with
 *         AFC_ERROR operation)
 */
static int receive_AFC_data(iphone_afc_client_t client, char **dump_here)
{
	AFCPacket header;
	int bytes = 0;
	uint32_t entire_len = 0;
	uint32_t this_len = 0;
	uint32_t current_count = 0;
	uint64_t param1 = -1;

	// reset internal afc error value
	client->afcerror = 0;

	// first, read the AFC header
	iphone_mux_recv(client->connection, (char*)&header, sizeof(AFCPacket), (uint32_t*)&bytes);
	if (bytes <= 0) {
		log_debug_msg("%s: Just didn't get enough.\n", __func__);
		*dump_here = NULL;
		return -1;
	} else if ((uint32_t)bytes < sizeof(AFCPacket)) {
		log_debug_msg("%s: Did not even get the AFCPacket header\n", __func__);
		*dump_here = NULL;
		return -1;
	}

	// check if it's a valid AFC header
	if (strncmp(header.magic, AFC_MAGIC, AFC_MAGIC_LEN)) {
		log_debug_msg("%s: Invalid AFC packet received (magic != " AFC_MAGIC ")!\n", __func__);
	}

	// check if it has the correct packet number
	if (header.packet_num != client->afc_packet->packet_num) {
		// otherwise print a warning but do not abort
		log_debug_msg("%s: ERROR: Unexpected packet number (%lld != %lld) aborting.\n", __func__, header.packet_num, client->afc_packet->packet_num);
		*dump_here = NULL;
		return -1;
	}

	// then, read the attached packet
	if (header.this_length < sizeof(AFCPacket)) {
		log_debug_msg("%s: Invalid AFCPacket header received!\n", __func__);
		*dump_here = NULL;
		return -1;
	} else if ((header.this_length == header.entire_length)
			&& header.entire_length == sizeof(AFCPacket)) {
		log_debug_msg("%s: Empty AFCPacket received!\n", __func__);
		*dump_here = NULL;
		if (header.operation == AFC_SUCCESS_RESPONSE) {
			return 0;
		} else {
			client->afcerror = EIO;
			return -1;
		}
	}

	log_debug_msg("%s: received AFC packet, full len=%lld, this len=%lld, operation=%lld\n", __func__, header.entire_length, header.this_length, header.operation);

	entire_len = (uint32_t)header.entire_length - sizeof(AFCPacket);
	this_len = (uint32_t)header.this_length - sizeof(AFCPacket);

	// this is here as a check (perhaps a different upper limit is good?)
	if (entire_len > (uint32_t)MAXIMUM_PACKET_SIZE) {
		fprintf(stderr, "%s: entire_len is larger than MAXIMUM_PACKET_SIZE, (%d > %d)!\n", __func__, entire_len, MAXIMUM_PACKET_SIZE);
	}

	*dump_here = (char*)malloc(entire_len);
	iphone_mux_recv(client->connection, *dump_here, this_len, (uint32_t*)&bytes);
	if (bytes <= 0) {
		free(*dump_here);
		*dump_here = NULL;
		log_debug_msg("%s: Did not get packet contents!\n", __func__);
		return -1;
	} else if ((uint32_t)bytes < this_len) {
		free(*dump_here);
		*dump_here = NULL;
		log_debug_msg("%s: Could not receive this_len=%d bytes\n", __func__, this_len);
		return -1;
	}

	current_count = this_len;

	if (entire_len > this_len) {
		while (current_count < entire_len) {
			iphone_mux_recv(client->connection, (*dump_here)+current_count, entire_len - current_count, (uint32_t*)&bytes);
			if (bytes <= 0) {
				log_debug_msg("%s: Error receiving data (recv returned %d)\n", __func__, bytes);
				break;
			}
			current_count += bytes;
		}
		if (current_count < entire_len) {
			log_debug_msg("%s: WARNING: could not receive full packet (read %s, size %d)\n", __func__, current_count, entire_len);
		}
	}

	if (current_count >= sizeof(uint64_t)) {
		param1 = *(uint64_t*)(*dump_here);
	}

	// check for errors
	if (header.operation == AFC_SUCCESS_RESPONSE) {
		// we got a positive response!
		log_debug_msg("%s: got a success response\n", __func__);
	} else if (header.operation == AFC_FILE_HANDLE) {
		// we got a file handle response
		log_debug_msg("%s: got a file handle response, handle=%lld\n", __func__, param1);
	} else if (header.operation == AFC_ERROR) {
		// error message received
		if (param1 == 0) {
			// ERROR_SUCCESS, this is not an error!
			log_debug_msg("%s: ERROR_SUCCESS\n", __func__);
		} else {
			// but this is an error!
			log_debug_msg("%s: ERROR %lld\n", __func__, param1);
			free(*dump_here);
			*dump_here = NULL;
			// store error value
			client->afcerror = (int)param1;
			afcerror_to_errno(client->afcerror);
			return -1;
		}
	} else {
		// unknown operation code received!
		free(*dump_here);
		*dump_here = NULL;

		log_debug_msg("%s: WARNING: Unknown operation code received 0x%llx param1=%lld\n", __func__, header.operation, param1);
		fprintf(stderr, "%s: WARNING: Unknown operation code received 0x%llx param1=%lld\n", __func__, header.operation, param1);

		return -1;
	}
	return current_count;
}

static int count_nullspaces(char *string, int number)
{
	int i = 0, nulls = 0;

	for (i = 0; i < number; i++) {
		if (string[i] == '\0')
			nulls++;
	}

	return nulls;
}

static char **make_strings_list(char *tokens, int true_length)
{
	int nulls = 0, i = 0, j = 0;
	char **list = NULL;

	if (!tokens || !true_length)
		return NULL;

	nulls = count_nullspaces(tokens, true_length);
	list = (char **) malloc(sizeof(char *) * (nulls + 1));
	for (i = 0; i < nulls; i++) {
		list[i] = strdup(tokens + j);
		j += strlen(list[i]) + 1;
	}
	list[i] = NULL;

	return list;
}

/** Gets a directory listing of the directory requested.
 * 
 * @param client The client to get a directory listing from.
 * @param dir The directory to list. (must be a fully-qualified path)
 * 
 * @return A char ** list of files in that directory, terminated by an empty
 *         string for now or NULL if there was an error.
 */
iphone_error_t iphone_afc_get_dir_list(iphone_afc_client_t client, const char *dir, char ***list)
{
	int bytes = 0;
	char *data = NULL, **list_loc = NULL;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	if (!client || !dir || !list || (list && *list))
		return IPHONE_E_INVALID_ARG;

	afc_lock(client);

	// Send the command
	client->afc_packet->operation = AFC_LIST_DIR;
	client->afc_packet->entire_length = 0;
	client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, dir, strlen(dir));
	if (bytes <= 0) {
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
	// Receive the data
	bytes = receive_AFC_data(client, &data);
	if (bytes < 0) {
		afc_unlock(client);
		return IPHONE_E_AFC_ERROR;
	}
	// Parse the data
	list_loc = make_strings_list(data, bytes);
	if (list_loc)
		ret = IPHONE_E_SUCCESS;
	if (data)
		free(data);

	afc_unlock(client);
	*list = list_loc;

	return ret;
}

/** Get device info for a client connection to phone. (free space on disk, etc.)
 * 
 * @param client The client to get device info for.
 * 
 * @return A char ** list of parameters as given by AFC or NULL if there was an
 *         error.
 */
iphone_error_t iphone_afc_get_devinfo(iphone_afc_client_t client, char ***infos)
{
	int bytes = 0;
	char *data = NULL, **list = NULL;

	if (!client || !infos)
		return IPHONE_E_INVALID_ARG;

	afc_lock(client);

	// Send the command
	client->afc_packet->operation = AFC_GET_DEVINFO;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, NULL, 0);
	if (bytes < 0) {
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
	// Receive the data
	bytes = receive_AFC_data(client, &data);
	if (bytes < 0) {
		afc_unlock(client);
		return IPHONE_E_AFC_ERROR;
	}
	// Parse the data
	list = make_strings_list(data, bytes);
	if (data)
		free(data);

	afc_unlock(client);
	*infos = list;
	return IPHONE_E_SUCCESS;
}

/** Deletes a file.
 * 
 * @param client The client to have delete the file.
 * @param path The file to delete. (must be a fully-qualified path)
 * 
 * @return IPHONE_E_SUCCESS if everythong went well, IPHONE_E_INVALID_ARG
 *         if arguments are NULL or invalid, IPHONE_E_NOT_ENOUGH_DATA otherwise.
 */
iphone_error_t iphone_afc_delete_file(iphone_afc_client_t client, const char *path)
{
	char *response = NULL;
	int bytes;

	if (!client || !path || !client->afc_packet || !client->connection)
		return IPHONE_E_INVALID_ARG;

	afc_lock(client);

	// Send command
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	client->afc_packet->operation = AFC_DELETE;
	bytes = dispatch_AFC_packet(client, path, strlen(path));
	if (bytes <= 0) {
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
	// Receive response
	bytes = receive_AFC_data(client, &response);
	if (response)
		free(response);

	afc_unlock(client);

	if (bytes < 0) {
		return IPHONE_E_AFC_ERROR;
	}
	return IPHONE_E_SUCCESS;
}

/** Renames a file on the phone. 
 * 
 * @param client The client to have rename the file.
 * @param from The file to rename. (must be a fully-qualified path)
 * @param to The new name of the file. (must also be a fully-qualified path)
 * 
 * @return IPHONE_E_SUCCESS if everythong went well, IPHONE_E_INVALID_ARG
 *         if arguments are NULL or invalid, IPHONE_E_NOT_ENOUGH_DATA otherwise.
 */
iphone_error_t iphone_afc_rename_file(iphone_afc_client_t client, const char *from, const char *to)
{
	char *response = NULL;
	char *send = (char *) malloc(sizeof(char) * (strlen(from) + strlen(to) + 1 + sizeof(uint32_t)));
	int bytes = 0;

	if (!client || !from || !to || !client->afc_packet || !client->connection)
		return IPHONE_E_INVALID_ARG;

	afc_lock(client);

	// Send command
	memcpy(send, from, strlen(from) + 1);
	memcpy(send + strlen(from) + 1, to, strlen(to) + 1);
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	client->afc_packet->operation = AFC_RENAME;
	bytes = dispatch_AFC_packet(client, send, strlen(to) + strlen(from) + 2);
	free(send);
	if (bytes <= 0) {
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
	// Receive response
	bytes = receive_AFC_data(client, &response);
	if (response)
		free(response);

	afc_unlock(client);

	if (bytes < 0) {
		return IPHONE_E_AFC_ERROR;
	}
	return IPHONE_E_SUCCESS;
}

/** Creates a directory on the phone.
 * 
 * @param client The client to use to make a directory.
 * @param dir The directory's path. (must be a fully-qualified path, I assume
 *        all other mkdir restrictions apply as well)
 *
 * @return IPHONE_E_SUCCESS if everythong went well, IPHONE_E_INVALID_ARG
 *         if arguments are NULL or invalid, IPHONE_E_NOT_ENOUGH_DATA otherwise.
 */
iphone_error_t iphone_afc_mkdir(iphone_afc_client_t client, const char *dir)
{
	int bytes = 0;
	char *response = NULL;

	if (!client)
		return IPHONE_E_INVALID_ARG;

	afc_lock(client);

	// Send command
	client->afc_packet->operation = AFC_MAKE_DIR;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	bytes = dispatch_AFC_packet(client, dir, strlen(dir));
	if (bytes <= 0) {
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
	// Receive response
	bytes = receive_AFC_data(client, &response);
	if (response)
		free(response);

	afc_unlock(client);

	if (bytes < 0) {
		return IPHONE_E_AFC_ERROR;
	}
	return IPHONE_E_SUCCESS;
}

/** Gets information about a specific file.
 * 
 * @param client The client to use to get the information of the file.
 * @param path The fully-qualified path to the file. 
 * 
 * @return A pointer to an AFCFile struct containing the information received,
 *         or NULL on failure.
 */
static iphone_afc_file_t afc_get_file_info(iphone_afc_client_t client, const char *path)
{
	char *received, **list;
	iphone_afc_file_t my_file;
	int length, i = 0;

	afc_lock(client);

	// Send command
	client->afc_packet->operation = AFC_GET_INFO;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	dispatch_AFC_packet(client, path, strlen(path));

	// Receive data
	length = receive_AFC_data(client, &received);
	if (received) {
		list = make_strings_list(received, length);
		free(received);
	} else {
		afc_unlock(client);
		return NULL;
	}

	afc_unlock(client);

	// Parse the data
	if (list) {
		my_file = (iphone_afc_file_t) malloc(sizeof(struct iphone_afc_file_int));
		for (i = 0; list[i]; i++) {
			if (!strcmp(list[i], "st_size")) {
				my_file->size = atoll(list[i + 1]);
			}

			if (!strcmp(list[i], "st_blocks")) {
				my_file->blocks = atoi(list[i + 1]);
			}

			if (!strcmp(list[i], "st_ifmt")) {
				if (!strcmp(list[i + 1], "S_IFREG")) {
					my_file->mode = S_IFREG;
				} else if (!strcmp(list[i + 1], "S_IFDIR")) {
					my_file->mode = S_IFDIR;
				} else if (!strcmp(list[i + 1], "S_IFLNK")) {
					my_file->mode = S_IFLNK;
				}
			}

			if (!strcmp(list[i], "st_nlink")) {
				my_file->nlink = atoi(list[i + 1]);
			}
		}
		g_strfreev(list);
		return my_file;
	} else {
		return NULL;
	}
}

/** Gets information about a specific file.
 * 
 * @param client The client to use to get the information of the file.
 * @param path The fully-qualified path to the file
 * @param stbuf output buffer where file information will be stored 
 * 
 * @return A pointer to an AFCFile struct containing the information received,
 *         or NULL on failure.
 */
iphone_error_t iphone_afc_get_file_attr(iphone_afc_client_t client, const char *filename, struct stat * stbuf)
{

	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	if (!client || !client->connection || !client->afc_packet || !stbuf)
		return IPHONE_E_INVALID_ARG;

	memset(stbuf, 0, sizeof(struct stat));
	iphone_afc_file_t file = afc_get_file_info(client, filename);
	if (!file) {
		ret = IPHONE_E_AFC_ERROR;
	} else {
		stbuf->st_mode = file->mode | (S_ISDIR(file->mode) ? 0755 : (S_ISLNK(file->mode) ? 0777 : 0644));
		stbuf->st_size = file->size;
		stbuf->st_blksize = 2048;	// FIXME: Is this the actual block 
		// size used on the iPhone?
		stbuf->st_blocks = file->blocks;
		stbuf->st_nlink = file->nlink;
		stbuf->st_uid = getuid();
		stbuf->st_gid = getgid();

		free(file);
		ret = IPHONE_E_SUCCESS;
	}
	return ret;
}

/** Opens a file on the phone.
 * 
 * @param client The client to use to open the file. 
 * @param filename The file to open. (must be a fully-qualified path)
 * @param file_mode The mode to use to open the file. Can be AFC_FILE_READ or
 * 		    AFC_FILE_WRITE; the former lets you read and write,
 * 		    however, and the second one will *create* the file,
 * 		    destroying anything previously there.
 * 
 * @return A pointer to an AFCFile struct containing the file information (as
 *         received by afc_get_file_info) as well as the handle to the file or
 *         NULL in the case of failure.
 */
iphone_error_t
iphone_afc_open_file(iphone_afc_client_t client, const char *filename,
					 iphone_afc_file_mode_t file_mode, iphone_afc_file_t * file)
{
	iphone_afc_file_t file_loc = NULL;
	uint32_t ag = 0;
	int bytes = 0, length = 0;
	char *data = (char *) malloc(sizeof(char) * (8 + strlen(filename) + 1));

	if (!client || !client->connection || !client->afc_packet)
		return IPHONE_E_INVALID_ARG;

	afc_lock(client);

	// Send command
	memcpy(data, &file_mode, 4);
	memcpy(data + 4, &ag, 4);
	memcpy(data + 8, filename, strlen(filename));
	data[8 + strlen(filename)] = '\0';
	client->afc_packet->operation = AFC_FILE_OPEN;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, data, 8 + strlen(filename));
	free(data);

	if (bytes <= 0) {
		log_debug_msg("afc_open_file: Didn't receive a response to the command\n");
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
	// Receive the data
	length = receive_AFC_data(client, &data);
	if (length > 0 && data) {
		afc_unlock(client);

		// Get the file info and return it
		file_loc = afc_get_file_info(client, filename);
		memcpy(&file_loc->filehandle, data, 4);
		free(data);
		*file = file_loc;
		return IPHONE_E_SUCCESS;
	} else {
		log_debug_msg("afc_open_file: Didn't get any further data\n");
		afc_unlock(client);
		return IPHONE_E_AFC_ERROR;
	}

	afc_unlock(client);

	return IPHONE_E_UNKNOWN_ERROR;
}

/** Attempts to the read the given number of bytes from the given file.
 * 
 * @param client The relevant AFC client
 * @param file The AFCFile to read from
 * @param data The pointer to the memory region to store the read data
 * @param length The number of bytes to read
 *
 * @return The number of bytes read if successful. If there was an error -1.
 */
iphone_error_t
iphone_afc_read_file(iphone_afc_client_t client, iphone_afc_file_t file, char *data, int length, uint32_t * bytes)
{
	char *input = NULL;
	int current_count = 0, bytes_loc = 0;
	const int MAXIMUM_READ_SIZE = 1 << 16;

	if (!client || !client->afc_packet || !client->connection || !file)
		return IPHONE_E_INVALID_ARG;
	log_debug_msg("afc_read_file called for length %i\n", length);

	afc_lock(client);

	// Looping here to get around the maximum amount of data that
	// recieve_AFC_data can handle
	while (current_count < length) {
		log_debug_msg("afc_read_file: current count is %i but length is %i\n", current_count, length);

		// Send the read command
		AFCFilePacket *packet = (AFCFilePacket *) malloc(sizeof(AFCFilePacket));
		packet->filehandle = file->filehandle;
		packet->size = ((length - current_count) < MAXIMUM_READ_SIZE) ? (length - current_count) : MAXIMUM_READ_SIZE;
		client->afc_packet->operation = AFC_READ;
		client->afc_packet->entire_length = client->afc_packet->this_length = 0;
		bytes_loc = dispatch_AFC_packet(client, (char *) packet, sizeof(AFCFilePacket));
		free(packet);

		if (bytes_loc <= 0) {
			afc_unlock(client);
			return IPHONE_E_NOT_ENOUGH_DATA;
		}
		// Receive the data
		bytes_loc = receive_AFC_data(client, &input);
		log_debug_msg("afc_read_file: bytes returned: %i\n", bytes_loc);
		if (bytes_loc < 0) {
			afc_unlock(client);
			return IPHONE_E_AFC_ERROR;
		} else if (bytes_loc == 0) {
			if (input)
				free(input);
			afc_unlock(client);
			*bytes = current_count;
			return IPHONE_E_SUCCESS;	// FIXME check that's actually a
			// success
		} else {
			if (input) {
				log_debug_msg("afc_read_file: %d\n", bytes_loc);
				memcpy(data + current_count, input, (bytes_loc > length) ? length : bytes_loc);
				free(input);
				input = NULL;
				current_count += (bytes_loc > length) ? length : bytes_loc;
			}
		}
	}
	log_debug_msg("afc_read_file: returning current_count as %i\n", current_count);

	afc_unlock(client);
	*bytes = current_count;
	return IPHONE_E_SUCCESS;
}

/** Writes a given number of bytes to a file.
 * 
 * @param client The client to use to write to the file.
 * @param file A pointer to an AFCFile struct; serves as the file handle. 
 * @param data The data to write to the file.
 * @param length How much data to write.
 * 
 * @return The number of bytes written to the file, or a value less than 0 if
 *         none were written...
 */
iphone_error_t
iphone_afc_write_file(iphone_afc_client_t client, iphone_afc_file_t file,
					  const char *data, int length, uint32_t * bytes)
{
	char *acknowledgement = NULL;
	const int MAXIMUM_WRITE_SIZE = 1 << 15;
	uint32_t zero = 0, current_count = 0, i = 0;
	uint32_t segments = (length / MAXIMUM_WRITE_SIZE);
	int bytes_loc = 0;
	char *out_buffer = NULL;

	if (!client || !client->afc_packet || !client->connection || !file || !bytes)
		return IPHONE_E_INVALID_ARG;

	afc_lock(client);

	log_debug_msg("afc_write_file: Write length: %i\n", length);

	// Divide the file into segments.
	for (i = 0; i < segments; i++) {
		// Send the segment
		client->afc_packet->this_length = sizeof(AFCPacket) + 8;
		client->afc_packet->entire_length = client->afc_packet->this_length + MAXIMUM_WRITE_SIZE;
		client->afc_packet->operation = AFC_WRITE;
		out_buffer = (char *) malloc(sizeof(char) * client->afc_packet->entire_length - sizeof(AFCPacket));
		memcpy(out_buffer, (char *) &file->filehandle, sizeof(uint32_t));
		memcpy(out_buffer + 4, (char *) &zero, sizeof(uint32_t));
		memcpy(out_buffer + 8, data + current_count, MAXIMUM_WRITE_SIZE);
		bytes_loc = dispatch_AFC_packet(client, out_buffer, MAXIMUM_WRITE_SIZE + 8);
		if (bytes_loc < 0) {
			afc_unlock(client);
			return IPHONE_E_NOT_ENOUGH_DATA;
		}
		free(out_buffer);
		out_buffer = NULL;

		current_count += bytes_loc;
		bytes_loc = receive_AFC_data(client, &acknowledgement);
		if (bytes_loc < 0) {
			afc_unlock(client);
			return IPHONE_E_AFC_ERROR;
		} else {
			free(acknowledgement);
		}
	}

	// By this point, we should be at the end. i.e. the last segment that
	// didn't get sent in the for loop
	// this length is fine because it's always sizeof(AFCPacket) + 8, but
	// to be sure we do it again
	if (current_count == (uint32_t)length) {
		afc_unlock(client);
		*bytes = current_count;
		return IPHONE_E_SUCCESS;
	}

	client->afc_packet->this_length = sizeof(AFCPacket) + 8;
	client->afc_packet->entire_length = client->afc_packet->this_length + (length - current_count);
	client->afc_packet->operation = AFC_WRITE;
	out_buffer = (char *) malloc(sizeof(char) * client->afc_packet->entire_length - sizeof(AFCPacket));
	memcpy(out_buffer, (char *) &file->filehandle, sizeof(uint32_t));
	memcpy(out_buffer + 4, (char *) &zero, sizeof(uint32_t));
	memcpy(out_buffer + 8, data + current_count, (length - current_count));
	bytes_loc = dispatch_AFC_packet(client, out_buffer, (length - current_count) + 8);
	free(out_buffer);
	out_buffer = NULL;

	current_count += bytes_loc;

	if (bytes_loc <= 0) {
		afc_unlock(client);
		*bytes = current_count;
		return IPHONE_E_SUCCESS;
	}

	zero = bytes_loc;
	bytes_loc = receive_AFC_data(client, &acknowledgement);
	afc_unlock(client);
	if (bytes_loc < 0) {
		log_debug_msg("afc_write_file: uh oh?\n");
	} else {
		free(acknowledgement);
	}
	*bytes = current_count;
	return IPHONE_E_SUCCESS;
}

/** Closes a file on the phone. 
 * 
 * @param client The client to close the file with.
 * @param file A pointer to an AFCFile struct containing the file handle of the
 *        file to close.
 */
iphone_error_t iphone_afc_close_file(iphone_afc_client_t client, iphone_afc_file_t file)
{
	if (!client || !file)
		return IPHONE_E_INVALID_ARG;
	char *buffer = malloc(sizeof(char) * 8);
	uint32_t zero = 0;
	int bytes = 0;

	afc_lock(client);

	log_debug_msg("afc_close_file: File handle %i\n", file->filehandle);

	// Send command
	memcpy(buffer, &file->filehandle, sizeof(uint32_t));
	memcpy(buffer + sizeof(uint32_t), &zero, sizeof(zero));
	client->afc_packet->operation = AFC_FILE_CLOSE;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, buffer, sizeof(char) * 8);
	free(buffer);
	buffer = NULL;

	// FIXME: Is this necesary?
	// client->afc_packet->entire_length = client->afc_packet->this_length 
	// = 0;

	if (bytes <= 0) {
		afc_unlock(client);
		return IPHONE_E_UNKNOWN_ERROR;
	}
	// Receive the response
	bytes = receive_AFC_data(client, &buffer);
	if (buffer)
		free(buffer);
	free(file);
	afc_unlock(client);
	return IPHONE_E_SUCCESS;
}

/** Locks or unlocks a file on the phone. 
 *
 * makes use of flock, see
 * http://developer.apple.com/documentation/Darwin/Reference/ManPages/man2/flock.2.html
 *
 * operation (same as in sys/file.h on linux):
 *
 * LOCK_SH   1    // shared lock
 * LOCK_EX   2   // exclusive lock
 * LOCK_NB   4   // don't block when locking
 * LOCK_UN   8   // unlock
 *
 * @param client The client to close the file with.
 * @param file A pointer to an AFCFile struct containing the file handle of the
 *        file to close.
 * @operation the lock or unlock operation to perform.
 */
iphone_error_t iphone_afc_lock_file(iphone_afc_client_t client, iphone_afc_file_t file, int operation)
{
	if (!client || !file)
		return IPHONE_E_INVALID_ARG;
	char *buffer = malloc(16);
	uint32_t zero = 0;
	int bytes = 0;
	uint64_t op = operation;

	afc_lock(client);

	log_debug_msg("afc_lock_file: File handle %i\n", file->filehandle);

	// Send command
	memcpy(buffer, &file->filehandle, sizeof(uint32_t));
	memcpy(buffer + sizeof(uint32_t), &zero, sizeof(zero));
	memcpy(buffer + 8, &op, 8);

	client->afc_packet->operation = AFC_FILE_LOCK;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, buffer, 15);
	free(buffer);
	buffer = NULL;

	if (bytes <= 0) {
		afc_unlock(client);
		log_debug_msg("fuck\n");
		return IPHONE_E_UNKNOWN_ERROR;
	}
	// Receive the response
	bytes = receive_AFC_data(client, &buffer);
	if (buffer) {
		log_debug_buffer(buffer, bytes);
		free(buffer);
	}
	afc_unlock(client);
	if (bytes < 0) {
		return IPHONE_E_AFC_ERROR;
	}
	return IPHONE_E_SUCCESS;
}

/** Seeks to a given position of a pre-opened file on the phone. 
 * 
 * @param client The client to use to seek to the position.
 * @param file The file to seek to a position on.
 * @param seekpos Where to seek to. If passed a negative value, this will seek
 *        from the end of the file. 
 * 
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_NOT_ENOUGH_DATA on failure.
 */
iphone_error_t iphone_afc_seek_file(iphone_afc_client_t client, iphone_afc_file_t file, int seekpos)
{
	char *buffer = (char *) malloc(sizeof(char) * 24);
	uint32_t seekto = 0, zero = 0;
	int bytes = 0;

	if (seekpos < 0)
		seekpos = file->size - abs(seekpos);

	afc_lock(client);

	// Send the command
	seekto = seekpos;
	memcpy(buffer, &file->filehandle, sizeof(uint32_t));	// handle
	memcpy(buffer + 4, &zero, sizeof(uint32_t));	// pad
	memcpy(buffer + 8, &zero, sizeof(uint32_t));	// fromwhere
	memcpy(buffer + 12, &zero, sizeof(uint32_t));	// pad
	memcpy(buffer + 16, &seekto, sizeof(uint32_t));	// offset
	memcpy(buffer + 20, &zero, sizeof(uint32_t));	// pad
	client->afc_packet->operation = AFC_FILE_SEEK;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	bytes = dispatch_AFC_packet(client, buffer, 23);
	free(buffer);
	buffer = NULL;

	if (bytes <= 0) {
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
	// Receive response
	bytes = receive_AFC_data(client, &buffer);
	if (buffer)
		free(buffer);

	afc_unlock(client);

	if (bytes < 0) {
		return IPHONE_E_AFC_ERROR;
	}
	return IPHONE_E_SUCCESS;
}

/** Sets the size of a file on the phone.
 * 
 * @param client The client to use to set the file size.
 * @param file The (pre-opened) file to set the size on.
 * @param newsize The size to set the file to. 
 * 
 * @return 0 on success, -1 on failure. 
 * 
 * @note This function is more akin to ftruncate than truncate, and truncate
 *       calls would have to open the file before calling this, sadly.
 */
iphone_error_t iphone_afc_truncate_file(iphone_afc_client_t client, iphone_afc_file_t file, uint32_t newsize)
{
	char *buffer = (char *) malloc(sizeof(char) * 16);
	int bytes = 0;
	uint32_t zero = 0;

	afc_lock(client);

	// Send command
	memcpy(buffer, &file->filehandle, sizeof(uint32_t));	// handle
	memcpy(buffer + 4, &zero, sizeof(uint32_t));	// pad
	memcpy(buffer + 8, &newsize, sizeof(uint32_t));	// newsize
	memcpy(buffer + 12, &zero, 3);	// pad
	client->afc_packet->operation = AFC_FILE_TRUNCATE;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	bytes = dispatch_AFC_packet(client, buffer, 15);
	free(buffer);
	buffer = NULL;

	if (bytes <= 0) {
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
	// Receive response
	bytes = receive_AFC_data(client, &buffer);
	if (buffer)
		free(buffer);

	afc_unlock(client);

	if (bytes < 0) {
		return IPHONE_E_AFC_ERROR;
	}
	return IPHONE_E_SUCCESS;
}

/** Sets the size of a file on the phone without prior opening it.
 * 
 * @param client The client to use to set the file size.
 * @param path The path of the file to be truncated.
 * @param newsize The size to set the file to. 
 * 
 * @return IPHONE_E_SUCCESS if everything went well, IPHONE_E_INVALID_ARG
 *         if arguments are NULL or invalid, IPHONE_E_NOT_ENOUGH_DATA otherwise.
 */
iphone_error_t iphone_afc_truncate(iphone_afc_client_t client, const char *path, off_t newsize)
{
	char *response = NULL;
	char *send = (char *) malloc(sizeof(char) * (strlen(path) + 1 + 8));
	int bytes = 0;
	uint64_t size_requested = newsize;

	if (!client || !path || !client->afc_packet || !client->connection)
		return IPHONE_E_INVALID_ARG;

	afc_lock(client);

	// Send command
	memcpy(send, &size_requested, 8);
	memcpy(send + 8, path, strlen(path) + 1);
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	client->afc_packet->operation = AFC_TRUNCATE;
	bytes = dispatch_AFC_packet(client, send, 8 + strlen(path));
	free(send);
	if (bytes <= 0) {
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
	// Receive response
	bytes = receive_AFC_data(client, &response);
	if (response)
		free(response);

	afc_unlock(client);

	if (bytes < 0) {
		return IPHONE_E_AFC_ERROR;
	}
	return IPHONE_E_SUCCESS;
}


uint32_t iphone_afc_get_file_handle(iphone_afc_file_t file)
{
	return file->filehandle;
}
