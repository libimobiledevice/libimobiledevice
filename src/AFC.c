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
#include "AFC.h"
#include "plist.h"


// This is the maximum size an AFC data packet can be
const int MAXIMUM_PACKET_SIZE = (2 << 15) - 32;

extern int debug;

/** Locks an AFC client, done for thread safety stuff
 * 
 * @param client The AFC client connection to lock
 */
static void afc_lock(iphone_afc_client_t client) {
	if (debug) fprintf(stderr, "Locked\n");
	while (client->lock) {
		usleep(500); // they say it's obsolete, but whatever
	}
	client->lock = 1;
}

/** Unlocks an AFC client, done for thread safety stuff.
 * 
 * @param client The AFC 
 */
static void afc_unlock(iphone_afc_client_t client) { // just to be pretty 
	if (debug) fprintf(stderr, "Unlocked\n");
	client->lock = 0; 
}

/** Makes a connection to the AFC service on the phone. 
 * 
 * @param phone The iPhone to connect on.
 * @param s_port The source port. 
 * @param d_port The destination port. 
 * 
 * @return A handle to the newly-connected client or NULL upon error.
 */
iphone_error_t iphone_afc_new_client ( iphone_device_t device, int src_port, int dst_port, iphone_afc_client_t *client ) {
	int ret = IPHONE_E_SUCCESS;
	iphone_afc_client_t client_loc = (iphone_afc_client_t)malloc(sizeof(struct iphone_afc_client_int));
	
	if (!device) return IPHONE_E_INVALID_ARG;
	
	// Attempt connection
	client_loc->connection = NULL;
	ret = iphone_mux_new_client(device, src_port, dst_port,&client_loc->connection);
	if (IPHONE_E_SUCCESS != ret || !client_loc->connection) {
		free(client_loc);
	       	return ret;
	}

	// Allocate a packet
	client_loc->afc_packet = (AFCPacket*)malloc(sizeof(AFCPacket));
	if (!client_loc->afc_packet) {
		iphone_mux_free_client(client_loc->connection);
		free(client_loc);
		return IPHONE_E_UNKNOWN_ERROR;
	}

	client_loc->afc_packet->packet_num = 0;
	client_loc->afc_packet->unknown1 = 0;
	client_loc->afc_packet->unknown2 = 0;
	client_loc->afc_packet->unknown3 = 0;
	client_loc->afc_packet->unknown4 = 0;
	client_loc->afc_packet->entire_length = 0;
	client_loc->afc_packet->this_length = 0;
	client_loc->afc_packet->header1 = 0x36414643;
	client_loc->afc_packet->header2 = 0x4141504C;
	client_loc->file_handle = 0;
	client_loc->lock = 0;

	*client = client_loc;
	return IPHONE_E_SUCCESS;
}

/** Disconnects an AFC client from the phone.
 * 
 * @param client The client to disconnect.
 */
iphone_error_t iphone_afc_free_client ( iphone_afc_client_t client ) {
	if (!client || !client->connection || !client->afc_packet)
		return IPHONE_E_INVALID_ARG;
	
	iphone_mux_free_client(client->connection);
	free(client->afc_packet);
	free(client);
	return IPHONE_E_SUCCESS;
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
static int dispatch_AFC_packet(iphone_afc_client_t client, const char *data, int length) {
	int bytes = 0, offset = 0;
	char *buffer;	

	if (!client || !client->connection || !client->afc_packet) return 0;
	if (!data || !length) length = 0;
	
	client->afc_packet->packet_num++;
	if (!client->afc_packet->entire_length) {
		client->afc_packet->entire_length = (length) ? sizeof(AFCPacket) + length + 1 : sizeof(AFCPacket);
		client->afc_packet->this_length = client->afc_packet->entire_length;
	}
	if (!client->afc_packet->this_length){
		client->afc_packet->this_length = sizeof(AFCPacket);
	}
	
	// We want to send two segments; buffer+sizeof(AFCPacket) to this_length is the parameters
	// And everything beyond that is the next packet. (for writing)
	if (client->afc_packet->this_length != client->afc_packet->entire_length) {
		buffer = (char*)malloc(client->afc_packet->this_length);
		memcpy(buffer, (char*)client->afc_packet, sizeof(AFCPacket));
		offset = client->afc_packet->this_length - sizeof(AFCPacket);
		
		if (debug) fprintf(stderr, "dispatch_AFC_packet: Offset: %i\n", offset);
		if ((length) < (client->afc_packet->entire_length - client->afc_packet->this_length)) {
			if (debug){
				fprintf(stderr, "dispatch_AFC_packet: Length did not resemble what it was supposed");
		       		fprintf(stderr, "to based on the packet.\n");
				fprintf(stderr, "length minus offset: %i\n", length-offset);
				fprintf(stderr, "rest of packet: %i\n", client->afc_packet->entire_length - client->afc_packet->this_length);
			}
			free(buffer);
			return -1;
		}
		memcpy(buffer+sizeof(AFCPacket), data, offset);
		iphone_mux_send(client->connection, buffer, client->afc_packet->this_length, &bytes);
		free(buffer);
		if (bytes <= 0) {
			return bytes;
	       	}
		
		if (debug) {
			fprintf(stderr, "dispatch_AFC_packet: sent the first now go with the second\n");
			fprintf(stderr, "Length: %i\n", length-offset);
			fprintf(stderr, "Buffer: \n");
			fwrite(data+offset, 1, length-offset, stdout);
		}
		
		iphone_mux_send(client->connection, data+offset, length-offset, &bytes);
		return bytes;
	} else {
		if (debug) fprintf(stderr, "dispatch_AFC_packet doin things the old way\n");
		char *buffer = (char*)malloc(sizeof(char) * client->afc_packet->this_length);
		if (debug) fprintf(stderr, "dispatch_AFC_packet packet length = %i\n", client->afc_packet->this_length);
		memcpy(buffer, (char*)client->afc_packet, sizeof(AFCPacket));
		if (debug) fprintf(stderr, "dispatch_AFC_packet packet data follows\n");
		if (length > 0) { memcpy(buffer+sizeof(AFCPacket), data, length); buffer[sizeof(AFCPacket)+length] = '\0'; }
		if (debug) fwrite(buffer, 1, client->afc_packet->this_length, stdout);
		if (debug) fprintf(stderr, "\n");
		iphone_mux_send(client->connection, buffer, client->afc_packet->this_length, &bytes);

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

static int receive_AFC_data(iphone_afc_client_t client, char **dump_here) {
	AFCPacket *r_packet;
	char *buffer = (char*)malloc(sizeof(AFCPacket) * 4);
	char *final_buffer = NULL;
	int bytes = 0, recv_len = 0, current_count=0;
	int retval = 0;
	
	iphone_mux_recv(client->connection, buffer, sizeof(AFCPacket) * 4, &bytes);
	if (bytes <= 0) {
		free(buffer);
		fprintf(stderr, "Just didn't get enough.\n");
		*dump_here = NULL;
		return -1;
	}
	
	r_packet = (AFCPacket*)malloc(sizeof(AFCPacket));
	memcpy(r_packet, buffer, sizeof(AFCPacket));
	
	if (r_packet->entire_length == r_packet->this_length && r_packet->entire_length > sizeof(AFCPacket) && r_packet->operation != AFC_ERROR) {
		*dump_here = (char*)malloc(sizeof(char) * (r_packet->entire_length-sizeof(AFCPacket)));
		memcpy(*dump_here, buffer+sizeof(AFCPacket), r_packet->entire_length-sizeof(AFCPacket));
                retval = r_packet->entire_length - sizeof(AFCPacket);
		free(buffer);
		free(r_packet);
		return retval;
	}
	
	uint32 param1 = buffer[sizeof(AFCPacket)];
	free(buffer);

	if (r_packet->operation == AFC_ERROR && !(client->afc_packet->operation == AFC_DELETE && param1 == 7)) {
		if (debug) fprintf(stderr, "Oops? Bad operation code received: 0x%X, operation=0x%X, param1=%d\n",
				r_packet->operation, client->afc_packet->operation, param1);
		recv_len = r_packet->entire_length - r_packet->this_length;
		free(r_packet);
		if (debug) fprintf(stderr, "recv_len=%d\n", recv_len);
		if(param1 == 0) {
			if (debug) fprintf(stderr, "... false alarm, but still\n");
			*dump_here = NULL;
			return 0;
		}
		else { if (debug) fprintf(stderr, "Errno %i\n", param1); }
		*dump_here = NULL;
		return -1;
	} else {
		if (debug) fprintf(stderr, "Operation code %x\nFull length %i and this length %i\n", r_packet->operation, r_packet->entire_length, r_packet->this_length);
	}

	recv_len = r_packet->entire_length - r_packet->this_length;
	free(r_packet);
	if (!recv_len && r_packet->operation == AFC_SUCCESS_RESPONSE)
	{
		*dump_here = NULL;
		return 0;
	}
	
	// Keep collecting packets until we have received the entire file.
	buffer = (char*)malloc(sizeof(char) * (recv_len < MAXIMUM_PACKET_SIZE) ? recv_len : MAXIMUM_PACKET_SIZE);
	final_buffer = (char*)malloc(sizeof(char) * recv_len);
	while(current_count < recv_len){
		iphone_mux_recv(client->connection, buffer, recv_len-current_count, &bytes);
		if (debug) fprintf(stderr, "receive_AFC_data: still collecting packets\n");
		if (bytes < 0)
		{
			if(debug) fprintf(stderr, "receive_AFC_data: mux_recv failed: %d\n", bytes);
			break;
		}
		if (bytes > recv_len-current_count)
		{
			if(debug) fprintf(stderr, "receive_AFC_data: mux_recv delivered too much data\n");
			break;
		}
		if (bytes > 7 && strstr(buffer, "CFA6LPAA")) {
			if (debug) fprintf(stderr, "receive_AFC_data: WARNING: there is AFC data in this packet at %ti\n", strstr(buffer, "CFA6LPAA") - buffer);
			if (debug) fprintf(stderr, "receive_AFC_data: the total packet length is %i\n", bytes);
		}
			
		memcpy(final_buffer+current_count, buffer, bytes);
		current_count += bytes;
	}
	free(buffer);
	
	*dump_here = final_buffer;
	return current_count;
}

static int count_nullspaces(char *string, int number) {
	int i = 0, nulls = 0;
	
	for (i = 0; i < number; i++) {
		if (string[i] == '\0') nulls++;
	}
	
	return nulls;
}

static char **make_strings_list(char *tokens, int true_length) {
	int nulls = 0, i = 0, j = 0;
	char **list = NULL;
	
	if (!tokens || !true_length) return NULL;
	
	nulls = count_nullspaces(tokens, true_length);
	list = (char**)malloc(sizeof(char*) * (nulls + 1));
	for (i = 0; i < nulls; i++) {
		list[i] = strdup(tokens+j);
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
iphone_error_t iphone_afc_get_dir_list ( iphone_afc_client_t client, const char *dir, char ***list) {
	int bytes = 0;
	char *data = NULL, **list_loc = NULL;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	
	if (!client || !dir || !list || (list && *list)) return IPHONE_E_INVALID_ARG;

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
	if (bytes < 0 && !data) {
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
       	}
	
	// Parse the data
	list_loc = make_strings_list(data, bytes);
	if (list_loc) ret = IPHONE_E_SUCCESS;
	if (data) free(data);

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
iphone_error_t iphone_afc_get_devinfo ( iphone_afc_client_t client, char ***infos) {
	int bytes = 0;
	char *data = NULL, **list = NULL;
	
	if (!client || !infos) return IPHONE_E_INVALID_ARG;

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
	if (bytes < 0 && !data) {
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
	} 
	
	// Parse the data
	list = make_strings_list(data, bytes);
	if (data) free(data);
	
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
iphone_error_t iphone_afc_delete_file ( iphone_afc_client_t client, const char *path) {
	char *response = NULL;
	int bytes;
	
	if (!client || !path || !client->afc_packet || !client->connection) return IPHONE_E_INVALID_ARG;
	
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
	if (response) free(response);
	
	afc_unlock(client);
	
	if (bytes < 0) {
		return IPHONE_E_NOT_ENOUGH_DATA;
	} else {
		return IPHONE_E_SUCCESS;
	}
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
iphone_error_t iphone_afc_rename_file ( iphone_afc_client_t client, const char *from, const char *to) {
	char *response = NULL;
	char *send = (char*)malloc(sizeof(char) * (strlen(from) + strlen(to) + 1 + sizeof(uint32)));
	int bytes = 0;
	
	if (!client || !from || !to || !client->afc_packet || !client->connection) return IPHONE_E_INVALID_ARG;
	
	afc_lock(client);
	
	// Send command
	memcpy(send, from, strlen(from)+1);
	memcpy(send+strlen(from)+1, to, strlen(to)+1);
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
	if (response) free(response);

	afc_unlock(client);
	
	if (bytes < 0) {
		return IPHONE_E_NOT_ENOUGH_DATA;
	} else {
		return IPHONE_E_SUCCESS;
	}
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
iphone_error_t iphone_afc_mkdir ( iphone_afc_client_t client, const char *dir) {
	int bytes = 0;
	char *response = NULL;
	
	if (!client) return IPHONE_E_INVALID_ARG;
	
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
	if (response) free(response);

	afc_unlock(client);
	
	if (bytes < 0) {
		return IPHONE_E_NOT_ENOUGH_DATA;
	} else {
		return IPHONE_E_SUCCESS;
	}
}

/** Gets information about a specific file.
 * 
 * @param client The client to use to get the information of the file.
 * @param path The fully-qualified path to the file. 
 * 
 * @return A pointer to an AFCFile struct containing the information received,
 *         or NULL on failure.
 */
iphone_afc_file_t afc_get_file_info(iphone_afc_client_t client, const char *path) {
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
		my_file = (iphone_afc_file_t)malloc(sizeof(struct iphone_afc_file_int));
		for (i = 0; list[i]; i++) {
			if (!strcmp(list[i], "st_size")) {
				my_file->size = atoi(list[i+1]);
			}
			
			if (!strcmp(list[i], "st_blocks")) {
				my_file->blocks = atoi(list[i+1]);
			}
			
			if (!strcmp(list[i], "st_ifmt")) {
				if (!strcmp(list[i+1], "S_IFREG")) {
					my_file->type = S_IFREG;
				} else if (!strcmp(list[i+1], "S_IFDIR")) {
					my_file->type = S_IFDIR;
				}
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
iphone_error_t iphone_afc_get_file_attr ( iphone_afc_client_t client, const char *filename, struct stat *stbuf ) {

	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	if (!client ||!client->connection || !client->afc_packet || !stbuf) return IPHONE_E_INVALID_ARG;

	memset(stbuf, 0, sizeof(struct stat));
	iphone_afc_file_t file = afc_get_file_info(client, filename);
	if (!file){
		ret = IPHONE_E_NO_SUCH_FILE;
	} else {
		stbuf->st_mode = file->type | (S_ISDIR(file->type) ? 0755 : 0644);
		stbuf->st_size = file->size;
		stbuf->st_blksize = 2048; // FIXME: Is this the actual block size used on the iPhone?
		stbuf->st_blocks = file->blocks;
		stbuf->st_uid = getuid();
		stbuf->st_gid = getgid();

		ret = iphone_afc_close_file(client,file);
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
iphone_error_t iphone_afc_open_file ( iphone_afc_client_t client, const char *filename, iphone_afc_file_mode_t file_mode, iphone_afc_file_t *file ) {
	iphone_afc_file_t file_loc = NULL;
	uint32 ag = 0;
	int bytes = 0, length = 0;
	char *data = (char*)malloc(sizeof(char) * (8 + strlen(filename) + 1));
	
	if (!client ||!client->connection || !client->afc_packet) return IPHONE_E_INVALID_ARG;
	
	afc_lock(client);
	
	// Send command
	memcpy(data, &file_mode, 4);
	memcpy(data+4, &ag, 4);
	memcpy(data+8, filename, strlen(filename));
	data[8+strlen(filename)] = '\0';
	client->afc_packet->operation = AFC_FILE_OPEN;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, data, 8+strlen(filename));
	free(data);
	
	if (bytes <= 0) {
		if (debug) fprintf(stderr, "afc_open_file: Didn't receive a response to the command\n");
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
		if (debug) fprintf(stderr, "afc_open_file: Didn't get any further data\n");
		afc_unlock(client);
		return IPHONE_E_NOT_ENOUGH_DATA;
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
iphone_error_t iphone_afc_read_file ( iphone_afc_client_t client, iphone_afc_file_t file, char *data, int length, uint32_t *bytes) {
	char *input = NULL;
	int current_count = 0, bytes_loc = 0;
	const int MAXIMUM_READ_SIZE = 1 << 16;

	if (!client || !client->afc_packet || !client->connection || !file) return IPHONE_E_INVALID_ARG;
	if (debug) fprintf(stderr, "afc_read_file called for length %i\n", length);

	afc_lock(client);

	// Looping here to get around the maximum amount of data that recieve_AFC_data can handle
	while (current_count < length){
		if (debug) fprintf(stderr, "afc_read_file: current count is %i but length is %i\n", current_count, length);
		
		// Send the read command
		AFCFilePacket *packet = (AFCFilePacket*)malloc(sizeof(AFCFilePacket));
		packet->unknown1 = packet->unknown2 = 0;
		packet->filehandle = file->filehandle;
		packet->size = ((length - current_count) < MAXIMUM_READ_SIZE) ? (length - current_count) : MAXIMUM_READ_SIZE;
		client->afc_packet->operation = AFC_READ;
		client->afc_packet->entire_length = client->afc_packet->this_length = 0;
		bytes_loc = dispatch_AFC_packet(client, (char*)packet, sizeof(AFCFilePacket));
		free(packet);
		
		if (bytes_loc <= 0) {
			afc_unlock(client);
			return IPHONE_E_NOT_ENOUGH_DATA;
		}

		// Receive the data
		bytes_loc = receive_AFC_data(client, &input);
		if (debug) fprintf(stderr, "afc_read_file: bytes returned: %i\n", bytes_loc);
		if (bytes_loc < 0) {
			if (input) free(input);
			afc_unlock(client);
			return IPHONE_E_NOT_ENOUGH_DATA;
		} else if (bytes_loc == 0) {
			if (input) free(input);
			afc_unlock(client);
			*bytes = current_count;
			return IPHONE_E_SUCCESS; //FIXME check that's actually a success
		} else {
			if (input) {
				if (debug) fprintf(stderr, "afc_read_file: %d\n", bytes_loc);
				memcpy(data+current_count, input, (bytes_loc > length) ? length : bytes_loc);
				free(input);
				input = NULL;
				current_count += (bytes_loc > length) ? length : bytes_loc;
			}
		}
	}
	if (debug) fprintf(stderr, "afc_read_file: returning current_count as %i\n", current_count);
	
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
iphone_error_t iphone_afc_write_file ( iphone_afc_client_t client, iphone_afc_file_t file, const char *data, int length, uint32_t *bytes) {
	char *acknowledgement = NULL;
	const int MAXIMUM_WRITE_SIZE = 1 << 16;
	uint32 zero = 0, bytes_loc = 0, segments = (length / MAXIMUM_WRITE_SIZE), current_count = 0, i = 0;
	char *out_buffer = NULL;

	if (!client ||!client->afc_packet || !client->connection || !file || !bytes) return IPHONE_E_INVALID_ARG;
	
	afc_lock(client);

	if (debug) fprintf(stderr, "afc_write_file: Write length: %i\n", length);

	// Divide the file into segments.
	for (i = 0; i < segments; i++) {
		// Send the segment
		client->afc_packet->this_length = sizeof(AFCPacket) + 8;
		client->afc_packet->entire_length = client->afc_packet->this_length + MAXIMUM_WRITE_SIZE;
		client->afc_packet->operation = AFC_WRITE;
		out_buffer = (char*)malloc(sizeof(char) * client->afc_packet->entire_length - sizeof(AFCPacket));
		memcpy(out_buffer, (char*)&file->filehandle, sizeof(uint32));
		memcpy(out_buffer+4, (char*)&zero, sizeof(uint32));
		memcpy(out_buffer+8, data+current_count, MAXIMUM_WRITE_SIZE);
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
			return IPHONE_E_NOT_ENOUGH_DATA;
		}
	}
	
	// By this point, we should be at the end. i.e. the last segment that didn't get sent in the for loop
	// this length is fine because it's always sizeof(AFCPacket) + 8, but to be sure we do it again
	if (current_count == length) {
		afc_unlock(client);
		*bytes = current_count;
		return IPHONE_E_SUCCESS;
	}
	
	client->afc_packet->this_length = sizeof(AFCPacket) + 8;
	client->afc_packet->entire_length = client->afc_packet->this_length + (length - current_count);
	client->afc_packet->operation = AFC_WRITE;
	out_buffer = (char*)malloc(sizeof(char) * client->afc_packet->entire_length - sizeof(AFCPacket));
	memcpy(out_buffer, (char*)&file->filehandle, sizeof(uint32));
	memcpy(out_buffer+4, (char*)&zero, sizeof(uint32));
	memcpy(out_buffer+8, data+current_count, (length - current_count));
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
		if (debug) fprintf(stderr, "afc_write_file: uh oh?\n");
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
iphone_error_t iphone_afc_close_file ( iphone_afc_client_t client, iphone_afc_file_t file) {
	if (!client || !file) return IPHONE_E_INVALID_ARG;
	char *buffer = malloc(sizeof(char) * 8);
	uint32 zero = 0;
	int bytes = 0;
	
	afc_lock(client);
	
	if (debug) fprintf(stderr, "afc_close_file: File handle %i\n", file->filehandle);
	
	// Send command
	memcpy(buffer, &file->filehandle, sizeof(uint32));
	memcpy(buffer+sizeof(uint32), &zero, sizeof(zero));
	client->afc_packet->operation = AFC_FILE_CLOSE;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, buffer, sizeof(char) * 8);
	free(buffer);
	buffer = NULL;

	// FIXME: Is this necesary?
	//client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	
	if (bytes <= 0) { 
		afc_unlock(client); 
		return IPHONE_E_UNKNOWN_ERROR;
	}
	
	// Receive the response
	bytes = receive_AFC_data(client, &buffer);
	if (buffer) free(buffer);
	free(file);
	afc_unlock(client);
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
iphone_error_t iphone_afc_seek_file ( iphone_afc_client_t client, iphone_afc_file_t file, int seekpos) {
	char *buffer = (char*)malloc(sizeof(char) * 24);
	uint32 seekto = 0, bytes = 0, zero = 0;
	
	if (seekpos < 0) seekpos = file->size - abs(seekpos);

	afc_lock(client);
	
	// Send the command
	seekto = seekpos;
	memcpy(buffer, &file->filehandle, sizeof(uint32)); // handle
	memcpy(buffer+4, &zero, sizeof(uint32)); // pad
	memcpy(buffer+8, &zero, sizeof(uint32)); // fromwhere
	memcpy(buffer+12, &zero, sizeof(uint32)); // pad
	memcpy(buffer+16, &seekto, sizeof(uint32)); // offset
	memcpy(buffer+20, &zero, sizeof(uint32)); // pad
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
	if (buffer) free(buffer);
	
	afc_unlock(client);
	
	if (bytes >= 0) {
		return IPHONE_E_SUCCESS;
	} else {
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
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
iphone_error_t iphone_afc_truncate_file ( iphone_afc_client_t client, iphone_afc_file_t file, uint32_t newsize) {
	char *buffer = (char*)malloc(sizeof(char) * 16);
	uint32 bytes = 0, zero = 0;
	
	afc_lock(client);
	
	// Send command
	memcpy(buffer, &file->filehandle, sizeof(uint32)); // handle
	memcpy(buffer+4, &zero, sizeof(uint32)); // pad
	memcpy(buffer+8, &newsize, sizeof(uint32)); // newsize
	memcpy(buffer+12, &zero, 3); // pad
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
	if (buffer) free(buffer);
	
	afc_unlock(client);
	
	if (bytes >= 0) {
		return IPHONE_E_SUCCESS;
	} else {
		return IPHONE_E_NOT_ENOUGH_DATA;
	}
}
