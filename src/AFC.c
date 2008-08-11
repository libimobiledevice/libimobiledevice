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

#include "AFC.h"

// This is the maximum size an AFC data packet can be
const int MAXIMUM_PACKET_SIZE = (2 << 15) - 32;

extern int debug;


/* Locking, for thread-safety (well... kind of, hehe) */
void afc_lock(AFClient *client) {
	if (debug) printf("In the midst of a lock...\n");
	while (client->lock) {
		usleep(500); // they say it's obsolete, but whatever
	}
	client->lock = 1;
}

void afc_unlock(AFClient *client) { // just to be pretty 
	if (debug) printf("Unlock!\n");
	client->lock = 0; 
}

/* main AFC functions */

AFClient *afc_connect(iPhone *phone, int s_port, int d_port) {
	if (!phone) return NULL;
	AFClient *client = (AFClient*)malloc(sizeof(AFClient));
	client->connection = mux_connect(phone, s_port, d_port);
	if (!client->connection) { free(client); return NULL; }
	else {
		client->afc_packet = (AFCPacket*)malloc(sizeof(AFCPacket));
		if (client->afc_packet) {
			client->afc_packet->packet_num = 0;
			client->afc_packet->unknown1 = client->afc_packet->unknown2 = client->afc_packet->unknown3 = client->afc_packet->unknown4 = client->afc_packet->entire_length = client->afc_packet->this_length = 0;
			client->afc_packet->header1 = 0x36414643;
			client->afc_packet->header2 = 0x4141504C;
			client->file_handle = 0;
			client->lock = 0;
			return client;
		} else {
			mux_close_connection(client->connection);
			free(client);
			return NULL;
		}
	}
	
	return NULL; // should never get to this point
}

void afc_disconnect(AFClient *client) {
	// client and its members should never be NULL is assumed here.
	if (!client || !client->connection || !client->afc_packet) return;
	mux_close_connection(client->connection);
	free(client->afc_packet);
	free(client);
}

int count_nullspaces(char *string, int number) {
	int i = 0, nulls = 0;
	for (i = 0; i < number; i++) {
		if (string[i] == '\0') nulls++;
	}
	return nulls;
}

int dispatch_AFC_packet(AFClient *client, const char *data, int length) {
	char *buffer;
	int bytes = 0, offset = 0;
	if (!client || !client->connection || !client->afc_packet) return 0;
	if (!data || !length) length = 0;
	
	client->afc_packet->packet_num++;
	if (!client->afc_packet->entire_length) client->afc_packet->entire_length = client->afc_packet->this_length = (length) ? sizeof(AFCPacket) + length + 1 : sizeof(AFCPacket);
	if (!client->afc_packet->this_length) client->afc_packet->this_length = sizeof(AFCPacket);
		
	if (client->afc_packet->this_length != client->afc_packet->entire_length) {
		// We want to send two segments; buffer+sizeof(AFCPacket) to this_length is the parameters
		// And everything beyond that is the next packet. (for writing)
		char *buffer = (char*)malloc(client->afc_packet->this_length);
		memcpy(buffer, (char*)client->afc_packet, sizeof(AFCPacket));
		offset = client->afc_packet->this_length - sizeof(AFCPacket);
		if (debug) printf("dispatch_AFC_packet: Offset: %i\n", offset);
		if ((length) < (client->afc_packet->entire_length - client->afc_packet->this_length)) {
			if (debug) printf("dispatch_AFC_packet: Length did not resemble what it was supposed to based on the packet.\nlength minus offset: %i\nrest of packet: %i\n", length-offset, client->afc_packet->entire_length - client->afc_packet->this_length);
			free(buffer);
			return -1;
		}
		if (debug) printf("dispatch_AFC_packet: fucked-up packet method (probably a write)\n");
		memcpy(buffer+sizeof(AFCPacket), data, offset);
		bytes = mux_send(client->connection, buffer, client->afc_packet->this_length);
		free(buffer);
		if (bytes <= 0) { return bytes; }
		if (debug) {
			printf("dispatch_AFC_packet: sent the first now go with the second\n");
			printf("Length: %i\n", length-offset);
			printf("Buffer: \n");
			fwrite(data+offset, 1, length-offset, stdout);
		}
		
		
		bytes = mux_send(client->connection, data+offset, length-offset);
		return bytes;
	} else {
		if (debug) printf("dispatch_AFC_packet doin things the old way\n");
		char *buffer = (char*)malloc(sizeof(char) * client->afc_packet->this_length);
		if (debug) printf("dispatch_AFC_packet packet length = %i\n", client->afc_packet->this_length);
		memcpy(buffer, (char*)client->afc_packet, sizeof(AFCPacket));
		if (debug) printf("dispatch_AFC_packet packet data follows\n");
		if (length > 0) { memcpy(buffer+sizeof(AFCPacket), data, length); buffer[sizeof(AFCPacket)+length] = '\0'; }
		if (debug) fwrite(buffer, 1, client->afc_packet->this_length, stdout);
		if (debug) printf("\n");
		bytes = mux_send(client->connection, buffer, client->afc_packet->this_length);
		return bytes;
	}
	return -1;
}

int receive_AFC_data(AFClient *client, char **dump_here) {
	AFCPacket *r_packet;
	char *buffer = (char*)malloc(sizeof(AFCPacket) * 4);
	char *final_buffer = NULL;
	int bytes = 0, recv_len = 0, current_count=0;
	int retval = 0;
	
	bytes = mux_recv(client->connection, buffer, sizeof(AFCPacket) * 4);
	if (bytes <= 0) {
		free(buffer);
		printf("Just didn't get enough.\n");
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

	if (r_packet->operation == AFC_ERROR
			&& !(client->afc_packet->operation == AFC_DELETE && param1 == 7)
	   )
	{
		if (debug) printf("Oops? Bad operation code received: 0x%X, operation=0x%X, param1=%d\n",
				r_packet->operation, client->afc_packet->operation, param1);
		recv_len = r_packet->entire_length - r_packet->this_length;
		if (debug) printf("recv_len=%d\n", recv_len);
		if(param1 == 0) {
			if (debug) printf("... false alarm, but still\n");
			*dump_here = NULL;
			return 0;
		}
		else { if (debug) printf("Errno %i\n", param1); }
		free(r_packet);
		*dump_here = NULL;
		return -1;
	} else {
		if (debug) printf("Operation code %x\nFull length %i and this length %i\n", r_packet->operation, r_packet->entire_length, r_packet->this_length);
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
		bytes = mux_recv(client->connection, buffer, recv_len-current_count);
		if (debug) printf("receive_AFC_data: still collecting packets\n");
		if (bytes < 0)
		{
			if(debug) printf("receive_AFC_data: mux_recv failed: %d\n", bytes);
			break;
		}
		if (bytes > recv_len-current_count)
		{
			if(debug) printf("receive_AFC_data: mux_recv delivered too much data\n");
			break;
		}
		if (strstr(buffer, "CFA6LPAA")) {
			if (debug) printf("receive_AFC_data: WARNING: there is AFC data in this packet at %i\n", strstr(buffer, "CFA6LPAA") - buffer);
			if (debug) printf("receive_AFC_data: the total packet length is %i\n", bytes);
			//continue; // but we do need to continue because packets/headers != data
		}
			
		memcpy(final_buffer+current_count, buffer, bytes);
		current_count += bytes;
	}
	free(buffer);
	
	/*if (bytes <= 0) {
		free(final_buffer);
		printf("Didn't get it at the second pass.\n");
		*dump_here = NULL;
		return 0;
	}*/
	
	*dump_here = final_buffer; // what they do beyond this point = not my problem
	return current_count;
}

char **afc_get_dir_list(AFClient *client, const char *dir) {
	afc_lock(client);
	client->afc_packet->operation = AFC_LIST_DIR;
	int bytes = 0;
	char *blah = NULL, **list = NULL;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, dir, strlen(dir));
	if (bytes <= 0) { afc_unlock(client); return NULL; }
	
	bytes = receive_AFC_data(client, &blah);
	if (bytes < 0 && !blah) { afc_unlock(client); return NULL; }
	
	list = make_strings_list(blah, bytes);
	free(blah);
	afc_unlock(client);
	return list;
}

char **afc_get_devinfo(AFClient *client) {
	afc_lock(client);
	client->afc_packet->operation = AFC_GET_DEVINFO;
	int bytes = 0;
	char *blah = NULL, **list = NULL;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, NULL, 0);
	if (bytes < 0) { afc_unlock(client); return NULL; }
	
	bytes = receive_AFC_data(client, &blah);
	if (bytes < 0 && !blah) { afc_unlock(client); return NULL; } 
	
	list = make_strings_list(blah, bytes);
	free(blah);
	afc_unlock(client);
	return list;
}

	
char **make_strings_list(char *tokens, int true_length) {
	if (!tokens || !true_length) return NULL;
	int nulls = 0, i = 0, j = 0;
	char **list = NULL;
	
	nulls = count_nullspaces(tokens, true_length);
	list = (char**)malloc(sizeof(char*) * (nulls + 1));
	for (i = 0; i < nulls; i++) {
		list[i] = strdup(tokens+j);
		j += strlen(list[i]) + 1;
	}
	list[i] = strdup("");
	return list;
}

int afc_delete_file(AFClient *client, const char *path) {
	if (!client || !path || !client->afc_packet || !client->connection) return 0;
	afc_lock(client);
	char *receive = NULL;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	client->afc_packet->operation = AFC_DELETE;
	int bytes;
	bytes = dispatch_AFC_packet(client, path, strlen(path));
	if (bytes <= 0) { afc_unlock(client); return 0; }
	
	bytes = receive_AFC_data(client, &receive);
	free(receive);
	afc_unlock(client);
	if (bytes < 0) { return 0; }
	else return 1;
}

int afc_rename_file(AFClient *client, const char *from, const char *to) {
	if (!client || !from || !to || !client->afc_packet || !client->connection) return 0;
	afc_lock(client);
	char *receive = NULL;
	char *send = (char*)malloc(sizeof(char) * (strlen(from) + strlen(to) + 1 + sizeof(uint32)));
	int bytes = 0;
	
	memcpy(send, from, strlen(from)+1);
	memcpy(send+strlen(from)+1, to, strlen(to));
	fwrite(send, 1, strlen(from)+1+strlen(to), stdout);
	printf("\n");
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	client->afc_packet->operation = AFC_RENAME;
	bytes = dispatch_AFC_packet(client, send, strlen(to) + strlen(from) + 2);
	if (bytes <= 0) { afc_unlock(client); return 0; }
	
	bytes = receive_AFC_data(client, &receive);
	free(receive);
	afc_unlock(client);
	if (bytes < 0) return 0;
	else return 1;
}

int afc_mkdir(AFClient *client, const char *dir) {
	if (!client) return 0;
	afc_lock(client);
	int bytes = 0;
	char *recvd = NULL;
	
	client->afc_packet->operation = AFC_MAKE_DIR;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	bytes = dispatch_AFC_packet(client, dir, strlen(dir));
	if (bytes <= 0) { afc_unlock(client); return 0; }
	
	bytes = receive_AFC_data(client, &recvd);
	afc_unlock(client);
	if (recvd) { free(recvd); recvd = NULL; }
	if (bytes == 0) return 1;
	else return 0;
}

AFCFile *afc_get_file_info(AFClient *client, const char *path) {
	client->afc_packet->operation = AFC_GET_INFO;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	afc_lock(client);
	dispatch_AFC_packet(client, path, strlen(path));
	
	char *received, **list;
	AFCFile *my_file;
	int length, i = 0;
	
	length = receive_AFC_data(client, &received);
	list = make_strings_list(received, length);
	free(received);
	afc_unlock(client); // the rest is just interpretation anyway
	if (list) {
		my_file = (AFCFile *)malloc(sizeof(AFCFile));
		for (i = 0; strcmp(list[i], ""); i++) {
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
		free_dictionary(list);
		return my_file;
	} else {
		return NULL;
	}
}

AFCFile *afc_open_file(AFClient *client, const char *filename, uint32 file_mode) {
	//if (file_mode != AFC_FILE_READ && file_mode != AFC_FILE_WRITE) return NULL;
	if (!client ||!client->connection || !client->afc_packet) return NULL;
	afc_lock(client);
	char *further_data = (char*)malloc(sizeof(char) * (8 + strlen(filename) + 1));
	AFCFile *file_infos = NULL;
	memcpy(further_data, &file_mode, 4);
	uint32 ag = 0;
	memcpy(further_data+4, &ag, 4);
	memcpy(further_data+8, filename, strlen(filename));
	further_data[8+strlen(filename)] = '\0';
	int bytes = 0, length_thing = 0;
	client->afc_packet->operation = AFC_FILE_OPEN;
	
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, further_data, 8+strlen(filename));
	free(further_data);
	if (bytes <= 0) {
		if (debug) printf("didn't read enough\n");
		afc_unlock(client);
		return NULL;
	} else {
		length_thing = receive_AFC_data(client, &further_data);
		if (length_thing > 0 && further_data) {
			afc_unlock(client); // don't want to hang on the next call... and besides, it'll re-lock, do its thing, and unlock again anyway.
			file_infos = afc_get_file_info(client, filename);
			memcpy(&file_infos->filehandle, further_data, 4);
			return file_infos;
		} else {
			if (debug) printf("didn't get further data or something\n");
			afc_unlock(client);
			return NULL;
		}
	}
	if (debug) printf("what the fuck\n");
	afc_unlock(client);
	return NULL;
}

/** Attempts to the read the given number of bytes from the given file.
 * 
 * @param client The relevant AFC client
 * @param file The AFCFile to read from
 * @param data The pointer to the memory region to store the read data
 * @param length The number of bytes to read
 *
 * @return The number of bytes read if successful. If there was an error
 */
int afc_read_file(AFClient *client, AFCFile *file, char *data, int length) {
	if (!client || !client->afc_packet || !client->connection || !file) return -1;
	if (debug) printf("afc_read_file called for length %i\n", length);

	char *input = NULL;
	int current_count = 0, bytes = 0;
	const int MAXIMUM_READ_SIZE = 1 << 16;

	afc_lock(client);


	// Looping here to get around the maximum amount of data that recieve_AFC_data can handle
	while (current_count < length){
		if (debug) printf("afc_read_file: current count is %i but length is %i\n", current_count, length);
		
		// Send the read command
		AFCFilePacket *packet = (AFCFilePacket*)malloc(sizeof(AFCFilePacket));
		packet->unknown1 = packet->unknown2 = 0;
		packet->filehandle = file->filehandle;
		packet->size = ((length - current_count) < MAXIMUM_READ_SIZE) ? (length - current_count) : MAXIMUM_READ_SIZE;
		client->afc_packet->operation = AFC_READ;
		client->afc_packet->entire_length = client->afc_packet->this_length = 0;
		bytes = dispatch_AFC_packet(client, (char*)packet, sizeof(AFCFilePacket));
		
		// If we get a positive reponse to the command gather the data
		if (bytes > 0) {
			bytes = receive_AFC_data(client, &input);
			if (debug) printf("afc_read_file: bytes returned: %i\n", bytes);
			if (bytes < 0) {
				if (input) free(input);
				afc_unlock(client);
				return -1;
			} else if (bytes == 0) {
				if (input) free(input);
				afc_unlock(client);
				return current_count;
			} else {
				if (input) {
					if (debug) printf("afc_read_file: %d\n", bytes);
					memcpy(data+current_count, input, (bytes > length) ? length : bytes);
					free(input);
					input = NULL;
					current_count += (bytes > length) ? length : bytes;
				}
			}
		} else {
			afc_unlock(client);
			return -1;
		}
	}
	afc_unlock(client);
	if (debug) printf("afc_read_file: returning current_count as %i\n", current_count);
	return current_count;
}

int afc_write_file(AFClient *client, AFCFile *file, const char *data, int length) {
	char *acknowledgement = NULL;
	if (!client ||!client->afc_packet || !client->connection || !file) return -1;
	afc_lock(client);
	if (debug) printf("afc_write_file: Write length: %i\n", length);
	const int MAXIMUM_WRITE_SIZE = 1 << 16;
	uint32 zero = 0, bytes = 0, segments = (length / MAXIMUM_WRITE_SIZE), current_count = 0, i = 0;
	char *out_buffer = NULL;
	
	for (i = 0; i < segments; i++) { // Essentially, yeah, divide it into segments.
		client->afc_packet->this_length = sizeof(AFCPacket) + 8;
		//client->afc_packet->entire_length = client->afc_packet->this_length + length;
		client->afc_packet->entire_length = client->afc_packet->this_length + MAXIMUM_WRITE_SIZE;
		client->afc_packet->operation = AFC_WRITE;
		out_buffer = (char*)malloc(sizeof(char) * client->afc_packet->entire_length - sizeof(AFCPacket));
		memcpy(out_buffer, (char*)&file->filehandle, sizeof(uint32));
		memcpy(out_buffer+4, (char*)&zero, sizeof(uint32));
		memcpy(out_buffer+8, data+current_count, MAXIMUM_WRITE_SIZE);
	
		bytes = dispatch_AFC_packet(client, out_buffer, MAXIMUM_WRITE_SIZE + 8);
		if (bytes < 0) { afc_unlock(client); return bytes; }
		free(out_buffer); out_buffer = NULL; // cleanup and hope it works
		current_count += bytes;
		bytes = receive_AFC_data(client, &acknowledgement); 
		if (bytes < 0) { afc_unlock(client); return current_count; }
	}
	
	// By this point, we should be at the end. i.e. the last segment that didn't get sent in the for loop
	// this length is fine because it's always sizeof(AFCPacket) + 8, but to be sure we do it again
	if (current_count == length) { afc_unlock(client); return current_count; }
	client->afc_packet->this_length = sizeof(AFCPacket) + 8;
	client->afc_packet->entire_length = client->afc_packet->this_length + (length - current_count);
	// operation is already AFC_WRITE, but set again to be sure
	client->afc_packet->operation = AFC_WRITE;
	out_buffer = (char*)malloc(sizeof(char) * client->afc_packet->entire_length - sizeof(AFCPacket));
	memcpy(out_buffer, (char*)&file->filehandle, sizeof(uint32));
	memcpy(out_buffer+4, (char*)&zero, sizeof(uint32));
	memcpy(out_buffer+8, data+current_count, (length - current_count));
	bytes = dispatch_AFC_packet(client, out_buffer, (length - current_count) + 8);
	free(out_buffer); out_buffer = NULL;
	current_count += bytes;
	if (bytes <= 0) { afc_unlock(client); return current_count; }
	
	zero = bytes;
	bytes = receive_AFC_data(client, &acknowledgement);
	afc_unlock(client);
	if (bytes < 0) {
		if (debug) printf("afc_write_file: uh oh?\n");
	}
	
	return current_count;
}

void afc_close_file(AFClient *client, AFCFile *file) {
	char *buffer = malloc(sizeof(char) * 8);
	uint32 zero = 0;
	if (debug) printf("File handle %i\n", file->filehandle);
	afc_lock(client);
	memcpy(buffer, &file->filehandle, sizeof(uint32));
	memcpy(buffer+sizeof(uint32), &zero, sizeof(zero));
	client->afc_packet->operation = AFC_FILE_CLOSE;
	int bytes = 0;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, buffer, sizeof(char) * 8);

	free(buffer);
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	if (bytes <= 0) { afc_unlock(client); return; }
	
	bytes = receive_AFC_data(client, &buffer);
	afc_unlock(client);
	if (buffer) { free(buffer); }
	return;
}

int afc_seek_file(AFClient *client, AFCFile *file, int seekpos) {
	afc_lock(client);
	
	char *buffer = (char*)malloc(sizeof(char) * 24);
	uint32 seekto = 0, bytes = 0, zero = 0;
	if (seekpos < 0) seekpos = file->size - abs(seekpos);
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
	free(buffer); buffer = NULL;
	if (bytes <= 0) { afc_unlock(client); return -1; }
	
	bytes = receive_AFC_data(client, &buffer);
	if (buffer) free(buffer);
	afc_unlock(client);
	if (bytes >= 0) return 0;
	else return -1;
}

int afc_truncate_file(AFClient *client, AFCFile *file, uint32 newsize) {
	afc_lock(client);
	
	char *buffer = (char*)malloc(sizeof(char) * 16);
	uint32 bytes = 0, zero = 0;
	
	memcpy(buffer, &file->filehandle, sizeof(uint32)); // handle
	memcpy(buffer+4, &zero, sizeof(uint32)); // pad
	memcpy(buffer+8, &newsize, sizeof(uint32)); // newsize
	memcpy(buffer+12, &zero, 3); // pad
	client->afc_packet->operation = AFC_FILE_TRUNCATE;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	bytes = dispatch_AFC_packet(client, buffer, 15);
	free(buffer); buffer = NULL;
	if (bytes <= 0) { afc_unlock(client); return -1; }
	
	bytes = receive_AFC_data(client, &buffer);
	if (buffer) free(buffer);
	afc_unlock(client);
	if (bytes >= 0) return 0;
	else return -1;
}

