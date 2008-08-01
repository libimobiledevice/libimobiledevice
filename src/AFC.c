/*
 * AFC.c 
 * Contains functions for the built-in AFC client.
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

#include "AFC.h"

extern int debug;

AFClient *afc_connect(iPhone *phone, int s_port, int d_port) {
	if (!phone) return NULL;
	AFClient *client = (AFClient*)malloc(sizeof(AFClient));
	client->connection = mux_connect(phone, s_port, d_port);
	if (!client->connection) { free(client); return NULL; }
	else {
		client->afc_packet = (AFCPacket*)malloc(sizeof(AFCPacket));
		if (client->afc_packet) {
			client->phone = phone;
			client->afc_packet->packet_num = 0;
			client->afc_packet->unknown1 = client->afc_packet->unknown2 = client->afc_packet->unknown3 = client->afc_packet->unknown4 = client->afc_packet->entire_length = client->afc_packet->this_length = 0;
			client->afc_packet->header1 = 0x36414643;
			client->afc_packet->header2 = 0x4141504C;
			client->file_handle = 0;
			return client;
		} else {
			mux_close_connection(client->phone, client->connection);
			free(client);
			return NULL;
		}
	}
	
	return NULL; // should never get to this point
}

void afc_disconnect(AFClient *client) {
	// client and its members should never be NULL is assumed here.
	if (!client || !client->connection || !client->phone || !client->afc_packet) return;
	mux_close_connection(client->phone, client->connection);
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

int dispatch_AFC_packet(AFClient *client, char *data, int length) {
	char *buffer;
	int bytes = 0, offset = 0;
	if (!client || !client->connection || !client->phone || !client->afc_packet) return 0;
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
			return 0;
		}
		if (debug) printf("dispatch_AFC_packet: fucked-up packet method (probably a write)\n");
		memcpy(buffer+sizeof(AFCPacket), data, offset);
		bytes = mux_send(client->phone, client->connection, buffer, client->afc_packet->this_length);
		free(buffer);
		if (bytes <= 0) { return 0; }
		if (debug) {
			printf("dispatch_AFC_packet: sent the first now go with the second\n");
			printf("Length: %i\n", length-offset);
			printf("Buffer: \n");
			fwrite(data+offset, 1, length-offset, stdout);
		}
		
		
		bytes = mux_send(client->phone, client->connection, data+offset, length-offset);
		if (bytes <= 0) { return 0; }
		else { return bytes; }
	} else {
		if (debug) printf("dispatch_AFC_packet doin things the old way\n");
		char *buffer = (char*)malloc(sizeof(char) * client->afc_packet->this_length);
		if (debug) printf("dispatch_AFC_packet packet length = %i\n", client->afc_packet->this_length);
		memcpy(buffer, (char*)client->afc_packet, sizeof(AFCPacket));
		if (debug) printf("dispatch_AFC_packet packet data follows\n");
		if (length > 0) { memcpy(buffer+sizeof(AFCPacket), data, length); buffer[sizeof(AFCPacket)+length] = '\0'; }
		if (debug) fwrite(buffer, 1, client->afc_packet->this_length, stdout);
		if (debug) printf("\n");
		bytes = mux_send(client->phone, client->connection, buffer, client->afc_packet->this_length);
		if (bytes <= 0) return 0;
		else return bytes;
	}
	return 0;
}

int receive_AFC_data(AFClient *client, char **dump_here) {
	AFCPacket *r_packet;
	char *buffer = (char*)malloc(sizeof(AFCPacket) * 4);
	int bytes = 0, recv_len = 0;
        int retval = 0;
	
	bytes = mux_recv(client->phone, client->connection, buffer, sizeof(AFCPacket) * 4);
	if (bytes <= 0) {
		free(buffer);
		printf("Just didn't get enough.\n");
		*dump_here = NULL;
		return 0;
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

	if (r_packet->operation == 0x01 && !((client->afc_packet->operation == AFC_DELETE && param1 == 7))) {
		if (debug) printf("Oops? Bad operation code received.\n");
		if (param1 == 0) {
			if (debug) printf("... false alarm, but still\n");
			return 1;
		}
		else { if (debug) printf("Errno %i\n", param1); }
		free(r_packet);
		*dump_here = NULL;
		return 0;
	} else {
		if (debug) printf("Operation code %x\nFull length %i and this length %i\n", r_packet->operation, r_packet->entire_length, r_packet->this_length);
	}

	recv_len = r_packet->entire_length - r_packet->this_length;
	free(r_packet);
	if (!recv_len) return bytes;
	buffer = (char*)malloc(sizeof(char) * recv_len);
	bytes = mux_recv(client->phone, client->connection, buffer, recv_len);
	if (bytes <= 0) {
		free(buffer);
		printf("Didn't get it at the second pass.\n");
		*dump_here = NULL;
		return 0;
	}
	
	*dump_here = buffer; // what they do beyond this point = not my problem
	return bytes;
}

char **afc_get_dir_list(AFClient *client, char *dir) {
	client->afc_packet->operation = AFC_LIST_DIR;
	int bytes = 0;
	char *blah = NULL, **list = NULL;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, dir, strlen(dir));
	if (!bytes) return NULL;
	
	bytes = receive_AFC_data(client, &blah);
	if (!bytes && !blah) return NULL;
	
	list = make_strings_list(blah, bytes);
	free(blah);
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
	if (!client || !path || !client->afc_packet || !client->phone ||!client->connection) return 0;

	char *receive = NULL;
	client->afc_packet->this_length = client->afc_packet->entire_length = 0;
	client->afc_packet->operation = AFC_DELETE;
	int bytes;
	bytes = dispatch_AFC_packet(client, path, strlen(path));
	if (bytes <= 0) return 0;
	
	bytes = receive_AFC_data(client, &receive);
	free(receive);
	if (bytes <= 0) return 0;
	else return 1;
}

int afc_rename_file(AFClient *client, const char *from, const char *to) {
	if (!client || !from || !to || !client->afc_packet || !client->phone || !client->connection) return 0;
	
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
	if (bytes <= 0) return 0;
	
	bytes = receive_AFC_data(client, &receive);
	free(receive);
	if (bytes <= 0) return 0;
	else return 1;
}

	
	
AFCFile *afc_get_file_info(AFClient *client, char *path) {
	client->afc_packet->operation = AFC_GET_INFO;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	dispatch_AFC_packet(client, path, strlen(path));
	
	char *received, **list;
	AFCFile *my_file;
	int length, i = 0;
	
	length = receive_AFC_data(client, &received);
	list = make_strings_list(received, length);
	free(received);
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
	if (file_mode != AFC_FILE_READ && file_mode != AFC_FILE_WRITE) return NULL;
	if (!client ||!client->connection || !client->phone ||!client->afc_packet) return NULL;
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
		return NULL;
	} else {
		length_thing = receive_AFC_data(client, &further_data);
		if (length_thing && further_data) {
			file_infos = afc_get_file_info(client, filename);
			memcpy(&file_infos->filehandle, further_data, 4);
			return file_infos;
		} else {
			if (debug) printf("didn't get further data or something\n");
			return NULL;
		}
	}
	if (debug) printf("what the fuck\n");
	return NULL;
}

int afc_read_file(AFClient *client, AFCFile *file, char *data, int length) {
	if (!client || !client->afc_packet || !client->phone || !client->connection || !file) return -1;
	AFCFilePacket *packet = (AFCFilePacket*)malloc(sizeof(AFCFilePacket));
	char *input = NULL;
	packet->unknown1 = packet->unknown2 = 0;
	packet->filehandle = file->filehandle;
	packet->size = length;
	int bytes = 0;
	
	client->afc_packet->operation = AFC_READ;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, (char*)packet, sizeof(AFCFilePacket));
	
	if (bytes > 0) {
		bytes = receive_AFC_data(client, &input);
		if (bytes <= 0) {
			if (input) free(input);
			return -1;
		} else {
			memcpy(data, input, (bytes > length) ? length : bytes);
			free(input);
			return (bytes > length) ? length : bytes;
		}
	} else {
		return -1;
	}
	return 0;
}

int afc_write_file(AFClient *client, AFCFile *file, char *data, int length) {
	char *acknowledgement = NULL;
	if (!client ||!client->afc_packet ||!client->phone || !client->connection || !file) return -1;
	client->afc_packet->this_length = sizeof(AFCPacket) + 8;
	client->afc_packet->entire_length = client->afc_packet->this_length + length;
	client->afc_packet->operation = AFC_WRITE;
	if (debug) printf("afc_write_file: Write length: %i\n", length);
	uint32 zero = 0, bytes = 0;
	
	char *out_buffer = NULL;
	out_buffer = (char*)malloc(sizeof(char) * client->afc_packet->entire_length - sizeof(AFCPacket));
	memcpy(out_buffer, (char*)&file->filehandle, sizeof(uint32));
	memcpy(out_buffer+4, (char*)&zero, sizeof(uint32));
	memcpy(out_buffer+8, data, length);
	
	bytes = dispatch_AFC_packet(client, out_buffer, length + 8);
	if (!bytes) return -1;
	
	zero = bytes;
	bytes = receive_AFC_data(client, &acknowledgement);
	if (bytes <= 0) {
		if (debug) printf("afc_write_file: uh oh?\n");
	}
	
	return zero;
}

void afc_close_file(AFClient *client, AFCFile *file) {
	char *buffer = malloc(sizeof(char) * 8);
	uint32 zero = 0;
	if (debug) printf("File handle %i\n", file->filehandle);
	memcpy(buffer, &file->filehandle, sizeof(uint32));
	memcpy(buffer+sizeof(uint32), &zero, sizeof(zero));
	client->afc_packet->operation = AFC_FILE_CLOSE;
	int bytes = 0;
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	bytes = dispatch_AFC_packet(client, buffer, sizeof(char) * 8);

	free(buffer);
	client->afc_packet->entire_length = client->afc_packet->this_length = 0;
	if (!bytes) return;
	
	bytes = receive_AFC_data(client, &buffer);
	return;
	if (buffer) free(buffer); // we're *SUPPOSED* to get an "error" here. 
}

