/*
 * AFC.c -- contains functions for the built-in AFC client.
 * Written by FxChiP
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
			client->afc_packet->unknown1 = client->afc_packet->unknown2 = client->afc_packet->unknown3 = client->afc_packet->unknown4 = 0;
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
	int bytes = 0;
	if (!client || !client->connection || !client->phone || !client->afc_packet) return 0;
	if (!data || !length) length = 0;
	
	client->afc_packet->packet_num++;
	client->afc_packet->entire_length = client->afc_packet->this_length = (length) ? sizeof(AFCPacket) + length + 1 : sizeof(AFCPacket);
	
	if (!length) {
		bytes = mux_send(client->phone, client->connection, (char*)client->afc_packet, client->afc_packet->this_length);
		if (bytes <= 0) return 0;
		else return bytes;
	} else {
		buffer = (char*)malloc(sizeof(char) * client->afc_packet->this_length);
		memcpy(buffer, client->afc_packet, sizeof(AFCPacket));
		memcpy(buffer+sizeof(AFCPacket), data, length);
		buffer[client->afc_packet->this_length-1] = '\0';
		
		bytes = mux_send(client->phone, client->connection, buffer, client->afc_packet->this_length);
		free(buffer); // don't need it
		if (bytes <= 0) return 0;
		else return bytes;
	}
	
	return 0;
}

int receive_AFC_data(AFClient *client, char **dump_here) {
	AFCPacket *r_packet;
	char *buffer = (char*)malloc(sizeof(AFCPacket) * 4);
	int bytes = 0, recv_len = 0;
	
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
		free(buffer);
		free(r_packet);
		return r_packet->entire_length - sizeof(AFCPacket);
	}
	
	uint32 param1 = buffer[sizeof(AFCPacket)];
	free(buffer);

	if (r_packet->operation == 0x01) {
		printf("Oops? Bad operation code received.\n");
		if (param1 == 0) printf("... false alarm, but still\n");
		else printf("Errno %i\n", param1);
		free(r_packet);
		*dump_here = NULL;
		return 0;
	} else {
		printf("Operation code %x\nFull length %i and this length %i\n", r_packet->operation, r_packet->entire_length, r_packet->this_length);
	}

	recv_len = r_packet->entire_length - r_packet->this_length;
	free(r_packet);
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

AFCFile *afc_get_file_info(AFClient *client, char *path) {
	client->afc_packet->operation = AFC_GET_INFO;
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
	
	bytes = dispatch_AFC_packet(client, further_data, 8+strlen(filename));
	free(further_data);
	if (bytes <= 0) {
		printf("didn't read enough\n");
		return NULL;
	} else {
		printf("O HAI\n");
		length_thing = receive_AFC_data(client, &further_data);
		if (length_thing && further_data) {
			printf("ARA\n");
			file_infos = afc_get_file_info(client, filename);
			memcpy(&file_infos->filehandle, further_data, 4);
			printf("gr\n");
			return file_infos;
		} else {
			printf("didn't get further data or something\n");
			return NULL;
		}
	}
	printf("what the fuck\n");
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
	bytes = dispatch_AFC_packet(client, packet, sizeof(AFCFilePacket));
	
	if (bytes > 0) {
		bytes = receive_AFC_data(client, &input);
		if (bytes <= 0) {
			return -1;
		} else {
			memcpy(data, input, (bytes > length) ? length : bytes);
			return (bytes > length) ? length : bytes;
		}
	} else {
		return -1;
	}
	return 0;
}

void afc_close_file(AFClient *client, AFCFile *file) {
	char *buffer = malloc(sizeof(char) * 8);
	uint32 zero = 0;
	if (debug) printf("File handle %i\n", file->filehandle);
	memcpy(buffer, &file->filehandle, sizeof(uint32));
	memcpy(buffer, &zero, sizeof(zero));
	client->afc_packet->operation = AFC_FILE_CLOSE;
	int bytes = 0;
	bytes = dispatch_AFC_packet(client, buffer, sizeof(char) * 8);
	free(buffer);
	if (!bytes) return;
	
	bytes = receive_AFC_data(client, &buffer);
	if (bytes<=0 && !buffer) printf("closefile: all went as expected\n");
	else { printf("We have a buffer!??!?\nLength %i\n", bytes); fwrite(buffer, 1, bytes, stdout); printf("\n"); }
	if (buffer) free(buffer); // we're *SUPPOSED* to get an "error" here. 
}

