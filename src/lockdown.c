/*
 * lockdown.c
 * libiphone built-in lockdownd client
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

#include "usbmux.h"
#include "iphone.h"
#include "lockdown.h"
#include "userpref.h"
#include <errno.h>
#include <string.h>

extern int debug;

lockdownd_client *new_lockdownd_client(iPhone *phone) {
	if (!phone) return NULL;
	lockdownd_client *control = (lockdownd_client*)malloc(sizeof(lockdownd_client));
	control->connection = mux_connect(phone, 0x0a00, 0xf27e);
	if (!control->connection) {
		free(control);
		return NULL;
	}
	
	control->ssl_session = (gnutls_session_t*)malloc(sizeof(gnutls_session_t));
	control->in_SSL = 0;
	control->gtls_buffer_hack_len = 0;
	return control;
}

void lockdown_close(lockdownd_client *control) {
	if (!control) return;
	if (control->connection) {
		mux_close_connection(control->connection);
	}
	
	if (control->ssl_session) free(control->ssl_session);
	free(control);
}

	
int lockdownd_recv(lockdownd_client *control, char **dump_data) {
	if (!control) return 0;
	char *receive;
	uint32 datalen = 0, bytes = 0;
	
	if (!control->in_SSL) bytes = mux_recv(control->connection, (char *)&datalen, sizeof(datalen));
	else bytes = gnutls_record_recv(*control->ssl_session, &datalen, sizeof(datalen));
	datalen = ntohl(datalen);
	
	receive = (char*)malloc(sizeof(char) * datalen);
	if (!control->in_SSL) bytes = mux_recv(control->connection, receive, datalen);
	else bytes = gnutls_record_recv(*control->ssl_session, receive, datalen);
	*dump_data = receive;
	return bytes;
}

int lockdownd_send(lockdownd_client *control, char *raw_data, uint32 length) {
	if (!control) return 0;
	char *real_query;
	int bytes;
	
	real_query = (char*)malloc(sizeof(char) * (length+4));
	length = htonl(length);
	memcpy(real_query, &length, sizeof(length));
	memcpy(real_query+4, raw_data, ntohl(length));
	if (debug) {
		printf("lockdownd_send(): made the query, sending it along\n");
		FILE *packet = fopen("grpkt", "w");
		fwrite(real_query, 1, ntohl(length)+4, packet);
		fclose(packet);
		packet = NULL;
	}
	
	if (!control->in_SSL) bytes = mux_send(control->connection, real_query, ntohl(length)+sizeof(length));
	else gnutls_record_send(*control->ssl_session, real_query, ntohl(length)+sizeof(length));
	if (debug) printf("lockdownd_send(): sent it!\n");
	free(real_query);
	return bytes;
}

int lockdownd_hello(lockdownd_client *control) {
	if (!control) return 0;
	xmlDocPtr plist = new_plist();
	xmlNode *dict, *key;
	char **dictionary;
	int bytes = 0, i = 0;
	
	if (debug) printf("lockdownd_hello() called\n");
	dict = add_child_to_plist(plist, "dict", "\n", NULL, 0);
	key = add_key_str_dict_element(plist, dict, "Request", "QueryType", 1);
	char *XML_content;
	uint32 length;
	
	xmlDocDumpMemory(plist, (xmlChar **)&XML_content, &length);
	bytes = lockdownd_send(control, XML_content, length);
	
	xmlFree(XML_content);
	xmlFreeDoc(plist); plist = NULL;
	bytes = lockdownd_recv(control, &XML_content);

	plist = xmlReadMemory(XML_content, bytes, NULL, NULL, 0);
	if (!plist) return 0;
	dict = xmlDocGetRootElement(plist);
	for (dict = dict->children; dict; dict = dict->next) {
		if (!xmlStrcmp(dict->name, "dict")) break;
	}
	if (!dict) return 0;
	
	dictionary = read_dict_element_strings(dict);
	xmlFreeDoc(plist);
	free(XML_content);	
	
	for (i = 0; strcmp(dictionary[i], ""); i+=2) {
		if (!strcmp(dictionary[i], "Result") && !strcmp(dictionary[i+1], "Success")) {
			free_dictionary(dictionary);
			if (debug) printf("lockdownd_hello(): success\n");
			return 1;
		}
	}
	
	free_dictionary(dictionary);
	return 0;
}

int lockdownd_start_SSL_session(lockdownd_client *control, const char *HostID) {
	xmlDocPtr plist = new_plist();
	xmlNode *dict = add_child_to_plist(plist, "dict", "\n", NULL, 0);
	xmlNode *key;
	char *what2send = NULL, **dictionary = NULL;
	uint32 len = 0, bytes = 0, return_me = 0, i = 0;
	// end variables
	
	key = add_key_str_dict_element(plist, dict, "HostID", HostID, 1);
	if (!key) {
		if (debug) printf("Couldn't add a key.\n");
		xmlFreeDoc(plist);
		return 0;
	}
	key = add_key_str_dict_element(plist, dict, "Request", "StartSession", 1);
	if (!key) {
		if (debug) printf("Couldn't add a key.\n");
		xmlFreeDoc(plist);
		return 0;
	}
	
	xmlDocDumpMemory(plist, (xmlChar **)&what2send, &len);
	bytes = lockdownd_send(control, what2send, len);
	
	xmlFree(what2send);
	xmlFreeDoc(plist);
	
	if (bytes > 0) {
		len = lockdownd_recv(control, &what2send);
		plist = xmlReadMemory(what2send, len, NULL, NULL, 0);
		dict = xmlDocGetRootElement(plist);
		for (dict = dict->children; dict; dict = dict->next) {
			if (!xmlStrcmp(dict->name, "dict")) break;
		}
		dictionary = read_dict_element_strings(dict);
		xmlFreeDoc(plist);
		free(what2send);
		for (i = 0; strcmp(dictionary[i], ""); i+=2) {
			if (!strcmp(dictionary[i], "Result") && !strcmp(dictionary[i+1], "Success")) {
				// Set up GnuTLS...
				//gnutls_anon_client_credentials_t anoncred;
				gnutls_certificate_credentials_t xcred;
				if (debug) printf("We started the session OK, now trying GnuTLS\n");
				errno = 0;
				gnutls_global_init();
				//gnutls_anon_allocate_client_credentials(&anoncred);
				gnutls_certificate_allocate_credentials(&xcred);
				gnutls_certificate_set_x509_trust_file(xcred, "hostcert.pem", GNUTLS_X509_FMT_PEM);
				gnutls_init(control->ssl_session, GNUTLS_CLIENT);
				{
					int protocol_priority[16] = {GNUTLS_SSL3, 0 };
					int kx_priority[16] = { GNUTLS_KX_ANON_DH, GNUTLS_KX_RSA, 0 };
					int cipher_priority[16] = { GNUTLS_CIPHER_AES_128_CBC, GNUTLS_CIPHER_AES_256_CBC, 0 };
					int mac_priority[16] = { GNUTLS_MAC_SHA1, GNUTLS_MAC_MD5, 0 };
					int comp_priority[16] = { GNUTLS_COMP_NULL, 0 };

					gnutls_cipher_set_priority(*control->ssl_session, cipher_priority);
					gnutls_compression_set_priority(*control->ssl_session, comp_priority);
					gnutls_kx_set_priority(*control->ssl_session, kx_priority);
					gnutls_protocol_set_priority( *control->ssl_session, protocol_priority);
					gnutls_mac_set_priority(*control->ssl_session, mac_priority);

				}
				gnutls_credentials_set(*control->ssl_session, GNUTLS_CRD_CERTIFICATE, xcred); // this part is killing me.
				
				if (debug) printf("GnuTLS step 1...\n");
				gnutls_transport_set_ptr(*control->ssl_session, (gnutls_transport_ptr_t) control);
				if (debug) printf("GnuTLS step 2...\n");
				gnutls_transport_set_push_function(*control->ssl_session, (gnutls_push_func)&lockdownd_secuwrite);
				if (debug) printf("GnuTLS step 3...\n");
				gnutls_transport_set_pull_function(*control->ssl_session, (gnutls_pull_func)&lockdownd_securead);
				if (debug) printf("GnuTLS step 4 -- now handshaking...\n");
				
				if (errno && debug) printf("WARN: errno says %s before handshake!\n", strerror(errno));
				return_me = gnutls_handshake(*control->ssl_session);
				if (debug) printf("GnuTLS handshake done...\n");
				
				free_dictionary(dictionary);

				if (return_me != GNUTLS_E_SUCCESS) {
					if (debug) printf("GnuTLS reported something wrong.\n");
					gnutls_perror(return_me);
					if (debug) printf("oh.. errno says %s\n", strerror(errno));
					return 0;
				} else {
					control->in_SSL = 1;
					return 1;
				}
			}
		}
		
		if (debug) {
			printf("Apparently failed negotiating with lockdownd.\n");
			printf("Responding dictionary: \n");
			for (i = 0; strcmp(dictionary[i], ""); i+=2) {
				printf("\t%s: %s\n", dictionary[i], dictionary[i+1]);
			}
		}
	
		free_dictionary(dictionary);
		return 0;
	} else { 
		if (debug) printf("Didn't get enough bytes.\n");
		return 0;
	}
}

ssize_t lockdownd_secuwrite(gnutls_transport_ptr_t transport, char *buffer, size_t length) {
	int bytes = 0;
	lockdownd_client *control;
	control = (lockdownd_client*)transport;
	if (debug) printf("lockdownd_secuwrite() called\n");
	if (debug) printf("pre-send\nlength = %i\n", length);
	bytes = mux_send(control->connection, buffer, length);
	if (debug) printf("post-send\nsent %i bytes\n", bytes);
	if (debug) {
		FILE *my_ssl_packet = fopen("sslpacketwrite.out", "w+");
		fwrite(buffer, 1, length, my_ssl_packet);
		fflush(my_ssl_packet);
		printf("Wrote SSL packet to drive, too.\n");
		fclose(my_ssl_packet);
	}
	
	return bytes;
}

ssize_t lockdownd_securead(gnutls_transport_ptr_t transport, char *buffer, size_t length) {
	int bytes = 0, pos_start_fill = 0;
	char *hackhackhack = NULL; 
	lockdownd_client *control;
	control = (lockdownd_client*)transport;
	if (debug) printf("lockdownd_securead() called\nlength = %i\n", length);
	// Buffering hack! Throw what we've got in our "buffer" into the stream first, then get more.
	if (control->gtls_buffer_hack_len > 0) {
		if (length > control->gtls_buffer_hack_len) { // If it's asking for more than we got
			length -= control->gtls_buffer_hack_len; // Subtract what we have from their requested length
			pos_start_fill = control->gtls_buffer_hack_len; // set the pos to start filling at
			memcpy(buffer, control->gtls_buffer_hack, control->gtls_buffer_hack_len); // Fill their buffer partially
			free(control->gtls_buffer_hack); // free our memory, it's not chained anymore
			control->gtls_buffer_hack_len = 0; // we don't have a hack buffer anymore
			if (debug) printf("Did a partial fill to help quench thirst for data\n");
		} else if (length < control->gtls_buffer_hack_len) { // If it's asking for less...
			control->gtls_buffer_hack_len -= length; // subtract what they're asking for
			memcpy(buffer, control->gtls_buffer_hack, length); // fill their buffer
			hackhackhack = (char*)malloc(sizeof(char) * control->gtls_buffer_hack_len); // strndup is NOT a good solution -- concatenates \0!!!! Anyway, make a new "hack" buffer.
			memcpy(hackhackhack, control->gtls_buffer_hack+length, control->gtls_buffer_hack_len); // Move what's left into the new one
			free(control->gtls_buffer_hack); // Free the old one
			control->gtls_buffer_hack = hackhackhack; // And make it the new one.
			hackhackhack = NULL; 
			if (debug) printf("Quenched the thirst for data; new hack length is %i\n", control->gtls_buffer_hack_len);
			return length; // hand it over.
		} else { // length == hack length
			memcpy(buffer, control->gtls_buffer_hack, length); // copy our buffer into theirs
			free(control->gtls_buffer_hack); // free our "obligation"
			control->gtls_buffer_hack_len = 0; // free our "obligation"
			if (debug) printf("Satiated the thirst for data; now we have to eventually receive again.\n");
			return length; // hand it over
		}
	}
	// End buffering hack!
	char *recv_buffer = (char*)malloc(sizeof(char) * (length * 1000)); // ensuring nothing stupid happens
	
	if (debug) printf("pre-read\nclient wants %i bytes\n", length);
	bytes = mux_recv(control->connection, recv_buffer, (length * 1000));
	if (debug) printf("post-read\nwe got %i bytes\n", bytes);
	if (debug && bytes < 0) {
		printf("lockdownd_securead(): uh oh\n");
		printf("I believe what we have here is a failure to communicate... libusb says %s but strerror says %s\n", usb_strerror(), strerror(errno));
		return bytes + 28; // an errno
	}
	if (bytes >= length) {
		if (bytes > length) {
			if (debug) printf("lockdownd_securead: Client deliberately read less data than was there; resorting to GnuTLS buffering hack.\n");
			if (!control->gtls_buffer_hack_len) { // if there's no hack buffer yet
				//control->gtls_buffer_hack = strndup(recv_buffer+length, bytes-length); // strndup is NOT a good solution!
				control->gtls_buffer_hack_len += bytes-length;
				control->gtls_buffer_hack = (char*)malloc(sizeof(char) * control->gtls_buffer_hack_len);
				memcpy(control->gtls_buffer_hack, recv_buffer+length, control->gtls_buffer_hack_len);
			} else { // if there is. 
				control->gtls_buffer_hack = realloc(control->gtls_buffer_hack, control->gtls_buffer_hack_len + (bytes - length));
				memcpy(control->gtls_buffer_hack+control->gtls_buffer_hack_len, recv_buffer+length, bytes-length);
				control->gtls_buffer_hack_len += bytes - length;
			}
		}
		memcpy(buffer+pos_start_fill, recv_buffer, length);
		free(recv_buffer);
		if (bytes == length) { if (debug) printf("Returning how much we received.\n");  return bytes; }
		else { if (debug) printf("Returning what they want to hear.\nHack length: %i\n", control->gtls_buffer_hack_len); return length; }
	}
	return bytes;
}

int lockdownd_start_service(lockdownd_client *control, const char *service) {
	if (!control) return 0;

	char* host_id = get_host_id();
	if (host_id && !control->in_SSL && !lockdownd_start_SSL_session(control, host_id)) return 0;

	char *XML_query, **dictionary;
	uint32 length, i = 0, port = 0;
	uint8 result = 0;

	free(host_id);
	host_id = NULL;

	xmlDocPtr plist = new_plist();
	xmlNode *dict = add_child_to_plist(plist, "dict", "\n", NULL, 0);
	xmlNode *key;
	key = add_key_str_dict_element(plist, dict, "Request", "StartService", 1);
	if (!key) { xmlFreeDoc(plist); return 0; }
	key = add_key_str_dict_element(plist, dict, "Service", service, 1);
	if (!key) { xmlFreeDoc(plist); return 0; }
	
	xmlDocDumpMemory(plist, (xmlChar **)&XML_query, &length);
	
	lockdownd_send(control, XML_query, length);
	free(XML_query);
	
	length = lockdownd_recv(control, &XML_query);
	
	xmlFreeDoc(plist);
	
	if (length <= 0) return 0;
	else {
		plist = xmlReadMemory(XML_query, length, NULL, NULL, 0);
		if (!plist) return 0;
		dict = xmlDocGetRootElement(plist);
		if (!dict) return 0;
		for (dict = dict->children; dict; dict = dict->next) {
			if (!xmlStrcmp(dict->name, "dict")) break;
		}
		
		if (!dict) return 0;
		dictionary = read_dict_element_strings(dict);
		
		for (i = 0; strcmp(dictionary[i], ""); i+=2) {
			if (debug) printf("lockdownd_start_service() dictionary %s: %s\n", dictionary[i], dictionary[i+1]);
			
			if (!xmlStrcmp(dictionary[i], "Port")) {
				port = atoi(dictionary[i+1]);
				if (debug) printf("lockdownd_start_service() atoi'd port: %i\n", port);
			}
			
			if (!xmlStrcmp(dictionary[i], "Result")) {
				if (!xmlStrcmp(dictionary[i+1], "Success")) {
					result = 1;
				}
			}
		}
		
		if (debug) {
			printf("lockdownd_start_service(): DATA RECEIVED:\n\n");
			fwrite(XML_query, 1, length, stdout);
			printf("end data received by lockdownd_start_service()\n");
		}
		
		free(XML_query);
		xmlFreeDoc(plist);
		free_dictionary(dictionary);
		if (port && result) return port;
		else return 0;
	}
	
	return 0;
}

