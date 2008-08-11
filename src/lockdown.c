/*
 * lockdown.c
 * libiphone built-in lockdownd client
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

#include "usbmux.h"
#include "iphone.h"
#include "lockdown.h"
#include "userpref.h"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <glib.h>
#include <libtasn1.h>
#include <gnutls/x509.h>

extern int debug;

const ASN1_ARRAY_TYPE pkcs1_asn1_tab[]={
  {"PKCS1",536872976,0},
  {0,1073741836,0},
  {"RSAPublicKey",536870917,0},
  {"modulus",1073741827,0},
  {"publicExponent",3,0},
  {0,0,0}
};

int get_rand(int min, int max) {
	int retval = (rand() % (max - min)) + min;
	return retval;
}

/** Generates a valid HostID (which is actually a UUID).
 *
 * @param A null terminated string containing a valid HostID.
 */
char *lockdownd_generate_hostid() {
	char *hostid = (char*)malloc(sizeof(char) * 37); // HostID's are just UUID's, and UUID's are 36 characters long
	const char *chars = "ABCDEF0123456789";
	srand(time(NULL));
	int i = 0;
	
	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			hostid[i] = '-';
			continue;
		} else {
			hostid[i] = chars[get_rand(0,16)];
		}
	}
	hostid[36] = '\0'; // make it a real string
	return hostid;
}

/** Creates a lockdownd client for the give iPhone.
 *
 * @param phone The iPhone to create a lockdownd client for
 *
 * @return The lockdownd client.
 */
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


/** Closes the lockdownd client and does the necessary housekeeping.
 *
 * @param control The lockdown client
 */
void lockdownd_close(lockdownd_client *control) {
	if (!control) return;
	if (control->connection) {
		mux_close_connection(control->connection);
	}
	
	if (control->ssl_session) gnutls_deinit(*control->ssl_session);
	free(control->ssl_session);
	free(control);
}

/** Polls the iPhone for lockdownd data.
 *
 * @param control The lockdownd client
 * @param dump_data The pointer to the location of the buffer in which to store
 *                  the received data
 *
 * @return The number of bytes received
 */
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

/** Sends lockdownd data to the iPhone
 * 
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param control The lockdownd client
 * @param raw_data The null terminated string buffer to send
 * @param length The length of data to send
 *
 * @return The number of bytes sent
 */
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

/** Initiates the handshake for the lockdown session. Part of the lockdownd handshake.
 * 
 * @note You most likely want lockdownd_init unless you are doing something special.
 *
 * @param control The lockdownd client
 *
 * @return 1 on success and 0 on failure.
 */
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
	
	for (i = 0; dictionary[i]; i+=2) {
		if (!strcmp(dictionary[i], "Result") && !strcmp(dictionary[i+1], "Success")) {
			free_dictionary(dictionary);
			if (debug) printf("lockdownd_hello(): success\n");
			return 1;
		}
	}
	
	free_dictionary(dictionary);
	return 0;
}

/** Generic function to handle simple (key, value) requests.
 *
 * @param control an initialized lockdownd client.
 * @param key the key to request
 * @param value a pointer to the requested value
 *
 * @return 1 on success and 0 on failure.
 */
int lockdownd_generic_get_value(lockdownd_client *control, char *req_key, char **value)
{
	xmlDocPtr plist = new_plist();
	xmlNode *dict = NULL;
	xmlNode *key = NULL;;
	char **dictionary = NULL;
	int bytes = 0, i = 0;
	char *XML_content = NULL;
	uint32 length = 0;
	
	/* Setup DevicePublicKey request plist */
	dict = add_child_to_plist(plist, "dict", "\n", NULL, 0);
	key = add_key_str_dict_element(plist, dict, "Key", req_key, 1);
	key = add_key_str_dict_element(plist, dict, "Request", "GetValue", 1);
	xmlDocDumpMemory(plist, (xmlChar**)&XML_content, &length);

	/* send to iPhone */
	bytes = lockdownd_send(control, XML_content, length);
	
	xmlFree(XML_content);
	xmlFreeDoc(plist); plist = NULL;

	/* Now get iPhone's answer */
	bytes = lockdownd_recv(control, &XML_content);

	plist = xmlReadMemory(XML_content, bytes, NULL, NULL, 0);
	if (!plist) return 0;
	dict = xmlDocGetRootElement(plist);
	for (dict = dict->children; dict; dict = dict->next) {
		if (!xmlStrcmp(dict->name, "dict")) break;
	}
	if (!dict) return 0;
	
	/* Parse xml to check success and to find public key */
	dictionary = read_dict_element_strings(dict);
	xmlFreeDoc(plist);
	free(XML_content);	
	
	int success = 0;
	for (i = 0; dictionary[i]; i+=2) {
		if (!strcmp(dictionary[i], "Result") && !strcmp(dictionary[i+1], "Success")) {
			success = 1;
		}
		if (!strcmp(dictionary[i], "Value")) {
			*value = strdup(dictionary[i+1]);
		}
	}
	
	if (dictionary) {
		free_dictionary(dictionary);
		dictionary = NULL;
	}
	return success;
}

/** Askes for the device's unique id. Part of the lockdownd handshake.
 *
 * @note You most likely want lockdownd_init unless you are doing something special.
 *
 * @return 1 on success and 0 on failure.
 */
int lockdownd_get_device_uid(lockdownd_client *control, char **uid)
{
	return lockdownd_generic_get_value(control, "UniqueDeviceID", uid);
}

/** Askes for the device's public key. Part of the lockdownd handshake.
 *
 * @note You most likely want lockdownd_init unless you are doing something special.
 *
 * @return 1 on success and 0 on failure.
 */
int lockdownd_get_device_public_key(lockdownd_client *control, char **public_key)
{
	return lockdownd_generic_get_value(control, "DevicePublicKey", public_key);
}

/** Completes the entire lockdownd handshake.
 *
 * @param phone The iPhone
 * @param lockdownd_client The pointer to the location of the lockdownd_client
 *
 * @return 1 on success and 0 on failure
 */
int lockdownd_init(iPhone_t phone, lockdownd_client_t *control)
{
	int ret = 0;
	char *host_id = NULL;

	if (!phone)
		return 0;

	lockdownd_client *control_loc = new_lockdownd_client( (iPhone*)phone );
	if (!lockdownd_hello(control_loc)){
		fprintf(stderr, "Hello failed in the lockdownd client.\n");
	}

	char *uid = NULL;
	if(!lockdownd_get_device_uid(control_loc, &uid)){
		fprintf(stderr, "Device refused to send public key.\n");
	}

	host_id = get_host_id();

	if (!is_device_known(uid))
		ret = lockdownd_pair_device(*control, uid, host_id);
	else 
		ret = 1;

	if (uid) {
		free(uid);
		uid = NULL;
	}
	

	if (ret && host_id && lockdownd_start_SSL_session(control_loc, host_id)) {
		ret = 1;
	} else {
		ret = 0;
		fprintf(stderr, "lockdownd_init: SSL Session opening failed, has libiphone-initconf been run?\n");
	}

	if (host_id) {
		free(host_id);
		host_id = NULL;
	}

	*control = (lockdownd_client_t)control_loc;

	return ret;
}

/** Generates the appropriate keys and pairs the device. It's part of the
 *  lockdownd handshake.
 *
 * @note You most likely want lockdownd_init unless you are doing something special.
 *
 * @return 1 on success and 0 on failure
 */
int lockdownd_pair_device(lockdownd_client *control, char *uid, char *host_id)
{
	int ret = 0;
	xmlDocPtr plist = new_plist();
	xmlNode *dict = NULL;
	xmlNode *dictRecord = NULL;
	char **dictionary = NULL;
	int bytes = 0, i = 0;
	char *XML_content = NULL;
	uint32 length = 0;

	char* device_cert_b64 = NULL;
	char* host_cert_b64 = NULL;
	char* root_cert_b64 = NULL;
	char *public_key_b64 = NULL;

	if(!lockdownd_get_device_public_key(control, &public_key_b64)){
		fprintf(stderr, "Device refused to send public key.\n");
		return 0;
	}


	if(!lockdownd_gen_pair_cert(public_key_b64, &device_cert_b64, &host_cert_b64, &root_cert_b64)){
		free(public_key_b64);
		return 0;
	}

	/* Setup Pair request plist */
	dict = add_child_to_plist(plist, "dict", "\n", NULL, 0);
	dictRecord = add_key_dict_node(plist, dict, "PairRecord", "\n", 1);
	//dictRecord = add_child_to_plist(plist, "dict", "\n", NULL, 1);
	add_key_data_dict_element(plist, dictRecord, "DeviceCertificate", device_cert_b64, 2);
	add_key_data_dict_element(plist, dictRecord, "HostCertificate", host_cert_b64, 2);
	add_key_str_dict_element(plist, dictRecord, "HostID", host_id, 2);
	add_key_data_dict_element(plist, dictRecord, "RootCertificate", root_cert_b64, 2);
	add_key_str_dict_element(plist, dict, "Request", "Pair", 1);

	xmlDocDumpMemory(plist, (xmlChar**)&XML_content, &length);

	printf("XML Pairing request : %s\n",XML_content);

	/* send to iPhone */
	bytes = lockdownd_send(control, XML_content, length);
	
	xmlFree(XML_content);
	xmlFreeDoc(plist); plist = NULL;

	/* Now get iPhone's answer */
	bytes = lockdownd_recv(control, &XML_content);

	if (debug) {
		printf("lockdown_pair_device: iPhone's response to our pair request:\n");
		fwrite(XML_content, 1, bytes, stdout);
		printf("\n\n");
	}
	
	plist = xmlReadMemory(XML_content, bytes, NULL, NULL, 0);
	if (!plist) {
		free(public_key_b64);
		return 0;
		}
	dict = xmlDocGetRootElement(plist);
	for (dict = dict->children; dict; dict = dict->next) {
		if (!xmlStrcmp(dict->name, "dict")) break;
	}
	if (!dict) {
		free(public_key_b64);
		return 0;
	}
	
	/* Parse xml to check success and to find public key */
	dictionary = read_dict_element_strings(dict);
	xmlFreeDoc(plist);
	free(XML_content);	
	
	int success = 0;
	for (i = 0; dictionary[i]; i+=2) {
		if (!strcmp(dictionary[i], "Result") && !strcmp(dictionary[i+1], "Success")) {
			success = 1;
		}
	}

	if (dictionary) {
		free_dictionary(dictionary);
		dictionary = NULL;
	}

	/* store public key in config if pairing succeeded */
	if (success) {
		if (debug) printf("lockdownd_pair_device: pair success\n");
		store_device_public_key(uid, public_key_b64);
		ret = 1;
	} else {
		if (debug) printf("lockdownd_pair_device: pair failure\n");
	}
	free(public_key_b64);
	return ret;
}

/** Generates the device certificate from the public key as well as the host
 *  and root certificates.
 * 
 * @return 1 on success and 0 on failure.
 */
int lockdownd_gen_pair_cert(char *public_key_b64, char **device_cert_b64, char **host_cert_b64, char **root_cert_b64)
{
	int ret = 0, error = 0;

	gnutls_datum_t modulus = {NULL, 0};
	gnutls_datum_t exponent = {NULL, 0};

	/* first decode base64 public_key */
	gnutls_datum_t pem_pub_key;
	gsize decoded_size;
	pem_pub_key.data = g_base64_decode (public_key_b64, &decoded_size);
	pem_pub_key.size = decoded_size;

	/* now decode the PEM encoded key */
	gnutls_datum_t der_pub_key;
	if( GNUTLS_E_SUCCESS  == gnutls_pem_base64_decode_alloc ("RSA PUBLIC KEY", &pem_pub_key, &der_pub_key) ){
		ret = 1;
 
		/* initalize asn.1 parser */
		ASN1_TYPE pkcs1 = ASN1_TYPE_EMPTY;
		if (ASN1_SUCCESS == asn1_array2tree(pkcs1_asn1_tab, &pkcs1, NULL)) {

			ASN1_TYPE asn1_pub_key = ASN1_TYPE_EMPTY;
			asn1_create_element(pkcs1, "PKCS1.RSAPublicKey", &asn1_pub_key);

			if (ASN1_SUCCESS == asn1_der_decoding(&asn1_pub_key, der_pub_key.data, der_pub_key.size, NULL)) {

				/* get size to read */
				int ret1 = asn1_read_value (asn1_pub_key, "modulus", NULL, &modulus.size);
				int ret2 = asn1_read_value (asn1_pub_key, "publicExponent", NULL, &exponent.size);

				modulus.data = gnutls_malloc(modulus.size);
				exponent.data = gnutls_malloc(exponent.size);

				ret1 = asn1_read_value (asn1_pub_key, "modulus", modulus.data, &modulus.size);
				ret2 = asn1_read_value (asn1_pub_key, "publicExponent", exponent.data, &exponent.size);
				if (ASN1_SUCCESS == ret1 && ASN1_SUCCESS == ret2)
					ret = 1;
			}
			if (asn1_pub_key)
				asn1_delete_structure(&asn1_pub_key);
		}
		if (pkcs1)
			asn1_delete_structure(&pkcs1);
	}

	/* now generate certifcates */
	if (1 == ret && 0 != modulus.size && 0 != exponent.size) {

		gnutls_global_init();
		gnutls_datum_t essentially_null = {strdup("abababababababab"), strlen("abababababababab")};
	
		gnutls_x509_privkey_t fake_privkey, root_privkey;
		gnutls_x509_crt_t dev_cert, root_cert, host_cert;
	
		gnutls_x509_privkey_init(&fake_privkey);
		gnutls_x509_crt_init(&dev_cert);
		gnutls_x509_crt_init(&root_cert);
		gnutls_x509_crt_init(&host_cert);

		if ( GNUTLS_E_SUCCESS == gnutls_x509_privkey_import_rsa_raw(fake_privkey, &modulus, &exponent, &essentially_null, &essentially_null, &essentially_null, &essentially_null) ) {
		
			gnutls_x509_privkey_init(&root_privkey);
			
			/* get root cert */
			gnutls_datum_t pem_root_cert = {NULL, 0};
			get_root_certificate(&pem_root_cert);
			ret = gnutls_x509_crt_import(root_cert, &pem_root_cert, GNUTLS_X509_FMT_PEM);
			if (ret != GNUTLS_E_SUCCESS) error = 1;

			/* get host cert */
			gnutls_datum_t pem_host_cert = {NULL, 0};
			get_host_certificate(&pem_host_cert);
			ret = gnutls_x509_crt_import(host_cert, &pem_host_cert, GNUTLS_X509_FMT_PEM);
			if (ret != GNUTLS_E_SUCCESS) error = 1;

			/* get root private key */
			gnutls_datum_t pem_root_priv = {NULL, 0};
			get_root_private_key(&pem_root_priv);
			ret = gnutls_x509_privkey_import(root_privkey, &pem_root_priv, GNUTLS_X509_FMT_PEM);
			if (ret != GNUTLS_E_SUCCESS) error = 1;

			/* generate device certificate */
			gnutls_x509_crt_set_key(dev_cert, fake_privkey);
			gnutls_x509_crt_set_serial(dev_cert, "\x00", 1);
			gnutls_x509_crt_set_version(dev_cert, 3);
			gnutls_x509_crt_set_ca_status(dev_cert, 0);
			gnutls_x509_crt_set_activation_time(dev_cert, time(NULL));
			gnutls_x509_crt_set_expiration_time(dev_cert, time(NULL) + (60 * 60 * 24 * 365 * 10));
			gnutls_x509_crt_sign(dev_cert, root_cert, root_privkey);

			if (!error) {
				/* if everything went well, export in PEM format */
				gnutls_datum_t dev_pem = {NULL, 0};
				gnutls_x509_crt_export(dev_cert, GNUTLS_X509_FMT_PEM, NULL, &dev_pem.size);
				dev_pem.data = gnutls_malloc(dev_pem.size);
				gnutls_x509_crt_export(dev_cert, GNUTLS_X509_FMT_PEM, dev_pem.data, &dev_pem.size);

				/* now encode certificates for output */
				*device_cert_b64 = g_base64_encode(dev_pem.data, dev_pem.size);
				*host_cert_b64 = g_base64_encode(pem_host_cert.data, pem_host_cert.size);
				*root_cert_b64 = g_base64_encode(pem_root_cert.data, pem_root_cert.size);
				ret = 1;
			}
			gnutls_free(pem_root_priv.data);
			gnutls_free(pem_root_cert.data);
			gnutls_free(pem_host_cert.data);
		}
	}

	gnutls_free(modulus.data);
	gnutls_free(exponent.data);

	gnutls_free(der_pub_key.data);
	g_free(pem_pub_key.data);
	
	if (error) {
		return 0;
	} else {
		return ret;
	}
}

/** Starts SSL communication with lockdownd after the iPhone has been paired.
 *
 * @param control The lockdownd client
 * @param HostID The HostID used with this phone
 *
 * @return 1 on success and 0 on failure
 */
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
		for (i = 0; dictionary[i]; i+=2) {
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
			for (i = 0; dictionary[i]; i+=2) {
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

/** gnutls callback for writing data to the iPhone.
 *
 * @param transport It's really the lockdownd client, but the method signature has to match
 * @param buffer The data to send
 * @param length The length of data to send in bytes
 *
 * @return The number of bytes sent
 */
ssize_t lockdownd_secuwrite(gnutls_transport_ptr_t transport, char *buffer, size_t length) {
	int bytes = 0;
	lockdownd_client *control;
	control = (lockdownd_client*)transport;
	if (debug) printf("lockdownd_secuwrite() called\n");
	if (debug) printf("pre-send\nlength = %zi\n", length);
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

/** gnutls callback for reading data from the iPhone
 *
 * @param transport It's really the lockdownd client, but the method signature has to match
 * @param buffer The buffer to store data in
 * @param length The length of data to read in bytes
 *
 * @return The number of bytes read
 */
ssize_t lockdownd_securead(gnutls_transport_ptr_t transport, char *buffer, size_t length) {
	int bytes = 0, pos_start_fill = 0;
	char *hackhackhack = NULL; 
	lockdownd_client *control;
	control = (lockdownd_client*)transport;
	if (debug) printf("lockdownd_securead() called\nlength = %zi\n", length);
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
	
	if (debug) printf("pre-read\nclient wants %zi bytes\n", length);
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

/** Command to start the desired service
 *
 * @param control The lockdownd client
 * @param service The name of the service to start
 *
 * @return The port number the service was started on or 0 on failure.
 */
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
		
		for (i = 0; dictionary[i]; i+=2) {
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
