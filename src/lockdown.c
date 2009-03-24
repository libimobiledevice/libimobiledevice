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
#include "utils.h"
#include "iphone.h"
#include "lockdown.h"
#include "userpref.h"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <glib.h>
#include <libtasn1.h>
#include <gnutls/x509.h>

#include <plist/plist.h>


const ASN1_ARRAY_TYPE pkcs1_asn1_tab[] = {
	{"PKCS1", 536872976, 0},
	{0, 1073741836, 0},
	{"RSAPublicKey", 536870917, 0},
	{"modulus", 1073741827, 0},
	{"publicExponent", 3, 0},
	{0, 0, 0}
};

/** Creates a lockdownd client for the give iPhone.
 *
 * @param phone The iPhone to create a lockdownd client for
 *
 * @return The lockdownd client.
 */
iphone_lckd_client_t new_lockdownd_client(iphone_device_t phone)
{
	if (!phone)
		return NULL;
	iphone_lckd_client_t control = (iphone_lckd_client_t) malloc(sizeof(struct iphone_lckd_client_int));

	if (IPHONE_E_SUCCESS != iphone_mux_new_client(phone, 0x0a00, 0xf27e, &control->connection)) {
		free(control);
		return NULL;
	}

	control->ssl_session = (gnutls_session_t *) malloc(sizeof(gnutls_session_t));
	control->in_SSL = 0;
	return control;
}

/**
 * Closes the lockdownd communication session, by sending
 * the StopSession Request to the device. 
 *
 * @param control The lockdown client
 */
static void iphone_lckd_stop_session(iphone_lckd_client_t control)
{
	if (!control)
		return;					//IPHONE_E_INVALID_ARG;

	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_add_sub_key_el(dict, "Request");
	plist_add_sub_string_el(dict, "StopSession");
	plist_add_sub_key_el(dict, "SessionID");
	plist_add_sub_string_el(dict, control->session_id);

	log_dbg_msg(DBGMASK_LOCKDOWND, "iphone_lckd_stop_session() called\n");

	ret = iphone_lckd_send(control, dict);

	plist_free(dict);
	dict = NULL;

	ret = iphone_lckd_recv(control, &dict);

	if (!dict) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_stop_session(): IPHONE_E_PLIST_ERROR\n");
		return;					// IPHONE_E_PLIST_ERROR;
	}

	plist_t query_node = plist_find_node_by_string(dict, "StopSession");
	plist_t result_node = plist_get_next_sibling(query_node);
	plist_t value_node = plist_get_next_sibling(result_node);

	plist_type result_type = plist_get_node_type(result_node);
	plist_type value_type = plist_get_node_type(value_node);

	if (result_type == PLIST_KEY && value_type == PLIST_STRING) {

		char *result_value = NULL;
		char *value_value = NULL;

		plist_get_key_val(result_node, &result_value);
		plist_get_string_val(value_node, &value_value);

		if (!strcmp(result_value, "Result") && !strcmp(value_value, "Success")) {
			log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_stop_session(): success\n");
			ret = IPHONE_E_SUCCESS;
		}
		free(result_value);
		free(value_value);
	}
	plist_free(dict);
	dict = NULL;

	return;						// ret;
}

/**
 * Shuts down the SSL session by first calling iphone_lckd_stop_session
 * to cleanly close the lockdownd communication session, and then 
 * performing a close notify, which is done by "gnutls_bye".
 *
 * @param client The lockdown client
 */
static void iphone_lckd_stop_SSL_session(iphone_lckd_client_t client)
{
	if (!client) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_stop_SSL_session(): invalid argument!\n");
		return;
	}

	if (client->in_SSL) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "Stopping SSL Session\n");
		iphone_lckd_stop_session(client);
		log_dbg_msg(DBGMASK_LOCKDOWND, "Sending SSL close notify\n");
		gnutls_bye(*client->ssl_session, GNUTLS_SHUT_RDWR);
	}
	if (client->ssl_session) {
		gnutls_deinit(*client->ssl_session);
		free(client->ssl_session);
	}
	client->in_SSL = 0;

	return;
}

/** Closes the lockdownd client and does the necessary housekeeping.
 *
 * @param control The lockdown client
 */
iphone_error_t iphone_lckd_free_client(iphone_lckd_client_t client)
{
	if (!client)
		return IPHONE_E_INVALID_ARG;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	iphone_lckd_stop_SSL_session(client);

	if (client->connection) {
		lockdownd_close(client);

		// IMO, read of final "sessionUpcall connection closed" packet
		//  should come here instead of in iphone_free_device

		ret = iphone_mux_free_client(client->connection);
	}

	free(client);
	return ret;
}

/** Polls the iPhone for lockdownd data.
 *
 * @param control The lockdownd client
 * @param dump_data The pointer to the location of the buffer in which to store
 *                  the received data
 *
 * @return The number of bytes received
 */
iphone_error_t iphone_lckd_recv(iphone_lckd_client_t client, plist_t * plist)
{
	if (!client || !plist || (plist && *plist))
		return IPHONE_E_INVALID_ARG;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	char *receive;
	uint32_t datalen = 0, bytes = 0;

	if (!client->in_SSL)
		ret = iphone_mux_recv(client->connection, (char *) &datalen, sizeof(datalen), &bytes);
	else {
		bytes = gnutls_record_recv(*client->ssl_session, &datalen, sizeof(datalen));
		if (bytes > 0)
			ret = IPHONE_E_SUCCESS;
	}
	datalen = ntohl(datalen);

	receive = (char *) malloc(sizeof(char) * datalen);
	if (!client->in_SSL)
		ret = iphone_mux_recv(client->connection, receive, datalen, &bytes);
	else {
		bytes = gnutls_record_recv(*client->ssl_session, receive, datalen);
		if (bytes > 0)
			ret = IPHONE_E_SUCCESS;
	}

	if (bytes <= 0) {
		free(receive);
		return IPHONE_E_NOT_ENOUGH_DATA;
	}

	plist_from_xml(receive, bytes, plist);
	free(receive);

	if (!*plist)
		ret = IPHONE_E_PLIST_ERROR;

	return ret;
}

/** Sends lockdownd data to the iPhone
 * 
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The lockdownd client
 * @param plist The plist to send
 *
 * @return an error code (IPHONE_E_SUCCESS on success)
 */
iphone_error_t iphone_lckd_send(iphone_lckd_client_t client, plist_t plist)
{
	if (!client || !plist)
		return IPHONE_E_INVALID_ARG;
	char *real_query;
	int bytes;
	char *XMLContent = NULL;
	uint32_t length = 0;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	plist_to_xml(plist, &XMLContent, &length);
	log_dbg_msg(DBGMASK_LOCKDOWND, "Send msg :\nsize : %i\nbuffer :\n%s\n", length, XMLContent);


	real_query = (char *) malloc(sizeof(char) * (length + 4));
	length = htonl(length);
	memcpy(real_query, &length, sizeof(length));
	memcpy(real_query + 4, XMLContent, ntohl(length));
	free(XMLContent);
	log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_send(): made the query, sending it along\n");

	if (!client->in_SSL)
		ret = iphone_mux_send(client->connection, real_query, ntohl(length) + sizeof(length), &bytes);
	else {
		gnutls_record_send(*client->ssl_session, real_query, ntohl(length) + sizeof(length));
		ret = IPHONE_E_SUCCESS;
	}
	log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_send(): sent it!\n");
	free(real_query);

	return ret;
}

/** Initiates the handshake for the lockdown session. Part of the lockdownd handshake.
 * 
 * @note You most likely want lockdownd_init unless you are doing something special.
 *
 * @param control The lockdownd client
 *
 * @return 1 on success and 0 on failure.
 */
iphone_error_t lockdownd_hello(iphone_lckd_client_t control)
{
	if (!control)
		return IPHONE_E_INVALID_ARG;

	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_add_sub_key_el(dict, "Request");
	plist_add_sub_string_el(dict, "QueryType");

	log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_hello() called\n");
	ret = iphone_lckd_send(control, dict);

	plist_free(dict);
	dict = NULL;

	ret = iphone_lckd_recv(control, &dict);

	if (IPHONE_E_SUCCESS != ret)
		return ret;

	plist_t query_node = plist_find_node_by_string(dict, "QueryType");
	plist_t result_node = plist_get_next_sibling(query_node);
	plist_t value_node = plist_get_next_sibling(result_node);

	plist_type result_type = plist_get_node_type(result_node);
	plist_type value_type = plist_get_node_type(value_node);

	if (result_type == PLIST_KEY && value_type == PLIST_STRING) {

		char *result_value = NULL;
		char *value_value = NULL;

		plist_get_key_val(result_node, &result_value);
		plist_get_string_val(value_node, &value_value);

		if (!strcmp(result_value, "Result") && !strcmp(value_value, "Success")) {
			log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_hello(): success\n");
			ret = IPHONE_E_SUCCESS;
		}
		free(result_value);
		free(value_value);
	}

	plist_free(dict);
	dict = NULL;

	return ret;
}

/** Generic function to handle simple (key, value) requests.
 *
 * @param control an initialized lockdownd client.
 * @param key the key to request
 * @param value a pointer to the requested value
 *
 * @return IPHONE_E_SUCCESS on success.
 */
iphone_error_t lockdownd_generic_get_value(iphone_lckd_client_t control, const char *req_key, char *req_string,
										   gnutls_datum_t * value)
{
	if (!control || !req_key || !value || value->data)
		return IPHONE_E_INVALID_ARG;

	plist_t dict = NULL;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	/* Setup DevicePublicKey request plist */
	dict = plist_new_dict();
	plist_add_sub_key_el(dict, req_key);
	plist_add_sub_string_el(dict, req_string);
	plist_add_sub_key_el(dict, "Request");
	plist_add_sub_string_el(dict, "GetValue");

	/* send to iPhone */
	ret = iphone_lckd_send(control, dict);

	plist_free(dict);
	dict = NULL;

	if (ret != IPHONE_E_SUCCESS)
		return ret;

	/* Now get iPhone's answer */
	ret = iphone_lckd_recv(control, &dict);

	if (ret != IPHONE_E_SUCCESS)
		return ret;

	plist_t query_node = plist_find_node_by_string(dict, "GetValue");
	plist_t result_key_node = plist_get_next_sibling(query_node);
	plist_t result_value_node = plist_get_next_sibling(result_key_node);

	plist_type result_key_type = plist_get_node_type(result_key_node);
	plist_type result_value_type = plist_get_node_type(result_value_node);

	if (result_key_type == PLIST_KEY && result_value_type == PLIST_STRING) {

		char *result_key = NULL;
		char *result_value = NULL;
		ret = IPHONE_E_DICT_ERROR;

		plist_get_key_val(result_key_node, &result_key);
		plist_get_string_val(result_value_node, &result_value);

		if (!strcmp(result_key, "Result") && !strcmp(result_value, "Success")) {
			log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_generic_get_value(): success\n");
			ret = IPHONE_E_SUCCESS;
		}
		free(result_key);
		free(result_value);
	}
	if (ret != IPHONE_E_SUCCESS) {
		return ret;
	}

	plist_t value_key_node = plist_get_next_sibling(result_key_node);
	plist_t value_value_node = plist_get_next_sibling(value_key_node);

	plist_type value_key_type = plist_get_node_type(value_key_node);

	if (value_key_type == PLIST_KEY) {

		char *result_key = NULL;
		plist_get_key_val(value_key_node, &result_key);

		if (!strcmp(result_key, "Value")) {
			log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_generic_get_value(): success\n");

			plist_type value_value_type = plist_get_node_type(value_value_node);
			if (PLIST_STRING == value_value_type) {
				char *value_value = NULL;
				plist_get_string_val(value_value_node, &value_value);

				value->data = value_value;
				value->size = strlen(value_value);
				ret = IPHONE_E_SUCCESS;
			}
		}
		free(result_key);
	}

	plist_free(dict);
	return ret;
}

/** Askes for the device's unique id. Part of the lockdownd handshake.
 *
 * @note You most likely want lockdownd_init unless you are doing something special.
 *
 * @return 1 on success and 0 on failure.
 */
iphone_error_t lockdownd_get_device_uid(iphone_lckd_client_t control, char **uid)
{
	gnutls_datum_t temp = { NULL, 0 };
	return lockdownd_generic_get_value(control, "Key", "UniqueDeviceID", &temp);
	*uid = temp.data;
}

/** Askes for the device's public key. Part of the lockdownd handshake.
 *
 * @note You most likely want lockdownd_init unless you are doing something special.
 *
 * @return 1 on success and 0 on failure.
 */
iphone_error_t lockdownd_get_device_public_key(iphone_lckd_client_t control, gnutls_datum_t * public_key)
{
	return lockdownd_generic_get_value(control, "Key", "DevicePublicKey", public_key);
}

/** Completes the entire lockdownd handshake.
 *
 * @param phone The iPhone
 * @param lockdownd_client The pointer to the location of the lockdownd_client
 *
 * @return 1 on success and 0 on failure
 */
iphone_error_t iphone_lckd_new_client(iphone_device_t device, iphone_lckd_client_t * client)
{
	if (!device || !client || (client && *client))
		return IPHONE_E_INVALID_ARG;
	iphone_error_t ret = IPHONE_E_SUCCESS;
	char *host_id = NULL;

	iphone_lckd_client_t client_loc = new_lockdownd_client(device);
	if (!client_loc) {
		log_debug_msg("FATAL: lockdownd client could not be created!\n");
		return IPHONE_E_UNKNOWN_ERROR;
	}
	if (IPHONE_E_SUCCESS != lockdownd_hello(client_loc)) {
		log_debug_msg("Hello failed in the lockdownd client.\n");
		ret = IPHONE_E_NOT_ENOUGH_DATA;
	}


	char *uid = NULL;
	ret = lockdownd_get_device_uid(client_loc, &uid);
	if (IPHONE_E_SUCCESS != ret) {
		log_debug_msg("Device refused to send uid.\n");
	}

	host_id = get_host_id();
	if (IPHONE_E_SUCCESS == ret && !host_id) {
		log_debug_msg("No HostID found, run libiphone-initconf.\n");
		ret = IPHONE_E_INVALID_CONF;
	}

	if (IPHONE_E_SUCCESS == ret && !is_device_known(uid))
		ret = lockdownd_pair_device(client_loc, uid, host_id);

	if (uid) {
		free(uid);
		uid = NULL;
	}

	ret = lockdownd_start_SSL_session(client_loc, host_id);
	if (IPHONE_E_SUCCESS != ret) {
		ret = IPHONE_E_SSL_ERROR;
		log_debug_msg("SSL Session opening failed.\n");
	}

	if (host_id) {
		free(host_id);
		host_id = NULL;
	}

	if (IPHONE_E_SUCCESS == ret)
		*client = client_loc;
	return ret;
}

/** Generates the appropriate keys and pairs the device. It's part of the
 *  lockdownd handshake.
 *
 * @note You most likely want lockdownd_init unless you are doing something special.
 *
 * @return 1 on success and 0 on failure
 */
iphone_error_t lockdownd_pair_device(iphone_lckd_client_t control, char *uid, char *host_id)
{
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	plist_t dict = NULL;
	plist_t dict_record = NULL;

	gnutls_datum_t device_cert = { NULL, 0 };
	gnutls_datum_t host_cert = { NULL, 0 };
	gnutls_datum_t root_cert = { NULL, 0 };
	gnutls_datum_t public_key = { NULL, 0 };

	ret = lockdownd_get_device_public_key(control, &public_key);
	if (ret != IPHONE_E_SUCCESS) {
		log_debug_msg("Device refused to send public key.\n");
		return ret;
	}

	ret = lockdownd_gen_pair_cert(public_key, &device_cert, &host_cert, &root_cert);
	if (ret != IPHONE_E_SUCCESS) {
		free(public_key.data);
		return ret;
	}

	/* Setup Pair request plist */
	dict = plist_new_dict();
	plist_add_sub_key_el(dict, "PairRecord");
	dict_record = plist_new_dict();
	plist_add_sub_node(dict, dict_record);
	plist_add_sub_key_el(dict_record, "DeviceCertificate");
	plist_add_sub_data_el(dict_record, device_cert.data, device_cert.size);
	plist_add_sub_key_el(dict_record, "HostCertificate");
	plist_add_sub_data_el(dict_record, host_cert.data, host_cert.size);
	plist_add_sub_key_el(dict_record, "HostID");
	plist_add_sub_string_el(dict_record, host_id);
	plist_add_sub_key_el(dict_record, "RootCertificate");
	plist_add_sub_data_el(dict_record, root_cert.data, root_cert.size);
	plist_add_sub_key_el(dict_record, "Request");
	plist_add_sub_string_el(dict_record, "Pair");

	/* send to iPhone */
	ret = iphone_lckd_send(control, dict);
	plist_free(dict);
	dict = NULL;

	if (ret != IPHONE_E_SUCCESS)
		return ret;

	/* Now get iPhone's answer */
	ret = iphone_lckd_recv(control, &dict);

	if (ret != IPHONE_E_SUCCESS)
		return ret;

	plist_t query_node = plist_find_node_by_string(dict, "Pair");
	plist_t result_key_node = plist_get_next_sibling(query_node);
	plist_t result_value_node = plist_get_next_sibling(result_key_node);

	plist_type result_key_type = plist_get_node_type(result_key_node);
	plist_type result_value_type = plist_get_node_type(result_value_node);

	if (result_key_type == PLIST_KEY && result_value_type == PLIST_STRING) {

		char *result_key = NULL;
		char *result_value = NULL;

		plist_get_key_val(result_key_node, &result_key);
		plist_get_string_val(result_value_node, &result_value);

		if (!strcmp(result_key, "Result") && !strcmp(result_value, "Success")) {
			ret = IPHONE_E_SUCCESS;
		}

		free(result_key);
		free(result_value);
	}
	plist_free(dict);
	dict = NULL;

	/* store public key in config if pairing succeeded */
	if (ret == IPHONE_E_SUCCESS) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_pair_device: pair success\n");
		store_device_public_key(uid, public_key);
		ret = IPHONE_E_SUCCESS;
	} else {
		log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_pair_device: pair failure\n");
		ret = IPHONE_E_PAIRING_FAILED;
	}
	free(public_key.data);
	return ret;
}

/**
 * Performs the Goodbye Request to tell the device the communication
 * session is now closed.
 *
 * @param control The lockdown client
 */
void lockdownd_close(iphone_lckd_client_t control)
{
	if (!control)
		return;					//IPHONE_E_INVALID_ARG;

	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_add_sub_key_el(dict, "Request");
	plist_add_sub_string_el(dict, "Goodbye");

	log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_close() called\n");

	ret = iphone_lckd_send(control, dict);
	plist_free(dict);
	dict = NULL;

	ret = iphone_lckd_recv(control, &dict);

	if (!dict) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_close(): IPHONE_E_PLIST_ERROR\n");
		return;					// IPHONE_E_PLIST_ERROR;
	}

	plist_t query_node = plist_find_node_by_string(dict, "Goodbye");
	plist_t result_node = plist_get_next_sibling(query_node);
	plist_t value_node = plist_get_next_sibling(result_node);

	plist_type result_type = plist_get_node_type(result_node);
	plist_type value_type = plist_get_node_type(value_node);

	if (result_type == PLIST_KEY && value_type == PLIST_STRING) {
		char *result_value = NULL;
		char *value_value = NULL;

		plist_get_key_val(result_node, &result_value);
		plist_get_string_val(value_node, &value_value);

		if (!strcmp(result_value, "Result") && !strcmp(value_value, "Success")) {
			log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_close(): success\n");
			ret = IPHONE_E_SUCCESS;
		}
		free(result_value);
		free(value_value);
	}
	plist_free(dict);
	dict = NULL;
	return;						// ret;
}

/** Generates the device certificate from the public key as well as the host
 *  and root certificates.
 * 
 * @return IPHONE_E_SUCCESS on success.
 */
iphone_error_t lockdownd_gen_pair_cert(gnutls_datum_t public_key, gnutls_datum_t * odevice_cert,
									   gnutls_datum_t * ohost_cert, gnutls_datum_t * oroot_cert)
{
	if (!public_key.data || !odevice_cert || !ohost_cert || !oroot_cert)
		return IPHONE_E_INVALID_ARG;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	gnutls_datum_t modulus = { NULL, 0 };
	gnutls_datum_t exponent = { NULL, 0 };

	/* now decode the PEM encoded key */
	gnutls_datum_t der_pub_key;
	if (GNUTLS_E_SUCCESS == gnutls_pem_base64_decode_alloc("RSA PUBLIC KEY", &public_key, &der_pub_key)) {

		/* initalize asn.1 parser */
		ASN1_TYPE pkcs1 = ASN1_TYPE_EMPTY;
		if (ASN1_SUCCESS == asn1_array2tree(pkcs1_asn1_tab, &pkcs1, NULL)) {

			ASN1_TYPE asn1_pub_key = ASN1_TYPE_EMPTY;
			asn1_create_element(pkcs1, "PKCS1.RSAPublicKey", &asn1_pub_key);

			if (ASN1_SUCCESS == asn1_der_decoding(&asn1_pub_key, der_pub_key.data, der_pub_key.size, NULL)) {

				/* get size to read */
				int ret1 = asn1_read_value(asn1_pub_key, "modulus", NULL, &modulus.size);
				int ret2 = asn1_read_value(asn1_pub_key, "publicExponent", NULL, &exponent.size);

				modulus.data = gnutls_malloc(modulus.size);
				exponent.data = gnutls_malloc(exponent.size);

				ret1 = asn1_read_value(asn1_pub_key, "modulus", modulus.data, &modulus.size);
				ret2 = asn1_read_value(asn1_pub_key, "publicExponent", exponent.data, &exponent.size);
				if (ASN1_SUCCESS == ret1 && ASN1_SUCCESS == ret2)
					ret = IPHONE_E_SUCCESS;
			}
			if (asn1_pub_key)
				asn1_delete_structure(&asn1_pub_key);
		}
		if (pkcs1)
			asn1_delete_structure(&pkcs1);
	}

	/* now generate certifcates */
	if (IPHONE_E_SUCCESS == ret && 0 != modulus.size && 0 != exponent.size) {

		gnutls_global_init();
		gnutls_datum_t essentially_null = { strdup("abababababababab"), strlen("abababababababab") };

		gnutls_x509_privkey_t fake_privkey, root_privkey;
		gnutls_x509_crt_t dev_cert, root_cert, host_cert;

		gnutls_x509_privkey_init(&fake_privkey);
		gnutls_x509_crt_init(&dev_cert);
		gnutls_x509_crt_init(&root_cert);
		gnutls_x509_crt_init(&host_cert);

		if (GNUTLS_E_SUCCESS ==
			gnutls_x509_privkey_import_rsa_raw(fake_privkey, &modulus, &exponent, &essentially_null, &essentially_null,
											   &essentially_null, &essentially_null)) {

			gnutls_x509_privkey_init(&root_privkey);

			/* get root cert */
			gnutls_datum_t pem_root_cert = { NULL, 0 };
			get_root_certificate(&pem_root_cert);
			if (GNUTLS_E_SUCCESS != gnutls_x509_crt_import(root_cert, &pem_root_cert, GNUTLS_X509_FMT_PEM))
				ret = IPHONE_E_SSL_ERROR;

			/* get host cert */
			gnutls_datum_t pem_host_cert = { NULL, 0 };
			get_host_certificate(&pem_host_cert);
			if (GNUTLS_E_SUCCESS != gnutls_x509_crt_import(host_cert, &pem_host_cert, GNUTLS_X509_FMT_PEM))
				ret = IPHONE_E_SSL_ERROR;

			/* get root private key */
			gnutls_datum_t pem_root_priv = { NULL, 0 };
			get_root_private_key(&pem_root_priv);
			if (GNUTLS_E_SUCCESS != gnutls_x509_privkey_import(root_privkey, &pem_root_priv, GNUTLS_X509_FMT_PEM))
				ret = IPHONE_E_SSL_ERROR;

			/* generate device certificate */
			gnutls_x509_crt_set_key(dev_cert, fake_privkey);
			gnutls_x509_crt_set_serial(dev_cert, "\x00", 1);
			gnutls_x509_crt_set_version(dev_cert, 3);
			gnutls_x509_crt_set_ca_status(dev_cert, 0);
			gnutls_x509_crt_set_activation_time(dev_cert, time(NULL));
			gnutls_x509_crt_set_expiration_time(dev_cert, time(NULL) + (60 * 60 * 24 * 365 * 10));
			gnutls_x509_crt_sign(dev_cert, root_cert, root_privkey);

			if (IPHONE_E_SUCCESS == ret) {
				/* if everything went well, export in PEM format */
				gnutls_datum_t dev_pem = { NULL, 0 };
				gnutls_x509_crt_export(dev_cert, GNUTLS_X509_FMT_PEM, NULL, &dev_pem.size);
				dev_pem.data = gnutls_malloc(dev_pem.size);
				gnutls_x509_crt_export(dev_cert, GNUTLS_X509_FMT_PEM, dev_pem.data, &dev_pem.size);

				/* copy buffer for output */
				odevice_cert->data = malloc(dev_pem.size);
				memcpy(odevice_cert->data, dev_pem.data, dev_pem.size);
				odevice_cert->size = dev_pem.size;

				ohost_cert->data = malloc(pem_host_cert.size);
				memcpy(ohost_cert->data, pem_host_cert.data, pem_host_cert.size);
				ohost_cert->size = pem_host_cert.size;

				oroot_cert->data = malloc(pem_root_cert.size);
				memcpy(oroot_cert->data, pem_root_cert.data, pem_root_cert.size);
				oroot_cert->size = pem_root_cert.size;
			}
			gnutls_free(pem_root_priv.data);
			gnutls_free(pem_root_cert.data);
			gnutls_free(pem_host_cert.data);
		}
	}

	gnutls_free(modulus.data);
	gnutls_free(exponent.data);

	gnutls_free(der_pub_key.data);

	return ret;
}

/** Starts SSL communication with lockdownd after the iPhone has been paired.
 *
 * @param control The lockdownd client
 * @param HostID The HostID used with this phone
 *
 * @return 1 on success and 0 on failure
 */
iphone_error_t lockdownd_start_SSL_session(iphone_lckd_client_t control, const char *HostID)
{
	plist_t dict = NULL;
	uint32_t return_me = 0;

	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;
	control->session_id[0] = '\0';

	/* Setup DevicePublicKey request plist */
	dict = plist_new_dict();
	plist_add_sub_key_el(dict, "HostID");
	plist_add_sub_string_el(dict, HostID);
	plist_add_sub_key_el(dict, "Request");
	plist_add_sub_string_el(dict, "StartSession");

	ret = iphone_lckd_send(control, dict);
	plist_free(dict);
	dict = NULL;

	if (ret != IPHONE_E_SUCCESS)
		return ret;

	ret = iphone_lckd_recv(control, &dict);

	if (!dict)
		return IPHONE_E_PLIST_ERROR;

	plist_t query_node = plist_find_node_by_string(dict, "StartSession");
	plist_t result_key_node = plist_get_next_sibling(query_node);
	plist_t result_value_node = plist_get_next_sibling(result_key_node);

	plist_type result_key_type = plist_get_node_type(result_key_node);
	plist_type result_value_type = plist_get_node_type(result_value_node);

	if (result_key_type == PLIST_KEY && result_value_type == PLIST_STRING) {
		char *result_key = NULL;
		char *result_value = NULL;

		plist_get_key_val(result_key_node, &result_key);
		plist_get_string_val(result_value_node, &result_value);

		ret = IPHONE_E_SSL_ERROR;
		if (!strcmp(result_key, "Result") && !strcmp(result_value, "Success")) {
			// Set up GnuTLS...
			//gnutls_anon_client_credentials_t anoncred;
			gnutls_certificate_credentials_t xcred;

			log_dbg_msg(DBGMASK_LOCKDOWND, "We started the session OK, now trying GnuTLS\n");
			errno = 0;
			gnutls_global_init();
			//gnutls_anon_allocate_client_credentials(&anoncred);
			gnutls_certificate_allocate_credentials(&xcred);
			gnutls_certificate_set_x509_trust_file(xcred, "hostcert.pem", GNUTLS_X509_FMT_PEM);
			gnutls_init(control->ssl_session, GNUTLS_CLIENT);
			{
				int protocol_priority[16] = { GNUTLS_SSL3, 0 };
				int kx_priority[16] = { GNUTLS_KX_ANON_DH, GNUTLS_KX_RSA, 0 };
				int cipher_priority[16] = { GNUTLS_CIPHER_AES_128_CBC, GNUTLS_CIPHER_AES_256_CBC, 0 };
				int mac_priority[16] = { GNUTLS_MAC_SHA1, GNUTLS_MAC_MD5, 0 };
				int comp_priority[16] = { GNUTLS_COMP_NULL, 0 };

				gnutls_cipher_set_priority(*control->ssl_session, cipher_priority);
				gnutls_compression_set_priority(*control->ssl_session, comp_priority);
				gnutls_kx_set_priority(*control->ssl_session, kx_priority);
				gnutls_protocol_set_priority(*control->ssl_session, protocol_priority);
				gnutls_mac_set_priority(*control->ssl_session, mac_priority);

			}
			gnutls_credentials_set(*control->ssl_session, GNUTLS_CRD_CERTIFICATE, xcred);	// this part is killing me.

			log_dbg_msg(DBGMASK_LOCKDOWND, "GnuTLS step 1...\n");
			gnutls_transport_set_ptr(*control->ssl_session, (gnutls_transport_ptr_t) control);
			log_dbg_msg(DBGMASK_LOCKDOWND, "GnuTLS step 2...\n");
			gnutls_transport_set_push_function(*control->ssl_session, (gnutls_push_func) & lockdownd_secuwrite);
			log_dbg_msg(DBGMASK_LOCKDOWND, "GnuTLS step 3...\n");
			gnutls_transport_set_pull_function(*control->ssl_session, (gnutls_pull_func) & lockdownd_securead);
			log_dbg_msg(DBGMASK_LOCKDOWND, "GnuTLS step 4 -- now handshaking...\n");

			if (errno)
				log_dbg_msg(DBGMASK_LOCKDOWND, "WARN: errno says %s before handshake!\n", strerror(errno));
			return_me = gnutls_handshake(*control->ssl_session);
			log_dbg_msg(DBGMASK_LOCKDOWND, "GnuTLS handshake done...\n");

			if (return_me != GNUTLS_E_SUCCESS) {
				log_dbg_msg(DBGMASK_LOCKDOWND, "GnuTLS reported something wrong.\n");
				gnutls_perror(return_me);
				log_dbg_msg(DBGMASK_LOCKDOWND, "oh.. errno says %s\n", strerror(errno));
				return IPHONE_E_SSL_ERROR;
			} else {
				control->in_SSL = 1;
				ret = IPHONE_E_SUCCESS;
			}
		}
	}
	//store session id
	plist_t session_node = plist_find_node_by_key(dict, "SessionID");
	if (session_node) {

		plist_t session_node_val = plist_get_next_sibling(session_node);
		plist_type session_node_val_type = plist_get_node_type(session_node_val);

		if (session_node_val_type == PLIST_STRING) {

			char *session_id = NULL;
			plist_get_string_val(session_node_val, &session_id);

			if (session_node_val_type == PLIST_STRING && session_id) {
				// we need to store the session ID for StopSession
				strcpy(control->session_id, session_id);
				log_dbg_msg(DBGMASK_LOCKDOWND, "SessionID: %s\n", control->session_id);
			}
			free(session_id);
		}
	} else
		log_dbg_msg(DBGMASK_LOCKDOWND, "Failed to get SessionID!\n");
	plist_free(dict);
	dict = NULL;

	if (ret == IPHONE_E_SUCCESS)
		return ret;

	log_dbg_msg(DBGMASK_LOCKDOWND, "Apparently failed negotiating with lockdownd.\n");
	return IPHONE_E_SSL_ERROR;
}

/** gnutls callback for writing data to the iPhone.
 *
 * @param transport It's really the lockdownd client, but the method signature has to match
 * @param buffer The data to send
 * @param length The length of data to send in bytes
 *
 * @return The number of bytes sent
 */
ssize_t lockdownd_secuwrite(gnutls_transport_ptr_t transport, char *buffer, size_t length)
{
	int bytes = 0;
	iphone_lckd_client_t control;
	control = (iphone_lckd_client_t) transport;
	log_dbg_msg(DBGMASK_LOCKDOWND, "lockdownd_secuwrite() called\n");
	log_dbg_msg(DBGMASK_LOCKDOWND, "pre-send\nlength = %zi\n", length);
	iphone_mux_send(control->connection, buffer, length, &bytes);
	log_dbg_msg(DBGMASK_LOCKDOWND, "post-send\nsent %i bytes\n", bytes);

	dump_debug_buffer("sslpacketwrite.out", buffer, length);
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
ssize_t lockdownd_securead(gnutls_transport_ptr_t transport, char *buffer, size_t length)
{
	int bytes = 0, pos_start_fill = 0;
	int tbytes = 0;
	int this_len = length;
	iphone_error_t res;
	iphone_lckd_client_t control;
	control = (iphone_lckd_client_t) transport;
	char *recv_buffer;

	log_debug_msg("lockdownd_securead() called\nlength = %zi\n", length);

	log_debug_msg("pre-read\nclient wants %zi bytes\n", length);

	recv_buffer = (char *) malloc(sizeof(char) * this_len);

	// repeat until we have the full data or an error occurs.
	do {
		if ((res = iphone_mux_recv(control->connection, recv_buffer, this_len, &bytes)) != IPHONE_E_SUCCESS) {
			log_debug_msg("%s: ERROR: iphone_mux_recv returned %d\n", __func__, res);
			return res;
		}
		log_debug_msg("post-read\nwe got %i bytes\n", bytes);

		if (bytes < 0) {
			log_debug_msg("lockdownd_securead(): uh oh\n");
			log_debug_msg
				("I believe what we have here is a failure to communicate... libusb says %s but strerror says %s\n",
				 usb_strerror(), strerror(errno));
			return bytes;		// + 28;      // an errno
		}
		// increase read count
		tbytes += bytes;

		// fill the buffer with what we got right now
		memcpy(buffer + pos_start_fill, recv_buffer, bytes);
		pos_start_fill += bytes;

		if (tbytes >= length) {
			break;
		}

		this_len = length - tbytes;
		log_debug_msg("re-read\ntrying to read missing %i bytes\n", this_len);
	} while (tbytes < length);
	if (recv_buffer) {
		free(recv_buffer);
	}

	return tbytes;
}

/** Command to start the desired service
 *
 * @param control The lockdownd client
 * @param service The name of the service to start
 *
 * @return The port number the service was started on or 0 on failure.
 */
iphone_error_t iphone_lckd_start_service(iphone_lckd_client_t client, const char *service, int *port)
{
	if (!client || !service || !port)
		return IPHONE_E_INVALID_ARG;

	char *host_id = get_host_id();
	if (!host_id)
		return IPHONE_E_INVALID_CONF;
	if (!client->in_SSL && !lockdownd_start_SSL_session(client, host_id))
		return IPHONE_E_SSL_ERROR;

	plist_t dict = NULL;
	uint32_t port_loc = 0;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	free(host_id);
	host_id = NULL;

	dict = plist_new_dict();
	plist_add_sub_key_el(dict, "Request");
	plist_add_sub_string_el(dict, "StartService");
	plist_add_sub_key_el(dict, "Service");
	plist_add_sub_string_el(dict, service);

	/* send to iPhone */
	ret = iphone_lckd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (IPHONE_E_SUCCESS != ret)
		return ret;

	ret = iphone_lckd_recv(client, &dict);

	if (IPHONE_E_SUCCESS != ret)
		return ret;

	if (!dict)
		return IPHONE_E_PLIST_ERROR;

	plist_t query_node = plist_find_node_by_string(dict, "StartService");
	plist_t result_key_node = plist_get_next_sibling(query_node);
	plist_t result_value_node = plist_get_next_sibling(result_key_node);

	plist_t port_key_node = plist_find_node_by_key(dict, "Port");
	plist_t port_value_node = plist_get_next_sibling(port_key_node);

	plist_type result_key_type = plist_get_node_type(result_key_node);
	plist_type result_value_type = plist_get_node_type(result_value_node);
	plist_type port_key_type = plist_get_node_type(port_key_node);
	plist_type port_value_type = plist_get_node_type(port_value_node);

	if (result_key_type == PLIST_KEY && result_value_type == PLIST_STRING && port_key_type == PLIST_KEY
		&& port_value_type == PLIST_UINT) {

		char *result_key = NULL;
		char *result_value = NULL;
		char *port_key = NULL;
		uint64_t port_value = 0;

		plist_get_key_val(result_key_node, &result_key);
		plist_get_string_val(result_value_node, &result_value);
		plist_get_key_val(port_key_node, &port_key);
		plist_get_uint_val(port_value_node, &port_value);

		if (!strcmp(result_key, "Result") && !strcmp(result_value, "Success") && !strcmp(port_key, "Port")) {
			port_loc = port_value;
			ret = IPHONE_E_SUCCESS;
		}

		if (port && ret == IPHONE_E_SUCCESS)
			*port = port_loc;
		else
			ret = IPHONE_E_UNKNOWN_ERROR;
	}

	plist_free(dict);
	dict = NULL;
	return ret;
}
