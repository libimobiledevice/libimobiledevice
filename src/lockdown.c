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

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <libtasn1.h>
#include <gnutls/x509.h>
#include <plist/plist.h>

#include "lockdown.h"
#include "iphone.h"
#include "utils.h"
#include "userpref.h"

#define RESULT_SUCCESS 0
#define RESULT_FAILURE 1

const ASN1_ARRAY_TYPE pkcs1_asn1_tab[] = {
	{"PKCS1", 536872976, 0},
	{0, 1073741836, 0},
	{"RSAPublicKey", 536870917, 0},
	{"modulus", 1073741827, 0},
	{"publicExponent", 3, 0},
	{0, 0, 0}
};

/**
 * Internally used function for checking the result from lockdown's answer
 * plist to a previously sent request.
 *
 * @param dict The plist to evaluate.
 * @param query_match Name of the request to match.
 *
 * @return RESULT_SUCCESS when the result is 'Success',
 *         RESULT_FAILURE when the result is 'Failure',
 *         or a negative value if an error occured during evaluation.
 */
static int lockdown_check_result(plist_t dict, const char *query_match)
{
	int ret = -1;

	plist_t query_node = plist_dict_get_item(dict, "Request");
	if (!query_node) {
		return ret;
	}
	if (plist_get_node_type(query_node) != PLIST_STRING) {
		return ret;
	} else {
		char *query_value = NULL;
		plist_get_string_val(query_node, &query_value);
		if (!query_value) {
			return ret;
		}
		if (strcmp(query_value, query_match) != 0) {
			free(query_value);
			return ret;
		}
		free(query_value);
	}

	plist_t result_node = plist_dict_get_item(dict, "Result");
	if (!result_node) {
		return ret;
	}

	plist_type result_type = plist_get_node_type(result_node);

	if (result_type == PLIST_STRING) {

		char *result_value = NULL;

		plist_get_string_val(result_node, &result_value);

		if (result_value) {
			if (!strcmp(result_value, "Success")) {
				ret = RESULT_SUCCESS;
			} else if (!strcmp(result_value, "Failure")) {
				ret = RESULT_FAILURE;
			} else {
				log_dbg_msg(DBGMASK_LOCKDOWND, "%s: ERROR: unknown result value '%s'\n", __func__, result_value);
			}
		}
		if (result_value)
			free(result_value);
	}
	return ret;
}

/**
 * Closes the lockdownd communication session, by sending
 * the StopSession Request to the device.
 *
 * @param control The lockdown client
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_stop_session(lockdownd_client_t client, const char *session_id)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict,"Request", plist_new_string("StopSession"));
	plist_dict_insert_item(dict,"SessionID", plist_new_string(session_id));

	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: called\n", __func__);

	ret = lockdownd_send(client, dict);

	plist_free(dict);
	dict = NULL;

	ret = lockdownd_recv(client, &dict);

	if (!dict) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: LOCKDOWN_E_PLIST_ERROR\n", __func__);
		return LOCKDOWN_E_PLIST_ERROR;
	}

	ret = LOCKDOWN_E_UNKNOWN_ERROR;
	if (lockdown_check_result(dict, "StopSession") == RESULT_SUCCESS) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: success\n", __func__);
		ret = LOCKDOWN_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;

	return ret;
}

/**
 * Shuts down the SSL session by first calling iphone_lckd_stop_session
 * to cleanly close the lockdownd communication session, and then
 * performing a close notify, which is done by "gnutls_bye".
 *
 * @param client The lockdown client
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
static lockdownd_error_t lockdownd_stop_ssl_session(lockdownd_client_t client)
{
	if (!client) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: invalid argument!\n", __func__);
		return LOCKDOWN_E_INVALID_ARG;
	}
	lockdownd_error_t ret = LOCKDOWN_E_SUCCESS;

	if (client->in_SSL) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: stopping SSL session\n", __func__);
		ret = lockdownd_stop_session(client, client->session_id);
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: sending SSL close notify\n", __func__);
		gnutls_bye(*client->ssl_session, GNUTLS_SHUT_RDWR);
	}
	if (client->ssl_session) {
		gnutls_deinit(*client->ssl_session);
		free(client->ssl_session);
	}
	client->in_SSL = 0;

	return ret;
}

/** Closes the lockdownd client and does the necessary housekeeping.
 *
 * @param client The lockdown client
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_client_free(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	lockdownd_stop_ssl_session(client);

	if (client->connection) {
		lockdownd_goodbye(client);

		// IMO, read of final "sessionUpcall connection closed" packet
		//  should come here instead of in iphone_free_device
		if ((ret = iphone_device_disconnect(client->connection)) != IPHONE_E_SUCCESS) {
			ret = LOCKDOWN_E_UNKNOWN_ERROR;
		}
	}

	free(client);
	return ret;
}

/** Polls the iPhone for lockdownd data.
 *
 * @param control The lockdownd client
 * @param plist The plist to store the received data
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_recv(lockdownd_client_t client, plist_t *plist)
{
	if (!client || !plist || (plist && *plist))
		return LOCKDOWN_E_INVALID_ARG;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	char *receive = NULL;
	uint32_t datalen = 0, bytes = 0, received_bytes = 0;

	if (!client->in_SSL)
		ret = iphone_device_recv(client->connection, (char *) &datalen, sizeof(datalen), &bytes);
	else {
		ssize_t res = gnutls_record_recv(*client->ssl_session, &datalen, sizeof(datalen));
		if (res < 0) {
			log_dbg_msg(DBGMASK_LOCKDOWND, "gnutls_record_recv: Error occured: %s\n", gnutls_strerror(res));
			return LOCKDOWN_E_SSL_ERROR;
		} else {
			bytes = res;
			ret = LOCKDOWN_E_SUCCESS;
		}
	}
	datalen = ntohl(datalen);
	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: datalen = %d\n", __func__, datalen);

	receive = (char *) malloc(sizeof(char) * datalen);

	/* fill buffer and request more packets if needed */
	if (!client->in_SSL) {
		while ((received_bytes < datalen) && (ret == LOCKDOWN_E_SUCCESS)) {
			ret = iphone_device_recv(client->connection, receive + received_bytes, datalen - received_bytes, &bytes);
			received_bytes += bytes;
		}
	} else {
		ssize_t res = 0;
		while ((received_bytes < datalen) && (ret == LOCKDOWN_E_SUCCESS)) {
			res = gnutls_record_recv(*client->ssl_session, receive + received_bytes, datalen - received_bytes);
			if (res < 0) {
				log_dbg_msg(DBGMASK_LOCKDOWND, "gnutls_record_recv: Error occured: %s\n", gnutls_strerror(res));
				ret = LOCKDOWN_E_SSL_ERROR;
			} else {
				received_bytes += res;
				ret = LOCKDOWN_E_SUCCESS;
			}
		}
	}

	if (ret != LOCKDOWN_E_SUCCESS) {
		free(receive);
		return ret;
	}

	if ((ssize_t)received_bytes <= 0) {
		free(receive);
		return LOCKDOWN_E_NOT_ENOUGH_DATA;
	}

	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: received msg size: %i, buffer follows:\n%s", __func__, received_bytes, receive);
	plist_from_xml(receive, received_bytes, plist);
	free(receive);

	if (!*plist)
		ret = LOCKDOWN_E_PLIST_ERROR;

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
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_send(lockdownd_client_t client, plist_t plist)
{
	if (!client || !plist)
		return LOCKDOWN_E_INVALID_ARG;
	char *real_query;
	int bytes;
	char *XMLContent = NULL;
	uint32_t length = 0;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_to_xml(plist, &XMLContent, &length);
	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: sending msg size %i, buffer follows:\n%s", __func__, length, XMLContent);

	real_query = (char *) malloc(sizeof(char) * (length + 4));
	length = htonl(length);
	memcpy(real_query, &length, sizeof(length));
	memcpy(real_query + 4, XMLContent, ntohl(length));
	free(XMLContent);
	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: made the query, sending it along\n", __func__);

	if (!client->in_SSL)
		ret = iphone_device_send(client->connection, real_query, ntohl(length) + sizeof(length), (uint32_t*)&bytes);
	else {
		ssize_t res = gnutls_record_send(*client->ssl_session, real_query, ntohl(length) + sizeof(length));
		if (res < 0) {
			log_dbg_msg(DBGMASK_LOCKDOWND, "gnutls_record_send: Error occured: %s\n", gnutls_strerror(res));
			ret = LOCKDOWN_E_SSL_ERROR;
		} else {
			bytes = res;
			ret = LOCKDOWN_E_SUCCESS;
		}
	}
	if (ret == LOCKDOWN_E_SUCCESS) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: sent it!\n", __func__);
	} else {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: sending failed!\n", __func__);
	}
	free(real_query);

	return ret;
}

/** Initiates the handshake for the lockdown session. Part of the lockdownd handshake.
 *
 * @param client The lockdownd client
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_query_type(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict,"Request", plist_new_string("QueryType"));

	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: called\n", __func__);
	ret = lockdownd_send(client, dict);

	plist_free(dict);
	dict = NULL;

	ret = lockdownd_recv(client, &dict);

	if (LOCKDOWN_E_SUCCESS != ret)
		return ret;

	ret = LOCKDOWN_E_UNKNOWN_ERROR;
	if (lockdown_check_result(dict, "QueryType") == RESULT_SUCCESS) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: success\n", __func__);
		ret = LOCKDOWN_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;

	return ret;
}

/** Retrieves a preferences plist using an optional domain and/or key name.
 *
 * @param client an initialized lockdownd client.
 * @param domain the domain to query on or NULL for global domain
 * @param key the key name to request or NULL to query for all keys
 * @param value a plist node representing the result value node
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_get_value(lockdownd_client_t client, const char *domain, const char *key, plist_t *value)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	plist_t dict = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* setup request plist */
	dict = plist_new_dict();
	if (domain) {
		plist_dict_insert_item(dict,"Domain", plist_new_string(domain));
	}
	if (key) {
		plist_dict_insert_item(dict,"Key", plist_new_string(key));
	}
	plist_dict_insert_item(dict,"Request", plist_new_string("GetValue"));

	/* send to device */
	ret = lockdownd_send(client, dict);

	plist_free(dict);
	dict = NULL;

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	/* Now get device's answer */
	ret = lockdownd_recv(client, &dict);
	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	if (lockdown_check_result(dict, "GetValue") == RESULT_SUCCESS) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: success\n", __func__);
		ret = LOCKDOWN_E_SUCCESS;
	}
	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_t value_node = plist_dict_get_item(dict, "Value");

	if (value_node) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: has a value\n", __func__);
		*value = plist_copy(value_node);
	}

	plist_free(dict);
	return ret;
}

/** Sets a preferences value using a plist and optional domain and/or key name.
 *
 * @param client an initialized lockdownd client.
 * @param domain the domain to query on or NULL for global domain
 * @param key the key name to set the value or NULL to set a value dict plist
 * @param value a plist node of any node type representing the value to set
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_set_value(lockdownd_client_t client, const char *domain, const char *key, plist_t value)
{
	if (!client || !value)
		return LOCKDOWN_E_INVALID_ARG;

	plist_t dict = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* setup request plist */
	dict = plist_new_dict();
	if (domain) {
		plist_dict_insert_item(dict,"Domain", plist_new_string(domain));
	}
	if (key) {
		plist_dict_insert_item(dict,"Key", plist_new_string(key));
	}
	plist_dict_insert_item(dict,"Request", plist_new_string("SetValue"));
	plist_dict_insert_item(dict,"Value", value);

	/* send to device */
	ret = lockdownd_send(client, dict);

	plist_free(dict);
	dict = NULL;

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	/* Now get device's answer */
	ret = lockdownd_recv(client, &dict);
	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	if (lockdown_check_result(dict, "SetValue") == RESULT_SUCCESS) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: success\n", __func__);
		ret = LOCKDOWN_E_SUCCESS;
	}

	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_free(dict);
	return ret;
}

/** Removes a preference node on the device by domain and/or key name
 *
 * @note: Use with caution as this could remove vital information on the device
 *
 * @param client an initialized lockdownd client.
 * @param domain the domain to query on or NULL for global domain
 * @param key the key name to remove or NULL remove all keys for the current domain
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_remove_value(lockdownd_client_t client, const char *domain, const char *key)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	plist_t dict = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* setup request plist */
	dict = plist_new_dict();
	if (domain) {
		plist_dict_insert_item(dict,"Domain", plist_new_string(domain));
	}
	if (key) {
		plist_dict_insert_item(dict,"Key", plist_new_string(key));
	}
	plist_dict_insert_item(dict,"Request", plist_new_string("RemoveValue"));

	/* send to device */
	ret = lockdownd_send(client, dict);

	plist_free(dict);
	dict = NULL;

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	/* Now get device's answer */
	ret = lockdownd_recv(client, &dict);
	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	if (lockdown_check_result(dict, "RemoveValue") == RESULT_SUCCESS) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: success\n", __func__);
		ret = LOCKDOWN_E_SUCCESS;
	}

	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_free(dict);
	return ret;
}

/** Asks for the device's unique id. Part of the lockdownd handshake.
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_get_device_uuid(lockdownd_client_t client, char **uuid)
{
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	plist_t value = NULL;

	ret = lockdownd_get_value(client, NULL, "UniqueDeviceID", &value);
	if (ret != LOCKDOWN_E_SUCCESS) {
		return ret;
	}
	plist_get_string_val(value, uuid);

	plist_free(value);
	value = NULL;
	return ret;
}

/** Askes for the device's public key. Part of the lockdownd handshake.
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_get_device_public_key(lockdownd_client_t client, gnutls_datum_t * public_key)
{
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	plist_t value = NULL;
	char *value_value = NULL;
	uint64_t size = 0;

	ret = lockdownd_get_value(client, NULL, "DevicePublicKey", &value);
	if (ret != LOCKDOWN_E_SUCCESS) {
		return ret;
	}
	plist_get_data_val(value, &value_value, &size);
	public_key->data = (unsigned char*)value_value;
	public_key->size = size;

	plist_free(value);
	value = NULL;

	return ret;
}

/** Askes for the device's name.
 *
 * @param client The pointer to the location of the new lockdownd_client
 *
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_get_device_name(lockdownd_client_t client, char **device_name)
{
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	plist_t value = NULL;

	ret = lockdownd_get_value(client, NULL, "DeviceName", &value);
	if (ret != LOCKDOWN_E_SUCCESS) {
		return ret;
	}
	plist_get_string_val(value, device_name);

	plist_free(value);
	value = NULL;

	return ret;
}

/** Creates a lockdownd client for the give iPhone
 *
 * @param phone The iPhone to create a lockdownd client for
 * @param client The pointer to the location of the new lockdownd_client
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_client_new(iphone_device_t device, lockdownd_client_t *client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;
	lockdownd_error_t ret = LOCKDOWN_E_SUCCESS;
	char *host_id = NULL;

	iphone_connection_t connection;
	if (iphone_device_connect(device, 0xf27e, &connection) != IPHONE_E_SUCCESS) {
		log_debug_msg("%s: could not connect to lockdownd (device %s)\n", __func__, device->uuid);
		return LOCKDOWN_E_MUX_ERROR;
	}

	lockdownd_client_t client_loc = (lockdownd_client_t) malloc(sizeof(struct lockdownd_client_int));
	client_loc->connection = connection;
	client_loc->ssl_session = (gnutls_session_t *) malloc(sizeof(gnutls_session_t));
	client_loc->in_SSL = 0;

	if (LOCKDOWN_E_SUCCESS != lockdownd_query_type(client_loc)) {
		log_debug_msg("%s: QueryType failed in the lockdownd client.\n", __func__);
		ret = LOCKDOWN_E_NOT_ENOUGH_DATA;
	}

	char *uuid = NULL;
	ret = iphone_device_get_uuid(device, &uuid);
	if (LOCKDOWN_E_SUCCESS != ret) {
		log_debug_msg("%s: failed to get device uuid.\n", __func__);
	}
	log_debug_msg("%s: device uuid: %s\n", __func__, uuid);

	userpref_get_host_id(&host_id);
	if (LOCKDOWN_E_SUCCESS == ret && !host_id) {
		ret = LOCKDOWN_E_INVALID_CONF;
	}

	if (LOCKDOWN_E_SUCCESS == ret && !userpref_has_device_public_key(uuid))
		ret = lockdownd_pair(client_loc, uuid, host_id);

	if (uuid) {
		free(uuid);
		uuid = NULL;
	}

	if (LOCKDOWN_E_SUCCESS == ret) {
		ret = lockdownd_start_ssl_session(client_loc, host_id);
		if (LOCKDOWN_E_SUCCESS != ret) {
			ret = LOCKDOWN_E_SSL_ERROR;
			log_debug_msg("%s: SSL Session opening failed.\n", __func__);
		}

		if (host_id) {
			free(host_id);
			host_id = NULL;
		}

		if (LOCKDOWN_E_SUCCESS == ret)
			*client = client_loc;
	}

	return ret;
}

/** Generates the appropriate keys and pairs the device. It's part of the
 *  lockdownd handshake.
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_pair(lockdownd_client_t client, char *uuid, char *host_id)
{
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	plist_t dict = NULL;
	plist_t dict_record = NULL;

	gnutls_datum_t device_cert = { NULL, 0 };
	gnutls_datum_t host_cert = { NULL, 0 };
	gnutls_datum_t root_cert = { NULL, 0 };
	gnutls_datum_t public_key = { NULL, 0 };

	ret = lockdownd_get_device_public_key(client, &public_key);
	if (ret != LOCKDOWN_E_SUCCESS) {
		log_debug_msg("%s: device refused to send public key.\n", __func__);
		return ret;
	}
	log_debug_msg("%s: device public key follows:\n%s\n", __func__, public_key.data);

	ret = lockdownd_gen_pair_cert(public_key, &device_cert, &host_cert, &root_cert);
	if (ret != LOCKDOWN_E_SUCCESS) {
		free(public_key.data);
		return ret;
	}

	/* Setup Pair request plist */
	dict = plist_new_dict();
	dict_record = plist_new_dict();
	plist_dict_insert_item(dict,"PairRecord", dict_record);

	plist_dict_insert_item(dict_record, "DeviceCertificate", plist_new_data((const char*)device_cert.data, device_cert.size));
	plist_dict_insert_item(dict_record, "HostCertificate", plist_new_data((const char*)host_cert.data, host_cert.size));
	plist_dict_insert_item(dict_record, "HostID", plist_new_string(host_id));
	plist_dict_insert_item(dict_record, "RootCertificate", plist_new_data((const char*)root_cert.data, root_cert.size));

	plist_dict_insert_item(dict, "Request", plist_new_string("Pair"));

	/* send to iPhone */
	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	/* Now get iPhone's answer */
	ret = lockdownd_recv(client, &dict);

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	if (lockdown_check_result(dict, "Pair") == RESULT_SUCCESS) {
		ret = LOCKDOWN_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;

	/* store public key in config if pairing succeeded */
	if (ret == LOCKDOWN_E_SUCCESS) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: pair success\n", __func__);
		userpref_set_device_public_key(uuid, public_key);
	} else {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: pair failure\n", __func__);
		ret = LOCKDOWN_E_PAIRING_FAILED;
	}
	free(public_key.data);
	return ret;
}

/**
 * Tells the device to immediately enter recovery mode.
 *
 * @param client The lockdown client
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_enter_recovery(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict,"Request", plist_new_string("EnterRecovery"));

	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: telling device to enter recovery mode\n", __func__);

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = lockdownd_recv(client, &dict);

	if (lockdown_check_result(dict, "EnterRecovery") == RESULT_SUCCESS) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: success\n", __func__);
		ret = LOCKDOWN_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;
	return ret;
}

/**
 * Performs the Goodbye Request to tell the device the communication
 * session is now closed.
 *
 * @param client The lockdown client
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_goodbye(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict,"Request", plist_new_string("Goodbye"));

	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: called\n", __func__);

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = lockdownd_recv(client, &dict);
	if (!dict) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: did not get goodbye response back\n", __func__);
		return LOCKDOWN_E_PLIST_ERROR;
	}

	if (lockdown_check_result(dict, "Goodbye") == RESULT_SUCCESS) {
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: success\n", __func__);
		ret = LOCKDOWN_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;
	return ret;
}

/** Generates the device certificate from the public key as well as the host
 *  and root certificates.
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_gen_pair_cert(gnutls_datum_t public_key, gnutls_datum_t * odevice_cert,
									   gnutls_datum_t * ohost_cert, gnutls_datum_t * oroot_cert)
{
	if (!public_key.data || !odevice_cert || !ohost_cert || !oroot_cert)
		return LOCKDOWN_E_INVALID_ARG;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	userpref_error_t uret = USERPREF_E_UNKNOWN_ERROR;

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
				int ret1 = asn1_read_value(asn1_pub_key, "modulus", NULL, (int*)&modulus.size);
				int ret2 = asn1_read_value(asn1_pub_key, "publicExponent", NULL, (int*)&exponent.size);

				modulus.data = gnutls_malloc(modulus.size);
				exponent.data = gnutls_malloc(exponent.size);

				ret1 = asn1_read_value(asn1_pub_key, "modulus", modulus.data, (int*)&modulus.size);
				ret2 = asn1_read_value(asn1_pub_key, "publicExponent", exponent.data, (int*)&exponent.size);
				if (ASN1_SUCCESS == ret1 && ASN1_SUCCESS == ret2)
					ret = LOCKDOWN_E_SUCCESS;
			}
			if (asn1_pub_key)
				asn1_delete_structure(&asn1_pub_key);
		}
		if (pkcs1)
			asn1_delete_structure(&pkcs1);
	}

	/* now generate certifcates */
	if (LOCKDOWN_E_SUCCESS == ret && 0 != modulus.size && 0 != exponent.size) {

		gnutls_global_init();
		gnutls_datum_t essentially_null = { (unsigned char*)strdup("abababababababab"), strlen("abababababababab") };

		gnutls_x509_privkey_t fake_privkey, root_privkey, host_privkey;
		gnutls_x509_crt_t dev_cert, root_cert, host_cert;

		gnutls_x509_privkey_init(&fake_privkey);
		gnutls_x509_crt_init(&dev_cert);
		gnutls_x509_crt_init(&root_cert);
		gnutls_x509_crt_init(&host_cert);

		if (GNUTLS_E_SUCCESS ==
			gnutls_x509_privkey_import_rsa_raw(fake_privkey, &modulus, &exponent, &essentially_null, &essentially_null,
											   &essentially_null, &essentially_null)) {

			gnutls_x509_privkey_init(&root_privkey);
			gnutls_x509_privkey_init(&host_privkey);

			uret = userpref_get_keys_and_certs(root_privkey, root_cert, host_privkey, host_cert);

			if (USERPREF_E_SUCCESS == uret) {
				/* generate device certificate */
				gnutls_x509_crt_set_key(dev_cert, fake_privkey);
				gnutls_x509_crt_set_serial(dev_cert, "\x00", 1);
				gnutls_x509_crt_set_version(dev_cert, 3);
				gnutls_x509_crt_set_ca_status(dev_cert, 0);
				gnutls_x509_crt_set_activation_time(dev_cert, time(NULL));
				gnutls_x509_crt_set_expiration_time(dev_cert, time(NULL) + (60 * 60 * 24 * 365 * 10));
				gnutls_x509_crt_sign(dev_cert, root_cert, root_privkey);

				if (LOCKDOWN_E_SUCCESS == ret) {
					/* if everything went well, export in PEM format */
					size_t export_size = 0;
					gnutls_datum_t dev_pem = { NULL, 0 };
					gnutls_x509_crt_export(dev_cert, GNUTLS_X509_FMT_PEM, NULL, &export_size);
					dev_pem.data = gnutls_malloc(export_size);
					gnutls_x509_crt_export(dev_cert, GNUTLS_X509_FMT_PEM, dev_pem.data, &export_size);
					dev_pem.size = export_size;

					gnutls_datum_t pem_root_cert = { NULL, 0 };
					gnutls_datum_t pem_host_cert = { NULL, 0 };

					uret = userpref_get_certs_as_pem(&pem_root_cert, &pem_host_cert);

					if (USERPREF_E_SUCCESS == uret) {
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

						g_free(pem_root_cert.data);
						g_free(pem_host_cert.data);
					}
				}
			}

			switch(uret) {
			case USERPREF_E_INVALID_ARG:
				ret = LOCKDOWN_E_INVALID_ARG;
				break;
			case USERPREF_E_INVALID_CONF:
				ret = LOCKDOWN_E_INVALID_CONF;
				break;
			case USERPREF_E_SSL_ERROR:
				ret = LOCKDOWN_E_SSL_ERROR;
			default:
				break;
			}
		}
	}

	gnutls_free(modulus.data);
	gnutls_free(exponent.data);

	gnutls_free(der_pub_key.data);

	return ret;
}

/** Starts SSL communication with lockdownd after the iPhone has been paired.
 *
 * @param client The lockdownd client
 * @param HostID The HostID used with this phone
 *
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_start_ssl_session(lockdownd_client_t client, const char *HostID)
{
	plist_t dict = NULL;
	uint32_t return_me = 0;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	client->session_id[0] = '\0';

	/* Setup DevicePublicKey request plist */
	dict = plist_new_dict();
	plist_dict_insert_item(dict,"HostID", plist_new_string(HostID));
	plist_dict_insert_item(dict,"Request", plist_new_string("StartSession"));

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	ret = lockdownd_recv(client, &dict);

	if (!dict)
		return LOCKDOWN_E_PLIST_ERROR;

	if (lockdown_check_result(dict, "StartSession") == RESULT_FAILURE) {
		plist_t error_node = plist_dict_get_item(dict, "Error");
		if (error_node && PLIST_STRING == plist_get_node_type(error_node)) {
			char *error = NULL;
			plist_get_string_val(error_node, &error);

			if (!strcmp(error, "InvalidHostID")) {
				/* hostid is unknown. Pair and try again */
				char *uuid = NULL;
				char *host_id = NULL;
				userpref_get_host_id(&host_id);

				if (LOCKDOWN_E_SUCCESS == lockdownd_get_device_uuid(client, &uuid) ) {
					if (LOCKDOWN_E_SUCCESS == lockdownd_pair(client, uuid, host_id) ) {
						/* start session again */
						plist_free(dict);
						dict = plist_new_dict();
						plist_dict_insert_item(dict,"HostID", plist_new_string(HostID));
						plist_dict_insert_item(dict,"Request", plist_new_string("StartSession"));

						ret = lockdownd_send(client, dict);
						plist_free(dict);
						dict = NULL;

						ret = lockdownd_recv(client, &dict);
					}
				}
				free(uuid);
				free(host_id);
			}
			free(error);
		}
	}

	ret = LOCKDOWN_E_SSL_ERROR;
	if (lockdown_check_result(dict, "StartSession") == RESULT_SUCCESS) {
		// Set up GnuTLS...
		//gnutls_anon_client_credentials_t anoncred;
		gnutls_certificate_credentials_t xcred;

		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: started the session OK, now trying GnuTLS\n", __func__);
		errno = 0;
		gnutls_global_init();
		//gnutls_anon_allocate_client_credentials(&anoncred);
		gnutls_certificate_allocate_credentials(&xcred);
		gnutls_certificate_set_x509_trust_file(xcred, "hostcert.pem", GNUTLS_X509_FMT_PEM);
		gnutls_init(client->ssl_session, GNUTLS_CLIENT);
		{
			int protocol_priority[16] = { GNUTLS_SSL3, 0 };
			int kx_priority[16] = { GNUTLS_KX_ANON_DH, GNUTLS_KX_RSA, 0 };
			int cipher_priority[16] = { GNUTLS_CIPHER_AES_128_CBC, GNUTLS_CIPHER_AES_256_CBC, 0 };
			int mac_priority[16] = { GNUTLS_MAC_SHA1, GNUTLS_MAC_MD5, 0 };
			int comp_priority[16] = { GNUTLS_COMP_NULL, 0 };

			gnutls_cipher_set_priority(*client->ssl_session, cipher_priority);
			gnutls_compression_set_priority(*client->ssl_session, comp_priority);
			gnutls_kx_set_priority(*client->ssl_session, kx_priority);
			gnutls_protocol_set_priority(*client->ssl_session, protocol_priority);
			gnutls_mac_set_priority(*client->ssl_session, mac_priority);
		}
		gnutls_credentials_set(*client->ssl_session, GNUTLS_CRD_CERTIFICATE, xcred);	// this part is killing me.

		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: GnuTLS step 1...\n", __func__);
		gnutls_transport_set_ptr(*client->ssl_session, (gnutls_transport_ptr_t) client);
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: GnuTLS step 2...\n", __func__);
		gnutls_transport_set_push_function(*client->ssl_session, (gnutls_push_func) & lockdownd_secuwrite);
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: GnuTLS step 3...\n", __func__);
		gnutls_transport_set_pull_function(*client->ssl_session, (gnutls_pull_func) & lockdownd_securead);
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: GnuTLS step 4 -- now handshaking...\n", __func__);
		if (errno)
			log_dbg_msg(DBGMASK_LOCKDOWND, "%s: WARN: errno says %s before handshake!\n", __func__, strerror(errno));
		return_me = gnutls_handshake(*client->ssl_session);
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: GnuTLS handshake done...\n", __func__);

		if (return_me != GNUTLS_E_SUCCESS) {
			log_dbg_msg(DBGMASK_LOCKDOWND, "%s: GnuTLS reported something wrong.\n", __func__);
			gnutls_perror(return_me);
			log_dbg_msg(DBGMASK_LOCKDOWND, "%s: oh.. errno says %s\n", __func__, strerror(errno));
			return LOCKDOWN_E_SSL_ERROR;
		} else {
			client->in_SSL = 1;
			ret = LOCKDOWN_E_SUCCESS;
		}
	}
	/* store session id */
	plist_t session_node = plist_dict_get_item(dict, "SessionID");
	if (session_node) {

		plist_type session_node_type = plist_get_node_type(session_node);

		if (session_node_type == PLIST_STRING) {

			char *session_id = NULL;
			plist_get_string_val(session_node, &session_id);

			if (session_node_type == PLIST_STRING && session_id) {
				/* we need to store the session ID for StopSession */
				strcpy(client->session_id, session_id);
				log_dbg_msg(DBGMASK_LOCKDOWND, "%s: SessionID: %s\n", __func__, client->session_id);
			}
			if (session_id)
				free(session_id);
		}
	} else
		log_dbg_msg(DBGMASK_LOCKDOWND, "%s: Failed to get SessionID!\n", __func__);
	plist_free(dict);
	dict = NULL;

	if (ret == LOCKDOWN_E_SUCCESS)
		return ret;

	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: Apparently failed negotiating with lockdownd.\n", __func__);
	return LOCKDOWN_E_SSL_ERROR;
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
	uint32_t bytes = 0;
	lockdownd_client_t client;
	client = (lockdownd_client_t) transport;
	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: called\n", __func__);
	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: pre-send length = %zi\n", __func__, length);
	iphone_device_send(client->connection, buffer, length, &bytes);
	log_dbg_msg(DBGMASK_LOCKDOWND, "%s: post-send sent %i bytes\n", __func__, bytes);
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
	size_t tbytes = 0;
	int this_len = length;
	iphone_error_t res;
	lockdownd_client_t client;
	client = (lockdownd_client_t) transport;
	char *recv_buffer;

	log_debug_msg("%s: pre-read client wants %zi bytes\n", __func__, length);

	recv_buffer = (char *) malloc(sizeof(char) * this_len);

	// repeat until we have the full data or an error occurs.
	do {
		if ((res = iphone_device_recv(client->connection, recv_buffer, this_len, (uint32_t*)&bytes)) != LOCKDOWN_E_SUCCESS) {
			log_debug_msg("%s: ERROR: usbmux_recv returned %d\n", __func__, res);
			return res;
		}
		log_debug_msg("%s: post-read we got %i bytes\n", __func__, bytes);

		// increase read count
		tbytes += bytes;

		// fill the buffer with what we got right now
		memcpy(buffer + pos_start_fill, recv_buffer, bytes);
		pos_start_fill += bytes;

		if (tbytes >= length) {
			break;
		}

		this_len = length - tbytes;
		log_debug_msg("%s: re-read trying to read missing %i bytes\n", __func__, this_len);
	} while (tbytes < length);

	if (recv_buffer) {
		free(recv_buffer);
	}

	return tbytes;
}

/** Command to start the desired service
 *
 * @param client The lockdownd client
 * @param service The name of the service to start
 * @param port The port number the service was started on
 
 * @return an error code (LOCKDOWN_E_SUCCESS on success)
 */
lockdownd_error_t lockdownd_start_service(lockdownd_client_t client, const char *service, int *port)
{
	if (!client || !service || !port)
		return LOCKDOWN_E_INVALID_ARG;

	char *host_id = NULL;
	userpref_get_host_id(&host_id);
	if (!host_id)
		return LOCKDOWN_E_INVALID_CONF;
	if (!client->in_SSL && !lockdownd_start_ssl_session(client, host_id))
		return LOCKDOWN_E_SSL_ERROR;

	plist_t dict = NULL;
	uint32_t port_loc = 0;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	free(host_id);
	host_id = NULL;

	dict = plist_new_dict();
	plist_dict_insert_item(dict,"Request", plist_new_string("StartService"));
	plist_dict_insert_item(dict,"Service", plist_new_string(service));

	/* send to iPhone */
	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (LOCKDOWN_E_SUCCESS != ret)
		return ret;

	ret = lockdownd_recv(client, &dict);

	if (LOCKDOWN_E_SUCCESS != ret)
		return ret;

	if (!dict)
		return LOCKDOWN_E_PLIST_ERROR;

	ret = LOCKDOWN_E_UNKNOWN_ERROR;
	if (lockdown_check_result(dict, "StartService") == RESULT_SUCCESS) {
		plist_t port_value_node = plist_dict_get_item(dict, "Port");

		if (port_value_node && (plist_get_node_type(port_value_node) == PLIST_UINT)) {
			uint64_t port_value = 0;
			plist_get_uint_val(port_value_node, &port_value);

			if (port_value) {
				port_loc = port_value;
				ret = LOCKDOWN_E_SUCCESS;
			}
			if (port && ret == LOCKDOWN_E_SUCCESS)
				*port = port_loc;
		}
	}
	else
		ret = LOCKDOWN_E_START_SERVICE_FAILED;

	plist_free(dict);
	dict = NULL;
	return ret;
}

