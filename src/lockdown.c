/*
 * lockdown.c
 * com.apple.mobile.lockdownd service implementation.
 *
 * Copyright (c) 2010 Bryan Forbes All Rights Reserved.
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

#include <string.h>
#include <stdlib.h>
#define _GNU_SOURCE 1
#define __USE_GNU 1
#include <stdio.h>
#include <ctype.h>
#ifdef HAVE_OPENSSL
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#else
#include <libtasn1.h>
#include <gnutls/x509.h>
#endif
#include <plist/plist.h>

#include "property_list_service.h"
#include "lockdown.h"
#include "idevice.h"
#include "debug.h"
#include "userpref.h"
#include "asprintf.h"

#define RESULT_SUCCESS 0
#define RESULT_FAILURE 1

#ifndef HAVE_OPENSSL
const ASN1_ARRAY_TYPE pkcs1_asn1_tab[] = {
	{"PKCS1", 536872976, 0},
	{0, 1073741836, 0},
	{"RSAPublicKey", 536870917, 0},
	{"modulus", 1073741827, 0},
	{"publicExponent", 3, 0},
	{0, 0, 0}
};
#endif

/**
 * Internally used function for checking the result from lockdown's answer
 * plist to a previously sent request.
 *
 * @param dict The plist to evaluate.
 * @param query_match Name of the request to match or NULL if no match is
 *        required.
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
		if (query_match && (strcmp(query_value, query_match) != 0)) {
			free(query_value);
			return ret;
		}
		free(query_value);
	}

	plist_t result_node = plist_dict_get_item(dict, "Result");
	if (!result_node) {
		/* iOS 5: the 'Result' key is not present anymore.
		   But we need to check for the 'Error' key. */
		plist_t err_node = plist_dict_get_item(dict, "Error");
		if (err_node) {
			if (plist_get_node_type(err_node) == PLIST_STRING) {
				char *err_value = NULL;
				plist_get_string_val(err_node, &err_value);
				if (err_value) {
					debug_info("ERROR: %s", err_value);
					free(err_value);
				} else {
					debug_info("ERROR: unknown error occured");
				}
			}
			return RESULT_FAILURE;
		}
		return RESULT_SUCCESS;
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
				debug_info("ERROR: unknown result value '%s'", result_value);
			}
		}
		if (result_value)
			free(result_value);
	}
	return ret;
}

/**
 * Adds a label key with the passed value to a plist dict node.
 *
 * @param plist The plist to add the key to
 * @param label The value for the label key
 *
 */
static void plist_dict_add_label(plist_t plist, const char *label)
{
	if (plist && label) {
		if (plist_get_node_type(plist) == PLIST_DICT)
			plist_dict_insert_item(plist, "Label", plist_new_string(label));
	}
}

/**
 * Closes the lockdownd session by sending the StopSession request.
 *
 * @see lockdownd_start_session
 *
 * @param client The lockdown client
 * @param session_id The id of a running session
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_stop_session(lockdownd_client_t client, const char *session_id)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	if (!session_id) {
		debug_info("no session_id given, cannot stop session");
		return LOCKDOWN_E_INVALID_ARG;
	}

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_insert_item(dict,"Request", plist_new_string("StopSession"));
	plist_dict_insert_item(dict,"SessionID", plist_new_string(session_id));

	debug_info("stopping session %s", session_id);

	ret = lockdownd_send(client, dict);

	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);

	if (!dict) {
		debug_info("LOCKDOWN_E_PLIST_ERROR");
		return LOCKDOWN_E_PLIST_ERROR;
	}

	ret = LOCKDOWN_E_UNKNOWN_ERROR;
	if (lockdown_check_result(dict, "StopSession") == RESULT_SUCCESS) {
		debug_info("success");
		ret = LOCKDOWN_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;
	if (client->ssl_enabled) {
		property_list_service_disable_ssl(client->parent);
	}
	return ret;
}

/**
 * Closes the lockdownd client session if one is running and frees up the
 * lockdownd_client struct.
 *
 * @param client The lockdown client
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_client_free(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	if (client->session_id) {
		lockdownd_stop_session(client, client->session_id);
		free(client->session_id);
	}

	if (client->parent) {
		lockdownd_goodbye(client);

		if (property_list_service_client_free(client->parent) == PROPERTY_LIST_SERVICE_E_SUCCESS) {
			ret = LOCKDOWN_E_SUCCESS;
		}
	}

	if (client->udid) {
		free(client->udid);
	}
	if (client->label) {
		free(client->label);
	}

	free(client);
	return ret;
}

/**
 * Sets the label to send for requests to lockdownd.
 *
 * @param client The lockdown client
 * @param label The label to set or NULL to disable sending a label
 *
 */
void lockdownd_client_set_label(lockdownd_client_t client, const char *label)
{
	if (client) {
		if (client->label)
			free(client->label);

		client->label = (label != NULL) ? strdup(label): NULL;
	}
}

/**
 * Receives a plist from lockdownd.
 *
 * @param client The lockdownd client
 * @param plist The plist to store the received data
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client or
 *  plist is NULL
 */
lockdownd_error_t lockdownd_receive(lockdownd_client_t client, plist_t *plist)
{
	if (!client || !plist || (plist && *plist))
		return LOCKDOWN_E_INVALID_ARG;
	lockdownd_error_t ret = LOCKDOWN_E_SUCCESS;
	property_list_service_error_t err;

	err = property_list_service_receive_plist(client->parent, plist);
	if (err != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		ret = LOCKDOWN_E_UNKNOWN_ERROR;
	}

	if (!*plist)
		ret = LOCKDOWN_E_PLIST_ERROR;

	return ret;
}

/**
 * Sends a plist to lockdownd.
 *
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The lockdownd client
 * @param plist The plist to send
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client or
 *  plist is NULL
 */
lockdownd_error_t lockdownd_send(lockdownd_client_t client, plist_t plist)
{
	if (!client || !plist)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_SUCCESS;
	idevice_error_t err;

	err = property_list_service_send_xml_plist(client->parent, plist);
	if (err != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		ret = LOCKDOWN_E_UNKNOWN_ERROR;
	}
	return ret;
}

/**
 * Query the type of the service daemon. Depending on whether the device is
 * queried in normal mode or restore mode, different types will be returned.
 *
 * @param client The lockdownd client
 * @param type The type returned by the service daemon. Pass NULL to ignore.
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_query_type(lockdownd_client_t client, char **type)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_insert_item(dict,"Request", plist_new_string("QueryType"));

	debug_info("called");
	ret = lockdownd_send(client, dict);

	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);

	if (LOCKDOWN_E_SUCCESS != ret)
		return ret;

	ret = LOCKDOWN_E_UNKNOWN_ERROR;
	if (lockdown_check_result(dict, "QueryType") == RESULT_SUCCESS) {
		/* return the type if requested */
		if (type != NULL) {
			plist_t type_node = plist_dict_get_item(dict, "Type");
			plist_get_string_val(type_node, type);
		}
		debug_info("success with type %s", *type);
		ret = LOCKDOWN_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;

	return ret;
}

/**
 * Retrieves a preferences plist using an optional domain and/or key name.
 *
 * @param client An initialized lockdownd client.
 * @param domain The domain to query on or NULL for global domain
 * @param key The key name to request or NULL to query for all keys
 * @param value A plist node representing the result value node
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_get_value(lockdownd_client_t client, const char *domain, const char *key, plist_t *value)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	plist_t dict = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* setup request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
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
	ret = lockdownd_receive(client, &dict);
	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	if (lockdown_check_result(dict, "GetValue") == RESULT_SUCCESS) {
		debug_info("success");
		ret = LOCKDOWN_E_SUCCESS;
	}
	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_t value_node = plist_dict_get_item(dict, "Value");

	if (value_node) {
		debug_info("has a value");
		*value = plist_copy(value_node);
	}

	plist_free(dict);
	return ret;
}

/**
 * Sets a preferences value using a plist and optional by domain and/or key name.
 *
 * @param client an initialized lockdownd client.
 * @param domain the domain to query on or NULL for global domain
 * @param key the key name to set the value or NULL to set a value dict plist
 * @param value a plist node of any node type representing the value to set
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client or 
 *  value is NULL
 */
lockdownd_error_t lockdownd_set_value(lockdownd_client_t client, const char *domain, const char *key, plist_t value)
{
	if (!client || !value)
		return LOCKDOWN_E_INVALID_ARG;

	plist_t dict = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* setup request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
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
	ret = lockdownd_receive(client, &dict);
	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	if (lockdown_check_result(dict, "SetValue") == RESULT_SUCCESS) {
		debug_info("success");
		ret = LOCKDOWN_E_SUCCESS;
	}

	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_free(dict);
	return ret;
}

/**
 * Removes a preference node by domain and/or key name.
 *
 * @note: Use with caution as this could remove vital information on the device
 *
 * @param client An initialized lockdownd client.
 * @param domain The domain to query on or NULL for global domain
 * @param key The key name to remove or NULL remove all keys for the current domain
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_remove_value(lockdownd_client_t client, const char *domain, const char *key)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	plist_t dict = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* setup request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
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
	ret = lockdownd_receive(client, &dict);
	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	if (lockdown_check_result(dict, "RemoveValue") == RESULT_SUCCESS) {
		debug_info("success");
		ret = LOCKDOWN_E_SUCCESS;
	}

	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_free(dict);
	return ret;
}

/**
 * Returns the unique id of the device from lockdownd.
 *
 * @param client An initialized lockdownd client.
 * @param udid Holds the unique id of the device. The caller is responsible
 *  for freeing the memory.
 *
 * @return LOCKDOWN_E_SUCCESS on success
 */
lockdownd_error_t lockdownd_get_device_udid(lockdownd_client_t client, char **udid)
{
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	plist_t value = NULL;

	ret = lockdownd_get_value(client, NULL, "UniqueDeviceID", &value);
	if (ret != LOCKDOWN_E_SUCCESS) {
		return ret;
	}
	plist_get_string_val(value, udid);

	plist_free(value);
	value = NULL;
	return ret;
}

/**
 * Retrieves the public key of the device from lockdownd.
 *
 * @param client An initialized lockdownd client.
 * @param public_key Holds the public key of the device. The caller is
 *  responsible for freeing the memory.
 *
 * @return LOCKDOWN_E_SUCCESS on success
 */
lockdownd_error_t lockdownd_get_device_public_key(lockdownd_client_t client, key_data_t * public_key)
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

/**
 * Retrieves the name of the device from lockdownd set by the user.
 *
 * @param client An initialized lockdownd client.
 * @param device_name Holds the name of the device. The caller is
 *  responsible for freeing the memory.
 *
 * @return LOCKDOWN_E_SUCCESS on success
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

/**
 * Creates a new lockdownd client for the device.
 *
 * @note This function does not pair with the device or start a session. This
 *  has to be done manually by the caller after the client is created.
 *  The device disconnects automatically if the lockdown connection idles
 *  for more than 10 seconds. Make sure to call lockdownd_client_free() as soon
 *  as the connection is no longer needed.
 *
 * @param device The device to create a lockdownd client for
 * @param client The pointer to the location of the new lockdownd_client
 * @param label The label to use for communication. Usually the program name.
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_client_new(idevice_t device, lockdownd_client_t *client, const char *label)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	static struct lockdownd_service_descriptor service = {
		.port = 0xf27e,
		.ssl_enabled = 0
	};

	property_list_service_client_t plistclient = NULL;
	if (property_list_service_client_new(device, (lockdownd_service_descriptor_t)&service, &plistclient) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		debug_info("could not connect to lockdownd (device %s)", device->udid);
		return LOCKDOWN_E_MUX_ERROR;
	}

	lockdownd_client_t client_loc = (lockdownd_client_t) malloc(sizeof(struct lockdownd_client_private));
	client_loc->parent = plistclient;
	client_loc->ssl_enabled = 0;
	client_loc->session_id = NULL;

	if (idevice_get_udid(device, &client_loc->udid) != IDEVICE_E_SUCCESS) {
		debug_info("failed to get device udid.");
	}
	debug_info("device udid: %s", client_loc->udid);

	client_loc->label = label ? strdup(label) : NULL;

	*client = client_loc;

	return LOCKDOWN_E_SUCCESS;
}

/**
 * Creates a new lockdownd client for the device and starts initial handshake.
 * The handshake consists out of query_type, validate_pair, pair and
 * start_session calls. It uses the internal pairing record management.
 *
 * @note The device disconnects automatically if the lockdown connection idles
 *  for more than 10 seconds. Make sure to call lockdownd_client_free() as soon
 *  as the connection is no longer needed.
 *
 * @param device The device to create a lockdownd client for
 * @param client The pointer to the location of the new lockdownd_client
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_INVALID_CONF if configuration data is wrong
 */
lockdownd_error_t lockdownd_client_new_with_handshake(idevice_t device, lockdownd_client_t *client, const char *label)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_SUCCESS;
	lockdownd_client_t client_loc = NULL;
	char *host_id = NULL;
	char *type = NULL;

	ret = lockdownd_client_new(device, &client_loc, label);
	if (LOCKDOWN_E_SUCCESS != ret) {
		debug_info("failed to create lockdownd client.");
		return ret;
	}

	/* perform handshake */
	if (LOCKDOWN_E_SUCCESS != lockdownd_query_type(client_loc, &type)) {
		debug_info("QueryType failed in the lockdownd client.");
		ret = LOCKDOWN_E_NOT_ENOUGH_DATA;
	} else {
		if (strcmp("com.apple.mobile.lockdown", type)) {
			debug_info("Warning QueryType request returned \"%s\".", type);
		}
		if (type)
			free(type);
	}

	userpref_get_host_id(&host_id);
	if (LOCKDOWN_E_SUCCESS == ret && !host_id) {
		ret = LOCKDOWN_E_INVALID_CONF;
	}

	if (LOCKDOWN_E_SUCCESS == ret && !userpref_has_device_public_key(client_loc->udid))
		ret = lockdownd_pair(client_loc, NULL);

	/* in any case, we need to validate pairing to receive trusted host status */
	ret = lockdownd_validate_pair(client_loc, NULL);

	/* if not paired yet, let's do it now */
	if (LOCKDOWN_E_INVALID_HOST_ID == ret) {
		ret = lockdownd_pair(client_loc, NULL);
		if (LOCKDOWN_E_SUCCESS == ret) {
			ret = lockdownd_validate_pair(client_loc, NULL);
		}
	}

	if (LOCKDOWN_E_SUCCESS == ret) {
		ret = lockdownd_start_session(client_loc, host_id, NULL, NULL);
		if (LOCKDOWN_E_SUCCESS != ret) {
			debug_info("Session opening failed.");
		}

		if (host_id) {
			free(host_id);
			host_id = NULL;
		}
	}
	
	if (LOCKDOWN_E_SUCCESS == ret) {
		*client = client_loc;
	} else {
		lockdownd_client_free(client_loc);
	}

	return ret;
}

/**
 * Returns a new plist from the supplied lockdownd pair record. The caller is
 * responsible for freeing the plist.
 *
 * @param pair_record The pair record to create a plist from.
 *
 * @return A pair record plist from the device, NULL if pair_record is not set
 */
static plist_t lockdownd_pair_record_to_plist(lockdownd_pair_record_t pair_record)
{
	if (!pair_record)
		return NULL;

	char *host_id_loc = pair_record->host_id;

	/* setup request plist */
	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "DeviceCertificate", plist_new_data(pair_record->device_certificate, strlen(pair_record->device_certificate)));
	plist_dict_insert_item(dict, "HostCertificate", plist_new_data(pair_record->host_certificate, strlen(pair_record->host_certificate)));
	if (!pair_record->host_id)
		userpref_get_host_id(&host_id_loc);
	plist_dict_insert_item(dict, "HostID", plist_new_string(host_id_loc));
	plist_dict_insert_item(dict, "RootCertificate", plist_new_data(pair_record->root_certificate, strlen(pair_record->root_certificate)));

	if (!pair_record->host_id)
		free(host_id_loc);

	return dict;
}

/**
 * Generates a new pairing record plist and required certificates for the 
 * supplied public key of the device and the host_id of the caller's host
 * computer.
 *
 * @param public_key The public key of the device.
 * @param host_id The HostID to use for the pair record plist.
 * @param pair_record_plist Holds the generated pair record.
 *
 * @return LOCKDOWN_E_SUCCESS on success
 */
static lockdownd_error_t generate_pair_record_plist(key_data_t public_key, char *host_id, plist_t *pair_record_plist)
{
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	key_data_t device_cert = { NULL, 0 };
	key_data_t host_cert = { NULL, 0 };
	key_data_t root_cert = { NULL, 0 };

	ret = lockdownd_gen_pair_cert(public_key, &device_cert, &host_cert, &root_cert);
	if (ret != LOCKDOWN_E_SUCCESS) {
		return ret;
	}

	char *host_id_loc = host_id;

	if (!host_id)
		userpref_get_host_id(&host_id_loc);

	/* setup request plist */
	*pair_record_plist = plist_new_dict();
	plist_dict_insert_item(*pair_record_plist, "DeviceCertificate", plist_new_data((const char*)device_cert.data, device_cert.size));
	plist_dict_insert_item(*pair_record_plist, "HostCertificate", plist_new_data((const char*)host_cert.data, host_cert.size));
	plist_dict_insert_item(*pair_record_plist, "HostID", plist_new_string(host_id_loc));
	plist_dict_insert_item(*pair_record_plist, "RootCertificate", plist_new_data((const char*)root_cert.data, root_cert.size));

	if (!host_id)
		free(host_id_loc);

	if (device_cert.data)
		free(device_cert.data);
	if (host_cert.data)
		free(host_cert.data);
	if (root_cert.data)
		free(root_cert.data);

	return ret;
}

/**
 * Function used internally by lockdownd_pair() and lockdownd_validate_pair()
 *
 * @param client The lockdown client to pair with.
 * @param pair_record The pair record to use for pairing. If NULL is passed, then
 *    the pair records from the current machine are used. New records will be
 *    generated automatically when pairing is done for the first time.
 * @param verb This is either "Pair", "ValidatePair" or "Unpair".
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_PLIST_ERROR if the pair_record certificates are wrong,
 *  LOCKDOWN_E_PAIRING_FAILED if the pairing failed,
 *  LOCKDOWN_E_PASSWORD_PROTECTED if the device is password protected,
 *  LOCKDOWN_E_INVALID_HOST_ID if the device does not know the caller's host id
 */
static lockdownd_error_t lockdownd_do_pair(lockdownd_client_t client, lockdownd_pair_record_t pair_record, const char *verb)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	plist_t dict = NULL;
	plist_t dict_record = NULL;
	key_data_t public_key = { NULL, 0 };
	int pairing_mode = 0; /* 0 = libimobiledevice, 1 = external */

	if (pair_record && pair_record->host_id) {
		/* valid pair_record passed? */
		if (!pair_record->device_certificate || !pair_record->host_certificate || !pair_record->root_certificate) {
			return LOCKDOWN_E_PLIST_ERROR;
		}

		/* use passed pair_record */
		dict_record = lockdownd_pair_record_to_plist(pair_record);

		pairing_mode = 1;
	} else {
		ret = lockdownd_get_device_public_key(client, &public_key);
		if (ret != LOCKDOWN_E_SUCCESS) {
			if (public_key.data)
				free(public_key.data);
			debug_info("device refused to send public key.");
			return ret;
		}
		debug_info("device public key follows:\n%.*s", public_key.size, public_key.data);
		/* get libimobiledevice pair_record */
		ret = generate_pair_record_plist(public_key, NULL, &dict_record);
		if (ret != LOCKDOWN_E_SUCCESS) {
			if (dict_record)
				plist_free(dict_record);
			return ret;
		}
	}

	/* Setup Pair request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_insert_item(dict,"PairRecord", dict_record);
	plist_dict_insert_item(dict, "Request", plist_new_string(verb));

	/* send to device */
	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	/* Now get device's answer */
	ret = lockdownd_receive(client, &dict);

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	if (strcmp(verb, "Unpair") == 0) {
		/* workaround for Unpair giving back ValidatePair,
		 * seems to be a bug in the device's fw */
		if (lockdown_check_result(dict, NULL) != RESULT_SUCCESS) {
			ret = LOCKDOWN_E_PAIRING_FAILED;
		}
	} else {
		if (lockdown_check_result(dict, verb) != RESULT_SUCCESS) {
			ret = LOCKDOWN_E_PAIRING_FAILED;
		}
	}

	/* if pairing succeeded */
	if (ret == LOCKDOWN_E_SUCCESS) {
		debug_info("%s success", verb);
		if (!pairing_mode) {
			if (!strcmp("Unpair", verb)) {
				/* remove public key from config */
				userpref_remove_device_public_key(client->udid);
			} else {
				/* store public key in config */
				userpref_set_device_public_key(client->udid, public_key);
			}
		}
	} else {
		debug_info("%s failure", verb);
		plist_t error_node = NULL;
		/* verify error condition */
		error_node = plist_dict_get_item(dict, "Error");
		if (error_node) {
			char *value = NULL;
			plist_get_string_val(error_node, &value);
			if (value) {
				/* the first pairing fails if the device is password protected */
				if (!strcmp(value, "PasswordProtected")) {
					ret = LOCKDOWN_E_PASSWORD_PROTECTED;
				} else if (!strcmp(value, "InvalidHostID")) {
					ret = LOCKDOWN_E_INVALID_HOST_ID;
				}
				free(value);
			}

			plist_free(error_node);
			error_node = NULL;
		}
	}
	plist_free(dict);
	dict = NULL;
	if (public_key.data)
		free(public_key.data);
	return ret;
}

/** 
 * Pairs the device using the supplied pair record.
 *
 * @param client The lockdown client to pair with.
 * @param pair_record The pair record to use for pairing. If NULL is passed, then
 *    the pair records from the current machine are used. New records will be
 *    generated automatically when pairing is done for the first time.
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_PLIST_ERROR if the pair_record certificates are wrong,
 *  LOCKDOWN_E_PAIRING_FAILED if the pairing failed,
 *  LOCKDOWN_E_PASSWORD_PROTECTED if the device is password protected,
 *  LOCKDOWN_E_INVALID_HOST_ID if the device does not know the caller's host id
 */
lockdownd_error_t lockdownd_pair(lockdownd_client_t client, lockdownd_pair_record_t pair_record)
{
	return lockdownd_do_pair(client, pair_record, "Pair");
}

/** 
 * Validates if the device is paired with the given HostID. If succeeded them
 * specified host will become trusted host of the device indicated by the 
 * lockdownd preference named TrustedHostAttached. Otherwise the host must because
 * paired using lockdownd_pair() first.
 *
 * @param client The lockdown client to pair with.
 * @param pair_record The pair record to validate pairing with. If NULL is
 *    passed, then the pair record is read from the internal pairing record
 *    management.
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_PLIST_ERROR if the pair_record certificates are wrong,
 *  LOCKDOWN_E_PAIRING_FAILED if the pairing failed,
 *  LOCKDOWN_E_PASSWORD_PROTECTED if the device is password protected,
 *  LOCKDOWN_E_INVALID_HOST_ID if the device does not know the caller's host id
 */
lockdownd_error_t lockdownd_validate_pair(lockdownd_client_t client, lockdownd_pair_record_t pair_record)
{
	return lockdownd_do_pair(client, pair_record, "ValidatePair");
}

/** 
 * Unpairs the device with the given HostID and removes the pairing records
 * from the device and host if the internal pairing record management is used.
 *
 * @param client The lockdown client to pair with.
 * @param pair_record The pair record to use for unpair. If NULL is passed, then
 *    the pair records from the current machine are used.
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_PLIST_ERROR if the pair_record certificates are wrong,
 *  LOCKDOWN_E_PAIRING_FAILED if the pairing failed,
 *  LOCKDOWN_E_PASSWORD_PROTECTED if the device is password protected,
 *  LOCKDOWN_E_INVALID_HOST_ID if the device does not know the caller's host id
 */
lockdownd_error_t lockdownd_unpair(lockdownd_client_t client, lockdownd_pair_record_t pair_record)
{
	return lockdownd_do_pair(client, pair_record, "Unpair");
}

/**
 * Tells the device to immediately enter recovery mode.
 *
 * @param client The lockdown client
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_enter_recovery(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_insert_item(dict,"Request", plist_new_string("EnterRecovery"));

	debug_info("telling device to enter recovery mode");

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);

	if (lockdown_check_result(dict, "EnterRecovery") == RESULT_SUCCESS) {
		debug_info("success");
		ret = LOCKDOWN_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;
	return ret;
}

/**
 * Sends the Goodbye request to lockdownd signaling the end of communication.
 *
 * @param client The lockdown client
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client
 *  is NULL, LOCKDOWN_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
lockdownd_error_t lockdownd_goodbye(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_insert_item(dict,"Request", plist_new_string("Goodbye"));

	debug_info("called");

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);
	if (!dict) {
		debug_info("did not get goodbye response back");
		return LOCKDOWN_E_PLIST_ERROR;
	}

	if (lockdown_check_result(dict, "Goodbye") == RESULT_SUCCESS) {
		debug_info("success");
		ret = LOCKDOWN_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;
	return ret;
}

/**
 * Generates the device certificate from the public key as well as the host
 * and root certificates.
 *
 * @param public_key The public key of the device to use for generation.
 * @param odevice_cert Holds the generated device certificate.
 * @param ohost_cert Holds the generated host certificate.
 * @param oroot_cert Holds the generated root certificate.
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when a
 *  parameter is NULL, LOCKDOWN_E_INVALID_CONF if the internal configuration
 *  system failed, LOCKDOWN_E_SSL_ERROR if the certificates could not be
 *  generated
 */
lockdownd_error_t lockdownd_gen_pair_cert(key_data_t public_key, key_data_t * odevice_cert,
									   key_data_t * ohost_cert, key_data_t * oroot_cert)
{
	if (!public_key.data || !odevice_cert || !ohost_cert || !oroot_cert)
		return LOCKDOWN_E_INVALID_ARG;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	userpref_error_t uret = USERPREF_E_UNKNOWN_ERROR;

#ifdef HAVE_OPENSSL
	BIO *membio = BIO_new_mem_buf(public_key.data, public_key.size);
	RSA *pubkey = NULL;
	if (!PEM_read_bio_RSAPublicKey(membio, &pubkey, NULL, NULL)) {
		debug_info("Could not read public key");
	}
	BIO_free(membio);

	/* now generate certificates */
	key_data_t root_privkey, host_privkey;
	key_data_t root_cert, host_cert;
	X509* dev_cert;

	root_cert.data = NULL;
	root_cert.size = 0;
	host_cert.data = NULL;
	host_cert.size = 0;

	dev_cert = X509_new();

	root_privkey.data = NULL;
	root_privkey.size = 0;
	host_privkey.data = NULL;
	host_privkey.size = 0;

	uret = userpref_get_keys_and_certs(&root_privkey, &root_cert, &host_privkey, &host_cert);
	if (USERPREF_E_SUCCESS == uret) {
		/* generate device certificate */
		ASN1_INTEGER* sn = ASN1_INTEGER_new();
		ASN1_INTEGER_set(sn, 0);
		X509_set_serialNumber(dev_cert, sn);
		ASN1_INTEGER_free(sn);
		X509_set_version(dev_cert, 2);

		X509_EXTENSION* ext;
		if (!(ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, (char*)"critical,CA:FALSE"))) {
			debug_info("ERROR: X509V3_EXT_conf_nid failed");
		}
		X509_add_ext(dev_cert, ext, -1);

		ASN1_TIME* asn1time = ASN1_TIME_new();
		ASN1_TIME_set(asn1time, time(NULL));
		X509_set_notBefore(dev_cert, asn1time);
		ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * 365 * 10));
		X509_set_notAfter(dev_cert, asn1time);
		ASN1_TIME_free(asn1time);
	
		BIO* membp;

		X509* rootCert = NULL;
		membp = BIO_new_mem_buf(root_cert.data, root_cert.size);
		PEM_read_bio_X509(membp, &rootCert, NULL, NULL);
		BIO_free(membp);
		if (!rootCert) {
			debug_info("Could not read RootCertificate");
		} else {
			debug_info("RootCertificate loaded");
			EVP_PKEY* pkey = EVP_PKEY_new();
			EVP_PKEY_assign_RSA(pkey, pubkey);
			X509_set_pubkey(dev_cert, pkey);
			EVP_PKEY_free(pkey);
			X509_free(rootCert);
		}

		EVP_PKEY* rootPriv = NULL;
		membp = BIO_new_mem_buf(root_privkey.data, root_privkey.size);
		PEM_read_bio_PrivateKey(membp, &rootPriv, NULL, NULL);
		BIO_free(membp);
		if (!rootPriv) {
			debug_info("Could not read RootPrivateKey");
		} else {
			debug_info("RootPrivateKey loaded");
			if (X509_sign(dev_cert, rootPriv, EVP_sha1())) {
				ret = LOCKDOWN_E_SUCCESS;
			} else {
				debug_info("signing failed");
			}
			EVP_PKEY_free(rootPriv);
		}

		if (LOCKDOWN_E_SUCCESS == ret) {
			/* if everything went well, export in PEM format */
			key_data_t pem_root_cert = { NULL, 0 };
			key_data_t pem_host_cert = { NULL, 0 };

			uret = userpref_get_certs_as_pem(&pem_root_cert, &pem_host_cert);
			if (USERPREF_E_SUCCESS == uret) {
				/* copy buffer for output */
				membp = BIO_new(BIO_s_mem());
				if (membp && PEM_write_bio_X509(membp, dev_cert) > 0) {
					odevice_cert->size = BIO_get_mem_data(membp, &odevice_cert->data);
				}
				if (membp)
					free(membp);

				ohost_cert->data = malloc(pem_host_cert.size);
				memcpy(ohost_cert->data, pem_host_cert.data, pem_host_cert.size);
				ohost_cert->size = pem_host_cert.size;

				oroot_cert->data = malloc(pem_root_cert.size);
				memcpy(oroot_cert->data, pem_root_cert.data, pem_root_cert.size);
				oroot_cert->size = pem_root_cert.size;

				free(pem_root_cert.data);
				free(pem_host_cert.data);
			}
		}
	}
	X509V3_EXT_cleanup();
	X509_free(dev_cert);

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

	if (root_cert.data)
		free(root_cert.data);
	if (host_cert.data)
		free(host_cert.data);
	if (root_privkey.data)
		free(root_privkey.data);
	if (host_privkey.data)
		free(host_privkey.data);
#else
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

	/* now generate certificates */
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

						gnutls_free(pem_root_cert.data);
						gnutls_free(pem_host_cert.data);

						if (dev_pem.data)
							gnutls_free(dev_pem.data);
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

		if (essentially_null.data)
			free(essentially_null.data);
		gnutls_x509_crt_deinit(dev_cert);
		gnutls_x509_crt_deinit(root_cert);
		gnutls_x509_crt_deinit(host_cert);
		gnutls_x509_privkey_deinit(fake_privkey);
		gnutls_x509_privkey_deinit(root_privkey);
		gnutls_x509_privkey_deinit(host_privkey);

	}

	gnutls_free(modulus.data);
	gnutls_free(exponent.data);

	gnutls_free(der_pub_key.data);
#endif

	return ret;
}

/**
 * Opens a session with lockdownd and switches to SSL mode if device wants it.
 *
 * @param client The lockdownd client
 * @param host_id The HostID of the computer
 * @param session_id The new session_id of the created session
 * @param ssl_enabled Whether SSL communication is used in the session
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when a client
 *  or host_id is NULL, LOCKDOWN_E_PLIST_ERROR if the response plist had errors,
 *  LOCKDOWN_E_INVALID_HOST_ID if the device does not know the supplied HostID,
 *  LOCKDOWN_E_SSL_ERROR if enabling SSL communication failed
 */
lockdownd_error_t lockdownd_start_session(lockdownd_client_t client, const char *host_id, char **session_id, int *ssl_enabled)
{
	lockdownd_error_t ret = LOCKDOWN_E_SUCCESS;
	plist_t dict = NULL;

	if (!client || !host_id)
		ret = LOCKDOWN_E_INVALID_ARG;

	/* if we have a running session, stop current one first */
	if (client->session_id) {
		lockdownd_stop_session(client, client->session_id);
		free(client->session_id);
	}

	/* setup request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_insert_item(dict,"HostID", plist_new_string(host_id));
	plist_dict_insert_item(dict,"Request", plist_new_string("StartSession"));

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	ret = lockdownd_receive(client, &dict);

	if (!dict)
		return LOCKDOWN_E_PLIST_ERROR;

	if (lockdown_check_result(dict, "StartSession") == RESULT_FAILURE) {
		plist_t error_node = plist_dict_get_item(dict, "Error");
		if (error_node && PLIST_STRING == plist_get_node_type(error_node)) {
			char *error = NULL;
			plist_get_string_val(error_node, &error);
			if (!strcmp(error, "InvalidHostID")) {
				ret = LOCKDOWN_E_INVALID_HOST_ID;
			}
			free(error);
		}
	} else {
		uint8_t use_ssl = 0;

		plist_t enable_ssl = plist_dict_get_item(dict, "EnableSessionSSL");
		if (enable_ssl && (plist_get_node_type(enable_ssl) == PLIST_BOOLEAN)) {
			plist_get_bool_val(enable_ssl, &use_ssl);
		}
		debug_info("Session startup OK");

		if (ssl_enabled != NULL)
			*ssl_enabled = use_ssl;

		/* store session id, we need it for StopSession */
		plist_t session_node = plist_dict_get_item(dict, "SessionID");
		if (session_node && (plist_get_node_type(session_node) == PLIST_STRING)) {
			plist_get_string_val(session_node, &client->session_id);
		}
		if (client->session_id) {
			debug_info("SessionID: %s", client->session_id);
			if (session_id != NULL)
				*session_id = strdup(client->session_id);
		} else {
			debug_info("Failed to get SessionID!");
		}
		debug_info("Enable SSL Session: %s", (use_ssl?"true":"false"));
		if (use_ssl) {
			ret = property_list_service_enable_ssl(client->parent);
			if (ret == PROPERTY_LIST_SERVICE_E_SUCCESS) {
				client->ssl_enabled = 1;
			} else {
				ret = LOCKDOWN_E_SSL_ERROR;
				client->ssl_enabled = 0;
			}
		} else {
			client->ssl_enabled = 0;
			ret = LOCKDOWN_E_SUCCESS;
		}
	}

	plist_free(dict);
	dict = NULL;

	return ret;
}

/**
 * Requests to start a service and retrieve it's port on success.
 *
 * @param client The lockdownd client
 * @param identifier The identifier of the service to start
 * @param descriptor The service descriptor on success or NULL on failure
 
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG if a parameter
 *  is NULL, LOCKDOWN_E_INVALID_SERVICE if the requested service is not known
 *  by the device, LOCKDOWN_E_START_SERVICE_FAILED if the service could not because
 *  started by the device
 */
lockdownd_error_t lockdownd_start_service(lockdownd_client_t client, const char *identifier, lockdownd_service_descriptor_t *service)
{
	if (!client || !identifier || !service)
		return LOCKDOWN_E_INVALID_ARG;

	if (*service) {
		// reset fields if service descriptor is reused
		(*service)->port = 0;
		(*service)->ssl_enabled = 0;
	}

	char *host_id = NULL;
	userpref_get_host_id(&host_id);
	if (!host_id)
		return LOCKDOWN_E_INVALID_CONF;
	if (!client->session_id)
		return LOCKDOWN_E_NO_RUNNING_SESSION;

	plist_t dict = NULL;
	uint16_t port_loc = 0;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	free(host_id);
	host_id = NULL;

	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_insert_item(dict,"Request", plist_new_string("StartService"));
	plist_dict_insert_item(dict,"Service", plist_new_string(identifier));

	/* send to device */
	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (LOCKDOWN_E_SUCCESS != ret)
		return ret;

	ret = lockdownd_receive(client, &dict);

	if (LOCKDOWN_E_SUCCESS != ret)
		return ret;

	if (!dict)
		return LOCKDOWN_E_PLIST_ERROR;

	ret = LOCKDOWN_E_UNKNOWN_ERROR;
	if (lockdown_check_result(dict, "StartService") == RESULT_SUCCESS) {
		if (*service == NULL)
			*service = (lockdownd_service_descriptor_t)malloc(sizeof(struct lockdownd_service_descriptor));
		(*service)->port = 0;
		(*service)->ssl_enabled = 0;

		/* read service port number */
		plist_t node = plist_dict_get_item(dict, "Port");
		if (node && (plist_get_node_type(node) == PLIST_UINT)) {
			uint64_t port_value = 0;
			plist_get_uint_val(node, &port_value);

			if (port_value) {
				port_loc = port_value;
				ret = LOCKDOWN_E_SUCCESS;
			}
			if (port_loc && ret == LOCKDOWN_E_SUCCESS) {
				(*service)->port = port_loc;
			}
		}

		/* check if the service requires SSL */
		node = plist_dict_get_item(dict, "EnableServiceSSL");
		if (node && (plist_get_node_type(node) == PLIST_BOOLEAN)) {
			uint8_t b = 0;
			plist_get_bool_val(node, &b);
			(*service)->ssl_enabled = b;
		}
	} else {
		ret = LOCKDOWN_E_START_SERVICE_FAILED;
		plist_t error_node = plist_dict_get_item(dict, "Error");
		if (error_node && PLIST_STRING == plist_get_node_type(error_node)) {
			char *error = NULL;
			plist_get_string_val(error_node, &error);
			if (!strcmp(error, "InvalidService")) {
				ret = LOCKDOWN_E_INVALID_SERVICE;
			}
			free(error);
		}
	}

	plist_free(dict);
	dict = NULL;
	return ret;
}

/**
 * Activates the device. Only works within an open session.
 * The ActivationRecord plist dictionary must be obtained using the
 * activation protocol requesting from Apple's https webservice.
 *
 * @see http://iphone-docs.org/doku.php?id=docs:protocols:activation
 *
 * @param client The lockdown client
 * @param activation_record The activation record plist dictionary
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client or
 *  activation_record is NULL, LOCKDOWN_E_NO_RUNNING_SESSION if no session is
 *  open, LOCKDOWN_E_PLIST_ERROR if the received plist is broken, 
 *  LOCKDOWN_E_ACTIVATION_FAILED if the activation failed, 
 *  LOCKDOWN_E_INVALID_ACTIVATION_RECORD if the device reports that the
 *  activation_record is invalid
 */
lockdownd_error_t lockdownd_activate(lockdownd_client_t client, plist_t activation_record) 
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	if (!client->session_id)
		return LOCKDOWN_E_NO_RUNNING_SESSION;

	if (!activation_record)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_insert_item(dict,"Request", plist_new_string("Activate"));
	plist_dict_insert_item(dict,"ActivationRecord", plist_copy(activation_record));

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);
	if (!dict) {
		debug_info("LOCKDOWN_E_PLIST_ERROR");
		return LOCKDOWN_E_PLIST_ERROR;
	}

	ret = LOCKDOWN_E_ACTIVATION_FAILED;
	if (lockdown_check_result(dict, "Activate") == RESULT_SUCCESS) {
		debug_info("success");
		ret = LOCKDOWN_E_SUCCESS;
		
	} else {
		plist_t error_node = plist_dict_get_item(dict, "Error");
		if (error_node && PLIST_STRING == plist_get_node_type(error_node)) {
			char *error = NULL;
			plist_get_string_val(error_node, &error);
			if (!strcmp(error, "InvalidActivationRecord")) {
				ret = LOCKDOWN_E_INVALID_ACTIVATION_RECORD;
			}
			free(error);
		}
	}
	
	plist_free(dict);
	dict = NULL;

	return ret;
}

/**
 * Deactivates the device, returning it to the locked “Activate with iTunes”
 * screen.
 *
 * @param client The lockdown client
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_NO_RUNNING_SESSION if no session is open, 
 *  LOCKDOWN_E_PLIST_ERROR if the received plist is broken
 */
lockdownd_error_t lockdownd_deactivate(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	if (!client->session_id)
		return LOCKDOWN_E_NO_RUNNING_SESSION;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_insert_item(dict,"Request", plist_new_string("Deactivate"));

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);
	if (!dict) {
		debug_info("LOCKDOWN_E_PLIST_ERROR");
		return LOCKDOWN_E_PLIST_ERROR;
	}

	ret = LOCKDOWN_E_UNKNOWN_ERROR;
	if (lockdown_check_result(dict, "Deactivate") == RESULT_SUCCESS) {
		debug_info("success");
		ret = LOCKDOWN_E_SUCCESS;
	}
	plist_free(dict);
	dict = NULL;

	return ret;
}

static void str_remove_spaces(char *source)
{
	char *dest = source;
	while (*source != 0) {
		if (!isspace(*source)) {
			*dest++ = *source; /* copy */
		}
		source++;
	}
	*dest = 0;
}

/**
 * Calculates and returns the data classes the device supports from lockdownd.
 *
 * @param client An initialized lockdownd client.
 * @param classes A pointer to store an array of class names. The caller is responsible
 *  for freeing the memory which can be done using mobilesync_data_classes_free().
 * @param count The number of items in the classes array.
 *
 * @return LOCKDOWN_E_SUCCESS on success,
 *  LOCKDOWN_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_NO_RUNNING_SESSION if no session is open, 
 *  LOCKDOWN_E_PLIST_ERROR if the received plist is broken
 */
lockdownd_error_t lockdownd_get_sync_data_classes(lockdownd_client_t client, char ***classes, int *count)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	if (!client->session_id)
		return LOCKDOWN_E_NO_RUNNING_SESSION;

	plist_t dict = NULL;
	lockdownd_error_t err = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t value = NULL;

	char **newlist = NULL;
	char *val = NULL;

	*classes = NULL;
	*count = 0;

	err = lockdownd_get_value(client, "com.apple.mobile.iTunes", "SyncDataClasses", &dict);
	if (err != LOCKDOWN_E_SUCCESS) {
		if (dict) {
			plist_free(dict);
		}
		return err;
	}

	if (plist_get_node_type(dict) != PLIST_ARRAY) {
		plist_free(dict);
		return LOCKDOWN_E_PLIST_ERROR;
	}

	while((value = plist_array_get_item(dict, *count)) != NULL) {
			plist_get_string_val(value, &val);
			newlist = realloc(*classes, sizeof(char*) * (*count+1));
			str_remove_spaces(val);
			asprintf(&newlist[*count], "com.apple.%s", val);
			free(val);
			val = NULL;
			*classes = newlist;
			*count = *count+1;
	}

	newlist = realloc(*classes, sizeof(char*) * (*count+1));
	newlist[*count] = NULL;
	*classes = newlist;

	if (dict) {
		plist_free(dict);
	}
	return LOCKDOWN_E_SUCCESS;
}


/**
 * Frees memory of an allocated array of data classes as returned by lockdownd_get_sync_data_classes()
 *
 * @param classes An array of class names to free.
 *
 * @return LOCKDOWN_E_SUCCESS on success
 */
lockdownd_error_t lockdownd_data_classes_free(char **classes)
{
	if (classes) {
		int i = 0;
		while (classes[i++]) {
			free(classes[i]);
		}
		free(classes);
	}
	return LOCKDOWN_E_SUCCESS;
}

/**
 * Frees memory of a service descriptor as returned by lockdownd_start_service()
 *
 * @param sevice A service descriptor instance to free.
 *
 * @return LOCKDOWN_E_SUCCESS on success
 */
lockdownd_error_t lockdownd_service_descriptor_free(lockdownd_service_descriptor_t service)
{
	if (service)
		free(service);

	return LOCKDOWN_E_SUCCESS;
}
