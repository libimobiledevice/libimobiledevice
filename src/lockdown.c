/*
 * lockdown.c
 * com.apple.mobile.lockdownd service implementation.
 *
 * Copyright (c) 2009-2015 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2014-2015 Nikias Bassen All Rights Reserved.
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
#include <unistd.h>
#ifdef HAVE_OPENSSL
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#else
#include <libtasn1.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#endif
#include <plist/plist.h>

#include "property_list_service.h"
#include "lockdown.h"
#include "idevice.h"
#include "common/debug.h"
#include "common/userpref.h"
#include "common/utils.h"
#include "asprintf.h"

#ifdef WIN32
#include <windows.h>
#define sleep(x) Sleep(x*1000)
#endif

/**
 * Convert an error string identifier to a lockdownd_error_t value.
 * Used internally to get correct error codes from a response.
 *
 * @param name The error name to convert.
 *
 * @return A matching lockdownd_error_t error code,
 *     LOCKDOWN_E_UNKNOWN_ERROR otherwise.
 */
static lockdownd_error_t lockdownd_strtoerr(const char* name)
{
	lockdownd_error_t err = LOCKDOWN_E_UNKNOWN_ERROR;

	if (strcmp(name, "InvalidResponse") == 0) {
		err = LOCKDOWN_E_INVALID_RESPONSE;
	} else if (strcmp(name, "MissingKey") == 0) {
		err = LOCKDOWN_E_MISSING_KEY;
	} else if (strcmp(name, "MissingValue") == 0) {
		err = LOCKDOWN_E_MISSING_VALUE;
	} else if (strcmp(name, "GetProhibited") == 0) {
		err = LOCKDOWN_E_GET_PROHIBITED;
	} else if (strcmp(name, "SetProhibited") == 0) {
		err = LOCKDOWN_E_SET_PROHIBITED;
	} else if (strcmp(name, "RemoveProhibited") == 0) {
		err = LOCKDOWN_E_REMOVE_PROHIBITED;
	} else if (strcmp(name, "ImmutableValue") == 0) {
		err = LOCKDOWN_E_IMMUTABLE_VALUE;
	} else if (strcmp(name, "PasswordProtected") == 0) {
		err = LOCKDOWN_E_PASSWORD_PROTECTED;
	} else if (strcmp(name, "UserDeniedPairing") == 0) {
		err = LOCKDOWN_E_USER_DENIED_PAIRING;
	} else if (strcmp(name, "PairingDialogResponsePending") == 0) {
		err = LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING;
	} else if (strcmp(name, "MissingHostID") == 0) {
		err = LOCKDOWN_E_MISSING_HOST_ID;
	} else if (strcmp(name, "InvalidHostID") == 0) {
		err = LOCKDOWN_E_INVALID_HOST_ID;
	} else if (strcmp(name, "SessionActive") == 0) {
		err = LOCKDOWN_E_SESSION_ACTIVE;
	} else if (strcmp(name, "SessionInactive") == 0) {
		err = LOCKDOWN_E_SESSION_INACTIVE;
	} else if (strcmp(name, "MissingSessionID") == 0) {
		err = LOCKDOWN_E_MISSING_SESSION_ID;
	} else if (strcmp(name, "InvalidSessionID") == 0) {
		err = LOCKDOWN_E_INVALID_SESSION_ID;
	} else if (strcmp(name, "MissingService") == 0) {
		err = LOCKDOWN_E_MISSING_SERVICE;
	} else if (strcmp(name, "InvalidService") == 0) {
		err = LOCKDOWN_E_INVALID_SERVICE;
	} else if (strcmp(name, "ServiceLimit") == 0) {
		err = LOCKDOWN_E_SERVICE_LIMIT;
	} else if (strcmp(name, "MissingPairRecord") == 0) {
		err = LOCKDOWN_E_MISSING_PAIR_RECORD;
	} else if (strcmp(name, "SavePairRecordFailed") == 0) {
		err = LOCKDOWN_E_SAVE_PAIR_RECORD_FAILED;
	} else if (strcmp(name, "InvalidPairRecord") == 0) {
		err = LOCKDOWN_E_INVALID_PAIR_RECORD;
	} else if (strcmp(name, "InvalidActivationRecord") == 0) {
		err = LOCKDOWN_E_INVALID_ACTIVATION_RECORD;
	} else if (strcmp(name, "MissingActivationRecord") == 0) {
		err = LOCKDOWN_E_MISSING_ACTIVATION_RECORD;
	} else if (strcmp(name, "ServiceProhibited") == 0) {
		err = LOCKDOWN_E_SERVICE_PROHIBITED;
	} else if (strcmp(name, "EscrowLocked") == 0) {
		err = LOCKDOWN_E_ESCROW_LOCKED;
	} else if (strcmp(name, "PairingProhibitedOverThisConnection") == 0) {
		err = LOCKDOWN_E_PAIRING_PROHIBITED_OVER_THIS_CONNECTION;
	} else if (strcmp(name, "FMiPProtected") == 0) {
		err = LOCKDOWN_E_FMIP_PROTECTED;
	} else if (strcmp(name, "MCProtected") == 0) {
		err = LOCKDOWN_E_MC_PROTECTED;
	} else if (strcmp(name, "MCChallengeRequired") == 0) {
		err = LOCKDOWN_E_MC_CHALLENGE_REQUIRED;
	}

	return err;
}

/**
 * Convert a property_list_service_error_t value to a lockdownd_error_t
 * value. Used internally to get correct error codes.
 *
 * @param err A property_list_service_error_t error code
 *
 * @return A matching lockdownd_error_t error code,
 *     LOCKDOWND_E_UNKNOWN_ERROR otherwise.
 */
static lockdownd_error_t lockdownd_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return LOCKDOWN_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return LOCKDOWN_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return LOCKDOWN_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return LOCKDOWN_E_MUX_ERROR;
		case PROPERTY_LIST_SERVICE_E_SSL_ERROR:
			return LOCKDOWN_E_SSL_ERROR;
		case PROPERTY_LIST_SERVICE_E_RECEIVE_TIMEOUT:
			return LOCKDOWN_E_RECEIVE_TIMEOUT;
		default:
			break;
	}
	return LOCKDOWN_E_UNKNOWN_ERROR;
}

/**
 * Internally used function for checking the result from lockdown's answer
 * plist to a previously sent request.
 *
 * @param dict The plist to evaluate.
 * @param query_match Name of the request to match or NULL if no match is
 *        required.
 *
 * @return LOCKDOWN_E_SUCCESS when the result is 'Success',
 *         LOCKDOWN_E_UNKNOWN_ERROR when the result is 'Failure',
 *         or a specific error code if derieved from the result.
 */
static lockdownd_error_t lockdown_check_result(plist_t dict, const char *query_match)
{
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

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
					ret = lockdownd_strtoerr(err_value);
					free(err_value);
				} else {
					debug_info("ERROR: unknown error occured");
				}
			}
			return ret;
		}

		ret = LOCKDOWN_E_SUCCESS;

		return ret;
	}

	plist_type result_type = plist_get_node_type(result_node);
	if (result_type == PLIST_STRING) {
		char *result_value = NULL;

		plist_get_string_val(result_node, &result_value);
		if (result_value) {
			if (!strcmp(result_value, "Success")) {
				ret = LOCKDOWN_E_SUCCESS;
			} else if (!strcmp(result_value, "Failure")) {
				ret = LOCKDOWN_E_UNKNOWN_ERROR;
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
			plist_dict_set_item(plist, "Label", plist_new_string(label));
	}
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_stop_session(lockdownd_client_t client, const char *session_id)
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
	plist_dict_set_item(dict,"Request", plist_new_string("StopSession"));
	plist_dict_set_item(dict,"SessionID", plist_new_string(session_id));

	debug_info("stopping session %s", session_id);

	ret = lockdownd_send(client, dict);

	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);

	if (!dict) {
		debug_info("LOCKDOWN_E_PLIST_ERROR");
		return LOCKDOWN_E_PLIST_ERROR;
	}

	ret = lockdown_check_result(dict, "StopSession");
	if (ret == LOCKDOWN_E_SUCCESS) {
		debug_info("success");
	}

	plist_free(dict);
	dict = NULL;

	if (client->session_id) {
		free(client->session_id);
		client->session_id = NULL;
	}

	if (client->ssl_enabled) {
		property_list_service_disable_ssl(client->parent);
		client->ssl_enabled = 0;
	}

	return ret;
}

static lockdownd_error_t lockdownd_client_free_simple(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	if (client->parent) {
		if (property_list_service_client_free(client->parent) == PROPERTY_LIST_SERVICE_E_SUCCESS) {
			ret = LOCKDOWN_E_SUCCESS;
		}
	}

	if (client->session_id) {
		free(client->session_id);
		client->session_id = NULL;
	}
	if (client->udid) {
		free(client->udid);
	}
	if (client->label) {
		free(client->label);
	}

	free(client);
	client = NULL;

	return ret;
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_client_free(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	if (client->session_id) {
		lockdownd_stop_session(client, client->session_id);
	}

	ret = lockdownd_client_free_simple(client);

	return ret;
}

LIBIMOBILEDEVICE_API void lockdownd_client_set_label(lockdownd_client_t client, const char *label)
{
	if (client) {
		if (client->label)
			free(client->label);

		client->label = (label != NULL) ? strdup(label): NULL;
	}
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_receive(lockdownd_client_t client, plist_t *plist)
{
	if (!client || !plist || (plist && *plist))
		return LOCKDOWN_E_INVALID_ARG;

	return lockdownd_error(property_list_service_receive_plist(client->parent, plist));
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_send(lockdownd_client_t client, plist_t plist)
{
	if (!client || !plist)
		return LOCKDOWN_E_INVALID_ARG;

	return lockdownd_error(property_list_service_send_xml_plist(client->parent, plist));
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_query_type(lockdownd_client_t client, char **type)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict,"Request", plist_new_string("QueryType"));

	debug_info("called");
	ret = lockdownd_send(client, dict);

	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);

	if (LOCKDOWN_E_SUCCESS != ret)
		return ret;

	ret = LOCKDOWN_E_UNKNOWN_ERROR;
	plist_t type_node = plist_dict_get_item(dict, "Type");
	if (type_node && (plist_get_node_type(type_node) == PLIST_STRING)) {
		char* typestr = NULL;
		plist_get_string_val(type_node, &typestr);
		debug_info("success with type %s", typestr);
		/* return the type if requested */
		if (type != NULL) {
			*type = typestr;
		} else {
			free(typestr);
		}
		ret = LOCKDOWN_E_SUCCESS;
	} else {
		debug_info("hmm. QueryType response does not contain a type?!");
		debug_plist(dict);
	}
	plist_free(dict);
	dict = NULL;

	return ret;
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_get_value(lockdownd_client_t client, const char *domain, const char *key, plist_t *value)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	plist_t dict = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* setup request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	if (domain) {
		plist_dict_set_item(dict,"Domain", plist_new_string(domain));
	}
	if (key) {
		plist_dict_set_item(dict,"Key", plist_new_string(key));
	}
	plist_dict_set_item(dict,"Request", plist_new_string("GetValue"));

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

	ret = lockdown_check_result(dict, "GetValue");
	if (ret == LOCKDOWN_E_SUCCESS) {
		debug_info("success");
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

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_set_value(lockdownd_client_t client, const char *domain, const char *key, plist_t value)
{
	if (!client || !value)
		return LOCKDOWN_E_INVALID_ARG;

	plist_t dict = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* setup request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	if (domain) {
		plist_dict_set_item(dict,"Domain", plist_new_string(domain));
	}
	if (key) {
		plist_dict_set_item(dict,"Key", plist_new_string(key));
	}
	plist_dict_set_item(dict,"Request", plist_new_string("SetValue"));
	plist_dict_set_item(dict,"Value", value);

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

	ret = lockdown_check_result(dict, "SetValue");
	if (ret == LOCKDOWN_E_SUCCESS) {
		debug_info("success");
	}

	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_free(dict);
	return ret;
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_remove_value(lockdownd_client_t client, const char *domain, const char *key)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	plist_t dict = NULL;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* setup request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	if (domain) {
		plist_dict_set_item(dict,"Domain", plist_new_string(domain));
	}
	if (key) {
		plist_dict_set_item(dict,"Key", plist_new_string(key));
	}
	plist_dict_set_item(dict,"Request", plist_new_string("RemoveValue"));

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

	ret = lockdown_check_result(dict, "RemoveValue");
	if (ret == LOCKDOWN_E_SUCCESS) {
		debug_info("success");
	}

	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	plist_free(dict);
	return ret;
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_get_device_udid(lockdownd_client_t client, char **udid)
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
static lockdownd_error_t lockdownd_get_device_public_key_as_key_data(lockdownd_client_t client, key_data_t *public_key)
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

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_get_device_name(lockdownd_client_t client, char **device_name)
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

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_client_new(idevice_t device, lockdownd_client_t *client, const char *label)
{
	if (!device || !client)
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

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_client_new_with_handshake(idevice_t device, lockdownd_client_t *client, const char *label)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_SUCCESS;
	lockdownd_client_t client_loc = NULL;
	plist_t pair_record = NULL;
	char *host_id = NULL;
	char *type = NULL;

	ret = lockdownd_client_new(device, &client_loc, label);
	if (LOCKDOWN_E_SUCCESS != ret) {
		debug_info("failed to create lockdownd client.");
		return ret;
	}

	/* perform handshake */
	ret = lockdownd_query_type(client_loc, &type);
	if (LOCKDOWN_E_SUCCESS != ret) {
		debug_info("QueryType failed in the lockdownd client.");
	} else if (strcmp("com.apple.mobile.lockdown", type)) {
		debug_info("Warning QueryType request returned \"%s\".", type);
	}
	free(type);

	userpref_read_pair_record(client_loc->udid, &pair_record);
	if (pair_record) {
		pair_record_get_host_id(pair_record, &host_id);
	}
	if (LOCKDOWN_E_SUCCESS == ret && !host_id) {
		ret = LOCKDOWN_E_INVALID_CONF;
	}

	if (LOCKDOWN_E_SUCCESS == ret && !pair_record) {
		/* attempt pairing */
		ret = lockdownd_pair(client_loc, NULL);
	}

	plist_free(pair_record);
	pair_record = NULL;

	/* in any case, we need to validate pairing to receive trusted host status */
	ret = lockdownd_validate_pair(client_loc, NULL);

	/* if not paired yet, let's do it now */
	if (LOCKDOWN_E_INVALID_HOST_ID == ret) {
		free(host_id);
		host_id = NULL;
		ret = lockdownd_pair(client_loc, NULL);
		if (LOCKDOWN_E_SUCCESS == ret) {
			ret = lockdownd_validate_pair(client_loc, NULL);
		} else if (LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING == ret) {
			debug_info("Device shows the pairing dialog.");
		}
	}

	if (LOCKDOWN_E_SUCCESS == ret) {
		if (!host_id) {
			userpref_read_pair_record(client_loc->udid, &pair_record);
			if (pair_record) {
				pair_record_get_host_id(pair_record, &host_id);
				plist_free(pair_record);
			}
		}

		ret = lockdownd_start_session(client_loc, host_id, NULL, NULL);
		if (LOCKDOWN_E_SUCCESS != ret) {
			debug_info("Session opening failed.");
		}

	}

	if (LOCKDOWN_E_SUCCESS == ret) {
		*client = client_loc;
	} else {
		lockdownd_client_free(client_loc);
	}
	free(host_id);
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

	/* setup request plist */
	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "DeviceCertificate", plist_new_data(pair_record->device_certificate, strlen(pair_record->device_certificate)));
	plist_dict_set_item(dict, "HostCertificate", plist_new_data(pair_record->host_certificate, strlen(pair_record->host_certificate)));
	plist_dict_set_item(dict, "HostID", plist_new_string(pair_record->host_id));
	plist_dict_set_item(dict, "RootCertificate", plist_new_data(pair_record->root_certificate, strlen(pair_record->root_certificate)));
	plist_dict_set_item(dict, "SystemBUID", plist_new_string(pair_record->system_buid));

	return dict;
}

/**
 * Generates a pair record plist with required certificates for a specific
 * device. If a pairing exists, it is loaded from the computer instead of being
 * generated.
 *
 * @param pair_record_plist Holds the pair record.
 *
 * @return LOCKDOWN_E_SUCCESS on success
 */
static lockdownd_error_t pair_record_generate(lockdownd_client_t client, plist_t *pair_record)
{
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	key_data_t public_key = { NULL, 0 };
	char* host_id = NULL;
	char* system_buid = NULL;

	/* retrieve device public key */
	ret = lockdownd_get_device_public_key_as_key_data(client, &public_key);
	if (ret != LOCKDOWN_E_SUCCESS) {
		debug_info("device refused to send public key.");
		goto leave;
	}
	debug_info("device public key follows:\n%.*s", public_key.size, public_key.data);

	*pair_record = plist_new_dict();

	/* generate keys and certificates into pair record */
	userpref_error_t uret = USERPREF_E_SUCCESS;
	uret = pair_record_generate_keys_and_certs(*pair_record, public_key);
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

	/* set SystemBUID */
	userpref_read_system_buid(&system_buid);
	if (system_buid) {
		plist_dict_set_item(*pair_record, USERPREF_SYSTEM_BUID_KEY, plist_new_string(system_buid));
	}

	/* set HostID */
	host_id = generate_uuid();
	pair_record_set_host_id(*pair_record, host_id);

leave:
	if (host_id)
		free(host_id);
	if (system_buid)
		free(system_buid);
	if (public_key.data)
		free(public_key.data);

	return ret;
}

/**
 * Function used internally by lockdownd_pair() and lockdownd_validate_pair()
 *
 * @param client The lockdown client
 * @param pair_record The pair record to use for pairing. If NULL is passed, then
 *    the pair records from the current machine are used. New records will be
 *    generated automatically when pairing is done for the first time.
 * @param verb This is either "Pair", "ValidatePair" or "Unpair".
 * @param options The pairing options to pass.
 * @param response If non-NULL a pointer to lockdownd's response dictionary is returned.
 *
 * @return LOCKDOWN_E_SUCCESS on success, NP_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_PLIST_ERROR if the pair_record certificates are wrong,
 *  LOCKDOWN_E_PAIRING_FAILED if the pairing failed,
 *  LOCKDOWN_E_PASSWORD_PROTECTED if the device is password protected,
 *  LOCKDOWN_E_INVALID_HOST_ID if the device does not know the caller's host id
 */
static lockdownd_error_t lockdownd_do_pair(lockdownd_client_t client, lockdownd_pair_record_t pair_record, const char *verb, plist_t options, plist_t *result)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;
	plist_t dict = NULL;
	plist_t pair_record_plist = NULL;
	plist_t wifi_node = NULL;
	int pairing_mode = 0; /* 0 = libimobiledevice, 1 = external */

	if (pair_record && pair_record->system_buid && pair_record->host_id) {
		/* valid pair_record passed? */
		if (!pair_record->device_certificate || !pair_record->host_certificate || !pair_record->root_certificate) {
			return LOCKDOWN_E_PLIST_ERROR;
		}

		/* use passed pair_record */
		pair_record_plist = lockdownd_pair_record_to_plist(pair_record);

		pairing_mode = 1;
	} else {
		/* generate a new pair record if pairing */
		if (!strcmp("Pair", verb)) {
			ret = pair_record_generate(client, &pair_record_plist);

			if (ret != LOCKDOWN_E_SUCCESS) {
				if (pair_record_plist)
					plist_free(pair_record_plist);
				return ret;
			}

			/* get wifi mac now, if we get it later we fail on iOS 7 which causes a reconnect */
			lockdownd_get_value(client, NULL, "WiFiAddress", &wifi_node);
		} else {
			/* use existing pair record */
			userpref_read_pair_record(client->udid, &pair_record_plist);
			if (!pair_record_plist) {
				return LOCKDOWN_E_INVALID_HOST_ID;
			}
		}
	}

	plist_t request_pair_record = plist_copy(pair_record_plist);

	/* remove stuff that is private */
	plist_dict_remove_item(request_pair_record, USERPREF_ROOT_PRIVATE_KEY_KEY);
	plist_dict_remove_item(request_pair_record, USERPREF_HOST_PRIVATE_KEY_KEY);

	/* setup pair request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict, "PairRecord", request_pair_record);
	plist_dict_set_item(dict, "Request", plist_new_string(verb));
	plist_dict_set_item(dict, "ProtocolVersion", plist_new_string(LOCKDOWN_PROTOCOL_VERSION));

	if (options) {
		plist_dict_set_item(dict, "PairingOptions", plist_copy(options));
	}

	/* send to device */
	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(pair_record_plist);
		if (wifi_node)
			plist_free(wifi_node);
		return ret;
	}

	/* Now get device's answer */
	ret = lockdownd_receive(client, &dict);

	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(pair_record_plist);
		if (wifi_node)
			plist_free(wifi_node);
		return ret;
	}

	if (strcmp(verb, "Unpair") == 0) {
		/* workaround for Unpair giving back ValidatePair,
		 * seems to be a bug in the device's fw */
		if (lockdown_check_result(dict, NULL) != LOCKDOWN_E_SUCCESS) {
			ret = LOCKDOWN_E_PAIRING_FAILED;
		}
	} else {
		if (lockdown_check_result(dict, verb) != LOCKDOWN_E_SUCCESS) {
			ret = LOCKDOWN_E_PAIRING_FAILED;
		}
	}

	/* if pairing succeeded */
	if (ret == LOCKDOWN_E_SUCCESS) {
		debug_info("%s success", verb);
		if (!pairing_mode) {
			debug_info("internal pairing mode");
			if (!strcmp("Unpair", verb)) {
				/* remove public key from config */
				userpref_delete_pair_record(client->udid);
			} else {
				if (!strcmp("Pair", verb)) {
					/* add returned escrow bag if available */
					plist_t extra_node = plist_dict_get_item(dict, USERPREF_ESCROW_BAG_KEY);
					if (extra_node && plist_get_node_type(extra_node) == PLIST_DATA) {
						debug_info("Saving EscrowBag from response in pair record");
						plist_dict_set_item(pair_record_plist, USERPREF_ESCROW_BAG_KEY, plist_copy(extra_node));
					}

					/* save previously retrieved wifi mac address in pair record */
					if (wifi_node) {
						debug_info("Saving WiFiAddress from device in pair record");
						plist_dict_set_item(pair_record_plist, USERPREF_WIFI_MAC_ADDRESS_KEY, plist_copy(wifi_node));
						plist_free(wifi_node);
						wifi_node = NULL;
					}

					userpref_save_pair_record(client->udid, pair_record_plist);
				}
			}
		} else {
			debug_info("external pairing mode");
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
				ret = lockdownd_strtoerr(value);
				free(value);
			}
		}
	}

	if (pair_record_plist) {
		plist_free(pair_record_plist);
		pair_record_plist = NULL;
	}

	if (wifi_node) {
		plist_free(wifi_node);
		wifi_node = NULL;
	}

	if (result) {
		*result = dict;
	} else {
		plist_free(dict);
		dict = NULL;
	}

	return ret;
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_pair(lockdownd_client_t client, lockdownd_pair_record_t pair_record)
{

	plist_t options = plist_new_dict();
	plist_dict_set_item(options, "ExtendedPairingErrors", plist_new_bool(1));

	lockdownd_error_t ret = lockdownd_do_pair(client, pair_record, "Pair", options, NULL);

	plist_free(options);

	return ret;
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_pair_with_options(lockdownd_client_t client, lockdownd_pair_record_t pair_record, plist_t options, plist_t *response)
{
	return lockdownd_do_pair(client, pair_record, "Pair", options, response);
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_validate_pair(lockdownd_client_t client, lockdownd_pair_record_t pair_record)
{
	return lockdownd_do_pair(client, pair_record, "ValidatePair", NULL, NULL);
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_unpair(lockdownd_client_t client, lockdownd_pair_record_t pair_record)
{
	return lockdownd_do_pair(client, pair_record, "Unpair", NULL, NULL);
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_enter_recovery(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict,"Request", plist_new_string("EnterRecovery"));

	debug_info("telling device to enter recovery mode");

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);

	ret = lockdown_check_result(dict, "EnterRecovery");
	if (ret == LOCKDOWN_E_SUCCESS) {
		debug_info("success");
	}

	plist_free(dict);
	dict = NULL;

	return ret;
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_goodbye(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict,"Request", plist_new_string("Goodbye"));

	debug_info("called");

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);
	if (!dict) {
		debug_info("did not get goodbye response back");
		return LOCKDOWN_E_PLIST_ERROR;
	}

	ret = lockdown_check_result(dict, "Goodbye");
	if (ret == LOCKDOWN_E_SUCCESS) {
		debug_info("success");
	}

	plist_free(dict);
	dict = NULL;

	return ret;
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_start_session(lockdownd_client_t client, const char *host_id, char **session_id, int *ssl_enabled)
{
	lockdownd_error_t ret = LOCKDOWN_E_SUCCESS;
	plist_t dict = NULL;

	if (!client || !host_id)
		ret = LOCKDOWN_E_INVALID_ARG;

	/* if we have a running session, stop current one first */
	if (client->session_id) {
		lockdownd_stop_session(client, client->session_id);
	}

	/* setup request plist */
	dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict,"Request", plist_new_string("StartSession"));

	/* add host id */
	if (host_id) {
		plist_dict_set_item(dict, "HostID", plist_new_string(host_id));
	}

	/* add system buid */
	char *system_buid = NULL;
	userpref_read_system_buid(&system_buid);
	if (system_buid) {
		plist_dict_set_item(dict, "SystemBUID", plist_new_string(system_buid));
		if (system_buid) {
			free(system_buid);
			system_buid = NULL;
		}
	}

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	ret = lockdownd_receive(client, &dict);

	if (!dict)
		return LOCKDOWN_E_PLIST_ERROR;

	ret = lockdown_check_result(dict, "StartSession");
	if (ret == LOCKDOWN_E_SUCCESS) {
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

		debug_info("Enable SSL Session: %s", (use_ssl ? "true" : "false"));

		if (use_ssl) {
			ret = lockdownd_error(property_list_service_enable_ssl(client->parent));
			client->ssl_enabled = (ret == LOCKDOWN_E_SUCCESS ? 1 : 0);
		} else {
			ret = LOCKDOWN_E_SUCCESS;
			client->ssl_enabled = 0;
		}
	}

	plist_free(dict);
	dict = NULL;

	return ret;
}

/**
 * Internal function used by lockdownd_do_start_service to create the
 * StartService request's plist.
 *
 * @param client The lockdownd client
 * @param identifier The identifier of the service to start
 * @param send_escrow_bag Should we send the device's escrow bag with the request
 * @param request The request's plist on success, NULL on failure
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_CONF on failure
 * to read the escrow bag from the device's record (when used).
 */
static lockdownd_error_t lockdownd_build_start_service_request(lockdownd_client_t client, const char *identifier, int send_escrow_bag, plist_t *request)
{
	plist_t dict = plist_new_dict();

	/* create the basic request params */
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict, "Request", plist_new_string("StartService"));
	plist_dict_set_item(dict, "Service", plist_new_string(identifier));

	/* if needed - get the escrow bag for the device and send it with the request */
	if (send_escrow_bag) {
		/* get the pairing record */
		plist_t pair_record = NULL;
		userpref_read_pair_record(client->udid, &pair_record);
		if (!pair_record) {
			debug_info("ERROR: failed to read pair record for device: %s", client->udid);
			plist_free(dict);
			return LOCKDOWN_E_INVALID_CONF;
		}

		/* try to read the escrow bag from the record */
		plist_t escrow_bag = plist_dict_get_item(pair_record, USERPREF_ESCROW_BAG_KEY);
		if (!escrow_bag || (PLIST_DATA != plist_get_node_type(escrow_bag))) {
			debug_info("ERROR: Failed to retrieve the escrow bag from the device's record");
			plist_free(dict);
			plist_free(pair_record);
			return LOCKDOWN_E_INVALID_CONF;
		}

		debug_info("Adding escrow bag to StartService for %s", identifier);
		plist_dict_set_item(dict, USERPREF_ESCROW_BAG_KEY, plist_copy(escrow_bag));
		plist_free(pair_record);
	}

	*request = dict;
	return LOCKDOWN_E_SUCCESS;
}

/**
 * Function used internally by lockdownd_start_service and lockdownd_start_service_with_escrow_bag.
 *
 * @param client The lockdownd client
 * @param identifier The identifier of the service to start
 * @param send_escrow_bag Should we send the device's escrow bag with the request
 * @param descriptor The service descriptor on success or NULL on failure
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG if a parameter
 *  is NULL, LOCKDOWN_E_INVALID_SERVICE if the requested service is not known
 *  by the device, LOCKDOWN_E_START_SERVICE_FAILED if the service could not because
 *  started by the device, LOCKDOWN_E_INVALID_CONF if the host id or escrow bag (when
 *  used) are missing from the device record.
 */
static lockdownd_error_t lockdownd_do_start_service(lockdownd_client_t client, const char *identifier, int send_escrow_bag, lockdownd_service_descriptor_t *service)
{
	if (!client || !identifier || !service)
		return LOCKDOWN_E_INVALID_ARG;

	if (*service) {
		// reset fields if service descriptor is reused
		(*service)->port = 0;
		(*service)->ssl_enabled = 0;
	}

	plist_t dict = NULL;
	uint16_t port_loc = 0;
	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* create StartService request */
	ret = lockdownd_build_start_service_request(client, identifier, send_escrow_bag, &dict);
	if (LOCKDOWN_E_SUCCESS != ret)
		return ret;

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

	ret = lockdown_check_result(dict, "StartService");
	if (ret == LOCKDOWN_E_SUCCESS) {
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
		plist_t error_node = plist_dict_get_item(dict, "Error");
		if (error_node && PLIST_STRING == plist_get_node_type(error_node)) {
			char *error = NULL;
			plist_get_string_val(error_node, &error);
			ret = lockdownd_strtoerr(error);
			free(error);
		}
	}

	plist_free(dict);
	dict = NULL;

	return ret;
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_start_service(lockdownd_client_t client, const char *identifier, lockdownd_service_descriptor_t *service)
{
	return lockdownd_do_start_service(client, identifier, 0, service);
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_start_service_with_escrow_bag(lockdownd_client_t client, const char *identifier, lockdownd_service_descriptor_t *service)
{
	return lockdownd_do_start_service(client, identifier, 1, service);
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_activate(lockdownd_client_t client, plist_t activation_record)
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
	plist_dict_set_item(dict,"Request", plist_new_string("Activate"));
	plist_dict_set_item(dict,"ActivationRecord", plist_copy(activation_record));

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);
	if (!dict) {
		debug_info("LOCKDOWN_E_PLIST_ERROR");
		return LOCKDOWN_E_PLIST_ERROR;
	}

	ret = lockdown_check_result(dict, "Activate");
	if (ret == LOCKDOWN_E_SUCCESS) {
		debug_info("success");
	}

	plist_free(dict);
	dict = NULL;

	return ret;
}

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_deactivate(lockdownd_client_t client)
{
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	if (!client->session_id)
		return LOCKDOWN_E_NO_RUNNING_SESSION;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_add_label(dict, client->label);
	plist_dict_set_item(dict,"Request", plist_new_string("Deactivate"));

	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	ret = lockdownd_receive(client, &dict);
	if (!dict) {
		debug_info("LOCKDOWN_E_PLIST_ERROR");
		return LOCKDOWN_E_PLIST_ERROR;
	}

	ret = lockdown_check_result(dict, "Deactivate");
	if (ret == LOCKDOWN_E_SUCCESS) {
		debug_info("success");
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

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_get_sync_data_classes(lockdownd_client_t client, char ***classes, int *count)
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
		if (asprintf(&newlist[*count], "com.apple.%s", val) < 0) {
			debug_info("ERROR: asprintf failed");
		}
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

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_data_classes_free(char **classes)
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

LIBIMOBILEDEVICE_API lockdownd_error_t lockdownd_service_descriptor_free(lockdownd_service_descriptor_t service)
{
	if (service)
		free(service);

	return LOCKDOWN_E_SUCCESS;
}
