/**
 * @file libimobiledevice/lockdown.h
 * @brief Manage device preferences, start services, pairing and activation.
 * \internal
 *
 * Copyright (c) 2009-2014 Martin S. All Rights Reserved.
 * Copyright (c) 2014 Koby Boyango All Rights Reserved.
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

#ifndef ILOCKDOWN_H
#define ILOCKDOWN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** Error Codes */
typedef enum {
	/* custom */
	LOCKDOWN_E_SUCCESS                                 =   0,
	LOCKDOWN_E_INVALID_ARG                             =  -1,
	LOCKDOWN_E_INVALID_CONF                            =  -2,
	LOCKDOWN_E_PLIST_ERROR                             =  -3,
	LOCKDOWN_E_PAIRING_FAILED                          =  -4,
	LOCKDOWN_E_SSL_ERROR                               =  -5,
	LOCKDOWN_E_DICT_ERROR                              =  -6,
	LOCKDOWN_E_RECEIVE_TIMEOUT                         =  -7,
	LOCKDOWN_E_MUX_ERROR                               =  -8,
	LOCKDOWN_E_NO_RUNNING_SESSION                      =  -9,
	/* native */
	LOCKDOWN_E_INVALID_RESPONSE                        = -10,
	LOCKDOWN_E_MISSING_KEY                             = -11,
	LOCKDOWN_E_MISSING_VALUE                           = -12,
	LOCKDOWN_E_GET_PROHIBITED                          = -13,
	LOCKDOWN_E_SET_PROHIBITED                          = -14,
	LOCKDOWN_E_REMOVE_PROHIBITED                       = -15,
	LOCKDOWN_E_IMMUTABLE_VALUE                         = -16,
	LOCKDOWN_E_PASSWORD_PROTECTED                      = -17,
	LOCKDOWN_E_USER_DENIED_PAIRING                     = -18,
	LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING         = -19,
	LOCKDOWN_E_MISSING_HOST_ID                         = -20,
	LOCKDOWN_E_INVALID_HOST_ID                         = -21,
	LOCKDOWN_E_SESSION_ACTIVE                          = -22,
	LOCKDOWN_E_SESSION_INACTIVE                        = -23,
	LOCKDOWN_E_MISSING_SESSION_ID                      = -24,
	LOCKDOWN_E_INVALID_SESSION_ID                      = -25,
	LOCKDOWN_E_MISSING_SERVICE                         = -26,
	LOCKDOWN_E_INVALID_SERVICE                         = -27,
	LOCKDOWN_E_SERVICE_LIMIT                           = -28,
	LOCKDOWN_E_MISSING_PAIR_RECORD                     = -29,
	LOCKDOWN_E_SAVE_PAIR_RECORD_FAILED                 = -30,
	LOCKDOWN_E_INVALID_PAIR_RECORD                     = -31,
	LOCKDOWN_E_INVALID_ACTIVATION_RECORD               = -32,
	LOCKDOWN_E_MISSING_ACTIVATION_RECORD               = -33,
	LOCKDOWN_E_SERVICE_PROHIBITED                      = -34,
	LOCKDOWN_E_ESCROW_LOCKED                           = -35,
	LOCKDOWN_E_PAIRING_PROHIBITED_OVER_THIS_CONNECTION = -36,
	LOCKDOWN_E_FMIP_PROTECTED                          = -37,
	LOCKDOWN_E_MC_PROTECTED                            = -38,
	LOCKDOWN_E_MC_CHALLENGE_REQUIRED                   = -39,
	LOCKDOWN_E_UNKNOWN_ERROR                           = -256
} lockdownd_error_t;

typedef struct lockdownd_client_private lockdownd_client_private;
typedef lockdownd_client_private *lockdownd_client_t; /**< The client handle. */

struct lockdownd_pair_record {
	char *device_certificate; /**< The device certificate */
	char *host_certificate;   /**< The host certificate */
	char *root_certificate;   /**< The root certificate */
	char *host_id;            /**< A unique HostID for the host computer */
	char *system_buid;          /**< A unique system id */
};
/** A pair record holding device, host and root certificates along the host_id */
typedef struct lockdownd_pair_record *lockdownd_pair_record_t;

struct lockdownd_service_descriptor {
	uint16_t port;
	uint8_t ssl_enabled;
};
typedef struct lockdownd_service_descriptor *lockdownd_service_descriptor_t;

/* Interface */

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
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_client_new(idevice_t device, lockdownd_client_t *client, const char *label);

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
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_INVALID_CONF if configuration data is wrong
 */
lockdownd_error_t lockdownd_client_new_with_handshake(idevice_t device, lockdownd_client_t *client, const char *label);

/**
 * Closes the lockdownd client session if one is running and frees up the
 * lockdownd_client struct.
 *
 * @param client The lockdown client
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_client_free(lockdownd_client_t client);


/**
 * Query the type of the service daemon. Depending on whether the device is
 * queried in normal mode or restore mode, different types will be returned.
 *
 * @param client The lockdownd client
 * @param type The type returned by the service daemon. Pass NULL to ignore.
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_query_type(lockdownd_client_t client, char **type);

/**
 * Retrieves a preferences plist using an optional domain and/or key name.
 *
 * @param client An initialized lockdownd client.
 * @param domain The domain to query on or NULL for global domain
 * @param key The key name to request or NULL to query for all keys
 * @param value A plist node representing the result value node
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_get_value(lockdownd_client_t client, const char *domain, const char *key, plist_t *value);

/**
 * Sets a preferences value using a plist and optional by domain and/or key name.
 *
 * @param client an initialized lockdownd client.
 * @param domain the domain to query on or NULL for global domain
 * @param key the key name to set the value or NULL to set a value dict plist
 * @param value a plist node of any node type representing the value to set
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client or
 *  value is NULL
 */
lockdownd_error_t lockdownd_set_value(lockdownd_client_t client, const char *domain, const char *key, plist_t value);

/**
 * Removes a preference node by domain and/or key name.
 *
 * @note: Use with caution as this could remove vital information on the device
 *
 * @param client An initialized lockdownd client.
 * @param domain The domain to query on or NULL for global domain
 * @param key The key name to remove or NULL remove all keys for the current domain
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_remove_value(lockdownd_client_t client, const char *domain, const char *key);

/**
 * Requests to start a service and retrieve it's port on success.
 *
 * @param client The lockdownd client
 * @param identifier The identifier of the service to start
 * @param service The service descriptor on success or NULL on failure
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG if a parameter
 *  is NULL, LOCKDOWN_E_INVALID_SERVICE if the requested service is not known
 *  by the device, LOCKDOWN_E_START_SERVICE_FAILED if the service could not be
 *  started by the device
 */
lockdownd_error_t lockdownd_start_service(lockdownd_client_t client, const char *identifier, lockdownd_service_descriptor_t *service);

/**
 * Requests to start a service and retrieve it's port on success.
 * Sends the escrow bag from the device's pair record.
 *
 * @param client The lockdownd client
 * @param identifier The identifier of the service to start
 * @param service The service descriptor on success or NULL on failure
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG if a parameter
 *  is NULL, LOCKDOWN_E_INVALID_SERVICE if the requested service is not known
 *  by the device, LOCKDOWN_E_START_SERVICE_FAILED if the service could not because
 *  started by the device, LOCKDOWN_E_INVALID_CONF if the host id or escrow bag are
 *  missing from the device record.
 */
lockdownd_error_t lockdownd_start_service_with_escrow_bag(lockdownd_client_t client, const char *identifier, lockdownd_service_descriptor_t *service);

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
lockdownd_error_t lockdownd_start_session(lockdownd_client_t client, const char *host_id, char **session_id, int *ssl_enabled);

/**
 * Closes the lockdownd session by sending the StopSession request.
 *
 * @see lockdownd_start_session
 *
 * @param client The lockdown client
 * @param session_id The id of a running session
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_stop_session(lockdownd_client_t client, const char *session_id);

/**
 * Sends a plist to lockdownd.
 *
 * @note This function is low-level and should only be used if you need to send
 *        a new type of message.
 *
 * @param client The lockdownd client
 * @param plist The plist to send
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client or
 *  plist is NULL
 */
lockdownd_error_t lockdownd_send(lockdownd_client_t client, plist_t plist);

/**
 * Receives a plist from lockdownd.
 *
 * @param client The lockdownd client
 * @param plist The plist to store the received data
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client or
 *  plist is NULL
 */
lockdownd_error_t lockdownd_receive(lockdownd_client_t client, plist_t *plist);

/**
 * Pairs the device using the supplied pair record.
 *
 * @param client The lockdown client
 * @param pair_record The pair record to use for pairing. If NULL is passed, then
 *    the pair records from the current machine are used. New records will be
 *    generated automatically when pairing is done for the first time.
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_PLIST_ERROR if the pair_record certificates are wrong,
 *  LOCKDOWN_E_PAIRING_FAILED if the pairing failed,
 *  LOCKDOWN_E_PASSWORD_PROTECTED if the device is password protected,
 *  LOCKDOWN_E_INVALID_HOST_ID if the device does not know the caller's host id
 */
lockdownd_error_t lockdownd_pair(lockdownd_client_t client, lockdownd_pair_record_t pair_record);

 /**
 * Pairs the device using the supplied pair record and passing the given options.
 *
 * @param client The lockdown client
 * @param pair_record The pair record to use for pairing. If NULL is passed, then
 *    the pair records from the current machine are used. New records will be
 *    generated automatically when pairing is done for the first time.
 * @param options The pairing options to pass. Can be NULL for no options.
 * @param response If non-NULL a pointer to lockdownd's response dictionary is returned.
 *    The caller is responsible to free the response dictionary with plist_free().
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_PLIST_ERROR if the pair_record certificates are wrong,
 *  LOCKDOWN_E_PAIRING_FAILED if the pairing failed,
 *  LOCKDOWN_E_PASSWORD_PROTECTED if the device is password protected,
 *  LOCKDOWN_E_INVALID_HOST_ID if the device does not know the caller's host id
 */
lockdownd_error_t lockdownd_pair_with_options(lockdownd_client_t client, lockdownd_pair_record_t pair_record, plist_t options, plist_t *response);

/**
 * Validates if the device is paired with the given HostID. If successful the
 * specified host will become trusted host of the device indicated by the
 * lockdownd preference named TrustedHostAttached. Otherwise the host must be
 * paired using lockdownd_pair() first.
 *
 * @param client The lockdown client
 * @param pair_record The pair record to validate pairing with. If NULL is
 *    passed, then the pair record is read from the internal pairing record
 *    management.
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_PLIST_ERROR if the pair_record certificates are wrong,
 *  LOCKDOWN_E_PAIRING_FAILED if the pairing failed,
 *  LOCKDOWN_E_PASSWORD_PROTECTED if the device is password protected,
 *  LOCKDOWN_E_INVALID_HOST_ID if the device does not know the caller's host id
 */
lockdownd_error_t lockdownd_validate_pair(lockdownd_client_t client, lockdownd_pair_record_t pair_record);

/**
 * Unpairs the device with the given HostID and removes the pairing records
 * from the device and host if the internal pairing record management is used.
 *
 * @param client The lockdown client
 * @param pair_record The pair record to use for unpair. If NULL is passed, then
 *    the pair records from the current machine are used.
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_PLIST_ERROR if the pair_record certificates are wrong,
 *  LOCKDOWN_E_PAIRING_FAILED if the pairing failed,
 *  LOCKDOWN_E_PASSWORD_PROTECTED if the device is password protected,
 *  LOCKDOWN_E_INVALID_HOST_ID if the device does not know the caller's host id
 */
lockdownd_error_t lockdownd_unpair(lockdownd_client_t client, lockdownd_pair_record_t pair_record);

/**
 * Activates the device. Only works within an open session.
 * The ActivationRecord plist dictionary must be obtained using the
 * activation protocol requesting from Apple's https webservice.
 *
 * @param client The lockdown client
 * @param activation_record The activation record plist dictionary
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client or
 *  activation_record is NULL, LOCKDOWN_E_NO_RUNNING_SESSION if no session is
 *  open, LOCKDOWN_E_PLIST_ERROR if the received plist is broken,
 *  LOCKDOWN_E_ACTIVATION_FAILED if the activation failed,
 *  LOCKDOWN_E_INVALID_ACTIVATION_RECORD if the device reports that the
 *  activation_record is invalid
 */
lockdownd_error_t lockdownd_activate(lockdownd_client_t client, plist_t activation_record);

/**
 * Deactivates the device, returning it to the locked “Activate with iTunes”
 * screen.
 *
 * @param client The lockdown client
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL,
 *  LOCKDOWN_E_NO_RUNNING_SESSION if no session is open,
 *  LOCKDOWN_E_PLIST_ERROR if the received plist is broken
 */
lockdownd_error_t lockdownd_deactivate(lockdownd_client_t client);

/**
 * Tells the device to immediately enter recovery mode.
 *
 * @param client The lockdown client
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client is NULL
 */
lockdownd_error_t lockdownd_enter_recovery(lockdownd_client_t client);

/**
 * Sends the Goodbye request to lockdownd signaling the end of communication.
 *
 * @param client The lockdown client
 *
 * @return LOCKDOWN_E_SUCCESS on success, LOCKDOWN_E_INVALID_ARG when client
 *  is NULL, LOCKDOWN_E_PLIST_ERROR if the device did not acknowledge the
 *  request
 */
lockdownd_error_t lockdownd_goodbye(lockdownd_client_t client);

/* Helper */

/**
 * Sets the label to send for requests to lockdownd.
 *
 * @param client The lockdown client
 * @param label The label to set or NULL to disable sending a label
 *
 */
void lockdownd_client_set_label(lockdownd_client_t client, const char *label);

/**
 * Returns the unique id of the device from lockdownd.
 *
 * @param client An initialized lockdownd client.
 * @param udid Holds the unique id of the device. The caller is responsible
 *  for freeing the memory.
 *
 * @return LOCKDOWN_E_SUCCESS on success
 */
lockdownd_error_t lockdownd_get_device_udid(lockdownd_client_t client, char **udid);

/**
 * Retrieves the name of the device from lockdownd set by the user.
 *
 * @param client An initialized lockdownd client.
 * @param device_name Holds the name of the device. The caller is
 *  responsible for freeing the memory.
 *
 * @return LOCKDOWN_E_SUCCESS on success
 */
lockdownd_error_t lockdownd_get_device_name(lockdownd_client_t client, char **device_name);

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
lockdownd_error_t lockdownd_get_sync_data_classes(lockdownd_client_t client, char ***classes, int *count);

/**
 * Frees memory of an allocated array of data classes as returned by lockdownd_get_sync_data_classes()
 *
 * @param classes An array of class names to free.
 *
 * @return LOCKDOWN_E_SUCCESS on success
 */
lockdownd_error_t lockdownd_data_classes_free(char **classes);

/**
 * Frees memory of a service descriptor as returned by lockdownd_start_service()
 *
 * @param service A service descriptor instance to free.
 *
 * @return LOCKDOWN_E_SUCCESS on success
 */
lockdownd_error_t lockdownd_service_descriptor_free(lockdownd_service_descriptor_t service);

/**
 * Gets a readable error string for a given lockdown error code.
 *
 * @params err A lockdownd error code
 *
 * @returns A readable error string
 */
const char* lockdownd_strerror(lockdownd_error_t err);

#ifdef __cplusplus
}
#endif

#endif
