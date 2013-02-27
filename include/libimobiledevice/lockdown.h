/**
 * @file libimobiledevice/lockdown.h
 * @brief Manage device preferences, start services, pairing and activation.
 * \internal
 *
 * Copyright (c) 2008 Zach C. All Rights Reserved.
 * Copyright (c) 2009 Martin S. All Rights Reserved.
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

/** @name Error Codes */
/*@{*/
#define LOCKDOWN_E_SUCCESS                     0
#define LOCKDOWN_E_INVALID_ARG                -1
#define LOCKDOWN_E_INVALID_CONF               -2
#define LOCKDOWN_E_PLIST_ERROR                -3
#define LOCKDOWN_E_PAIRING_FAILED             -4
#define LOCKDOWN_E_SSL_ERROR                  -5
#define LOCKDOWN_E_DICT_ERROR                 -6
#define LOCKDOWN_E_START_SERVICE_FAILED       -7
#define LOCKDOWN_E_NOT_ENOUGH_DATA            -8
#define LOCKDOWN_E_SET_VALUE_PROHIBITED       -9
#define LOCKDOWN_E_GET_VALUE_PROHIBITED      -10
#define LOCKDOWN_E_REMOVE_VALUE_PROHIBITED   -11
#define LOCKDOWN_E_MUX_ERROR                 -12
#define LOCKDOWN_E_ACTIVATION_FAILED         -13
#define LOCKDOWN_E_PASSWORD_PROTECTED        -14
#define LOCKDOWN_E_NO_RUNNING_SESSION        -15
#define LOCKDOWN_E_INVALID_HOST_ID           -16
#define LOCKDOWN_E_INVALID_SERVICE           -17
#define LOCKDOWN_E_INVALID_ACTIVATION_RECORD -18

#define LOCKDOWN_E_UNKNOWN_ERROR            -256
/*@}*/

/** Represents an error code. */
typedef int16_t lockdownd_error_t;

typedef struct lockdownd_client_private lockdownd_client_private;
typedef lockdownd_client_private *lockdownd_client_t; /**< The client handle. */

struct lockdownd_pair_record {
	char *device_certificate; /**< The device certificate */
	char *host_certificate;   /**< The host certificate */
	char *host_id;            /**< A unique HostID for the host computer */
	char *root_certificate;   /**< The root certificate */
};
/** A pair record holding device, host and root certificates along the host_id */
typedef struct lockdownd_pair_record *lockdownd_pair_record_t;

struct lockdownd_service_descriptor {
	uint16_t port;
	uint8_t ssl_enabled;
};
typedef struct lockdownd_service_descriptor *lockdownd_service_descriptor_t;

/* Interface */
lockdownd_error_t lockdownd_client_new(idevice_t device, lockdownd_client_t *client, const char *label);
lockdownd_error_t lockdownd_client_new_with_handshake(idevice_t device, lockdownd_client_t *client, const char *label);
lockdownd_error_t lockdownd_client_free(lockdownd_client_t client);

lockdownd_error_t lockdownd_query_type(lockdownd_client_t client, char **type);
lockdownd_error_t lockdownd_get_value(lockdownd_client_t client, const char *domain, const char *key, plist_t *value);
lockdownd_error_t lockdownd_set_value(lockdownd_client_t client, const char *domain, const char *key, plist_t value);
lockdownd_error_t lockdownd_remove_value(lockdownd_client_t client, const char *domain, const char *key);
lockdownd_error_t lockdownd_start_service(lockdownd_client_t client, const char *identifier, lockdownd_service_descriptor_t *service);
lockdownd_error_t lockdownd_start_session(lockdownd_client_t client, const char *host_id, char **session_id, int *ssl_enabled);
lockdownd_error_t lockdownd_stop_session(lockdownd_client_t client, const char *session_id);
lockdownd_error_t lockdownd_send(lockdownd_client_t client, plist_t plist);
lockdownd_error_t lockdownd_receive(lockdownd_client_t client, plist_t *plist);
lockdownd_error_t lockdownd_pair(lockdownd_client_t client, lockdownd_pair_record_t pair_record);
lockdownd_error_t lockdownd_validate_pair(lockdownd_client_t client, lockdownd_pair_record_t pair_record);
lockdownd_error_t lockdownd_unpair(lockdownd_client_t client, lockdownd_pair_record_t pair_record);
lockdownd_error_t lockdownd_activate(lockdownd_client_t client, plist_t activation_record);
lockdownd_error_t lockdownd_deactivate(lockdownd_client_t client);
lockdownd_error_t lockdownd_enter_recovery(lockdownd_client_t client);
lockdownd_error_t lockdownd_goodbye(lockdownd_client_t client);

/* Helper */
void lockdownd_client_set_label(lockdownd_client_t client, const char *label);
lockdownd_error_t lockdownd_get_device_udid(lockdownd_client_t control, char **udid);
lockdownd_error_t lockdownd_get_device_name(lockdownd_client_t client, char **device_name);
lockdownd_error_t lockdownd_get_sync_data_classes(lockdownd_client_t client, char ***classes, int *count);
lockdownd_error_t lockdownd_data_classes_free(char **classes);
lockdownd_error_t lockdownd_service_descriptor_free(lockdownd_service_descriptor_t service);

#ifdef __cplusplus
}
#endif

#endif
