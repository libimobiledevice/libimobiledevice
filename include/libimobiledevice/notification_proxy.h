/**
 * @file libimobiledevice/notification_proxy.h
 * @brief Observe and post notifications.
 * \internal
 *
 * Copyright (c) 2009 Nikias Bassen All Rights Reserved.
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

#ifndef INOTIFICATION_PROXY_H
#define INOTIFICATION_PROXY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define NP_SERVICE_NAME "com.apple.mobile.notification_proxy"

/** @name Error Codes */
/*@{*/
#define NP_E_SUCCESS                0
#define NP_E_INVALID_ARG           -1
#define NP_E_PLIST_ERROR           -2
#define NP_E_CONN_FAILED           -3

#define NP_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t np_error_t;

/**
 * @name Notifications that can be send
 *
 * For use with np_post_notification() (client --> device)
 */
#define NP_SYNC_WILL_START           "com.apple.itunes-mobdev.syncWillStart"
#define NP_SYNC_DID_START            "com.apple.itunes-mobdev.syncDidStart"
#define NP_SYNC_DID_FINISH           "com.apple.itunes-mobdev.syncDidFinish"
#define NP_SYNC_LOCK_REQUEST         "com.apple.itunes-mobdev.syncLockRequest"
/*@}*/

/**
 * @name Notifications that can be received
 *
 * For use with np_observe_notification() (device --> client)
 */
/*@{*/
#define NP_SYNC_CANCEL_REQUEST       "com.apple.itunes-client.syncCancelRequest"
#define NP_SYNC_SUSPEND_REQUEST      "com.apple.itunes-client.syncSuspendRequest"
#define NP_SYNC_RESUME_REQUEST       "com.apple.itunes-client.syncResumeRequest"
#define NP_PHONE_NUMBER_CHANGED      "com.apple.mobile.lockdown.phone_number_changed"
#define NP_DEVICE_NAME_CHANGED       "com.apple.mobile.lockdown.device_name_changed"
#define NP_TIMEZONE_CHANGED          "com.apple.mobile.lockdown.timezone_changed"
#define NP_TRUSTED_HOST_ATTACHED     "com.apple.mobile.lockdown.trusted_host_attached"
#define NP_HOST_DETACHED             "com.apple.mobile.lockdown.host_detached"
#define NP_HOST_ATTACHED             "com.apple.mobile.lockdown.host_attached"
#define NP_REGISTRATION_FAILED       "com.apple.mobile.lockdown.registration_failed"
#define NP_ACTIVATION_STATE          "com.apple.mobile.lockdown.activation_state"
#define NP_BRICK_STATE               "com.apple.mobile.lockdown.brick_state"
#define NP_DISK_USAGE_CHANGED        "com.apple.mobile.lockdown.disk_usage_changed" /**< iOS 4.0+ */
#define NP_DS_DOMAIN_CHANGED         "com.apple.mobile.data_sync.domain_changed"
#define NP_BACKUP_DOMAIN_CHANGED     "com.apple.mobile.backup.domain_changed"
#define NP_APP_INSTALLED             "com.apple.mobile.application_installed"
#define NP_APP_UNINSTALLED           "com.apple.mobile.application_uninstalled"
#define NP_DEV_IMAGE_MOUNTED         "com.apple.mobile.developer_image_mounted"
#define NP_ATTEMPTACTIVATION         "com.apple.springboard.attemptactivation"
#define NP_ITDBPREP_DID_END          "com.apple.itdbprep.notification.didEnd"
#define NP_LANGUAGE_CHANGED          "com.apple.language.changed"
#define NP_ADDRESS_BOOK_PREF_CHANGED "com.apple.AddressBook.PreferenceChanged"
/*@}*/

typedef struct np_client_private np_client_private;
typedef np_client_private *np_client_t; /**< The client handle. */

/** Reports which notification was received. */
typedef void (*np_notify_cb_t) (const char *notification, void *user_data);

/* Interface */

/**
 * Connects to the notification_proxy on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated np_client_t
 *    upon successful return.
 *
 * @return NP_E_SUCCESS on success, NP_E_INVALID_ARG when device is NULL,
 *   or NP_E_CONN_FAILED when the connection to the device could not be
 *   established.
 */
np_error_t np_client_new(idevice_t device, lockdownd_service_descriptor_t service, np_client_t *client);

/**
 * Starts a new notification proxy service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     np_client_t upon successful return. Must be freed using
 *     np_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return NP_E_SUCCESS on success, or an NP_E_* error
 *     code otherwise.
 */
np_error_t np_client_start_service(idevice_t device, np_client_t* client, const char* label);

/**
 * Disconnects a notification_proxy client from the device and frees up the
 * notification_proxy client data.
 *
 * @param client The notification_proxy client to disconnect and free.
 *
 * @return NP_E_SUCCESS on success, or NP_E_INVALID_ARG when client is NULL.
 */
np_error_t np_client_free(np_client_t client);


/**
 * Sends a notification to the device's notification_proxy.
 *
 * @param client The client to send to
 * @param notification The notification message to send
 *
 * @return NP_E_SUCCESS on success, or an error returned by np_plist_send
 */
np_error_t np_post_notification(np_client_t client, const char *notification);

/**
 * Tells the device to send a notification on the specified event.
 *
 * @param client The client to send to
 * @param notification The notifications that should be observed.
 *
 * @return NP_E_SUCCESS on success, NP_E_INVALID_ARG when client or
 *    notification are NULL, or an error returned by np_plist_send.
 */
np_error_t np_observe_notification(np_client_t client, const char *notification);

/**
 * Tells the device to send a notification on specified events.
 *
 * @param client The client to send to
 * @param notification_spec Specification of the notifications that should be
 *  observed. This is expected to be an array of const char* that MUST have a
 *  terminating NULL entry.
 *
 * @return NP_E_SUCCESS on success, NP_E_INVALID_ARG when client is null,
 *   or an error returned by np_observe_notification.
 */
np_error_t np_observe_notifications(np_client_t client, const char **notification_spec);

/**
 * This function allows an application to define a callback function that will
 * be called when a notification has been received.
 * It will start a thread that polls for notifications and calls the callback
 * function if a notification has been received.
 * In case of an error condition when polling for notifications - e.g. device
 * disconnect - the thread will call the callback function with an empty
 * notification "" and terminate itself.
 *
 * @param client the NP client
 * @param notify_cb pointer to a callback function or NULL to de-register a
 *        previously set callback function.
 * @param user_data Pointer that will be passed to the callback function as
 *        user data. If notify_cb is NULL, this parameter is ignored.
 *
 * @note Only one callback function can be registered at the same time;
 *       any previously set callback function will be removed automatically.
 *
 * @return NP_E_SUCCESS when the callback was successfully registered,
 *         NP_E_INVALID_ARG when client is NULL, or NP_E_UNKNOWN_ERROR when
 *         the callback thread could no be created.
 */
np_error_t np_set_notify_callback(np_client_t client, np_notify_cb_t notify_cb, void *userdata);

#ifdef __cplusplus
}
#endif

#endif
