/**
 * @file libimobiledevice/mobilebackup2.h
 * @brief Backup and restore of all device data (mobilebackup2, iOS4+ only)
 * \internal
 *
 * Copyright (c) 2010-2019 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2011-2014 Martin Szulecki, All Rights Reserved.
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

#ifndef IMOBILEBACKUP2_H
#define IMOBILEBACKUP2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define MOBILEBACKUP2_SERVICE_NAME "com.apple.mobilebackup2"

/** Error Codes */
typedef enum {
	MOBILEBACKUP2_E_SUCCESS           =  0,
	MOBILEBACKUP2_E_INVALID_ARG       = -1,
	MOBILEBACKUP2_E_PLIST_ERROR       = -2,
	MOBILEBACKUP2_E_MUX_ERROR         = -3,
	MOBILEBACKUP2_E_SSL_ERROR         = -4,
	MOBILEBACKUP2_E_RECEIVE_TIMEOUT   = -5,
	MOBILEBACKUP2_E_BAD_VERSION       = -6,
	MOBILEBACKUP2_E_REPLY_NOT_OK      = -7,
	MOBILEBACKUP2_E_NO_COMMON_VERSION = -8,
	MOBILEBACKUP2_E_UNKNOWN_ERROR     = -256
} mobilebackup2_error_t;

typedef struct mobilebackup2_client_private mobilebackup2_client_private;
typedef mobilebackup2_client_private *mobilebackup2_client_t; /**< The client handle. */


/**
 * Connects to the mobilebackup2 service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated
 *     mobilebackup2_client_t upon successful return.
 *
 * @return MOBILEBACKUP2_E_SUCCESS on success, MOBILEBACKUP2_E_INVALID ARG
 *     if one or more parameter is invalid, or MOBILEBACKUP2_E_BAD_VERSION
 *     if the mobilebackup2 version on the device is newer.
 */
mobilebackup2_error_t mobilebackup2_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobilebackup2_client_t * client);

/**
 * Starts a new mobilebackup2 service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     mobilebackup2_client_t upon successful return. Must be freed using
 *     mobilebackup2_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return MOBILEBACKUP2_E_SUCCESS on success, or an MOBILEBACKUP2_E_* error
 *     code otherwise.
 */
mobilebackup2_error_t mobilebackup2_client_start_service(idevice_t device, mobilebackup2_client_t* client, const char* label);

/**
 * Disconnects a mobilebackup2 client from the device and frees up the
 * mobilebackup2 client data.
 *
 * @param client The mobilebackup2 client to disconnect and free.
 *
 * @return MOBILEBACKUP2_E_SUCCESS on success, or MOBILEBACKUP2_E_INVALID_ARG
 *     if client is NULL.
 */
mobilebackup2_error_t mobilebackup2_client_free(mobilebackup2_client_t client);


/**
 * Sends a backup message plist.
 *
 * @param client The connected MobileBackup client to use.
 * @param message The message to send. This will be inserted into the request
 *     plist as value for MessageName. If this parameter is NULL,
 *     the plist passed in the options parameter will be sent directly.
 * @param options Additional options as PLIST_DICT to add to the request.
 *     The MessageName key with the value passed in the message parameter
 *     will be inserted into this plist before sending it. This parameter
 *     can be NULL if message is not NULL.
 */
mobilebackup2_error_t mobilebackup2_send_message(mobilebackup2_client_t client, const char *message, plist_t options);

/**
 * Receives a DL* message plist from the device.
 * This function is a wrapper around device_link_service_receive_message.
 *
 * @param client The connected MobileBackup client to use.
 * @param msg_plist Pointer to a plist that will be set to the contents of the
 *    message plist upon successful return.
 * @param dlmessage A pointer that will be set to a newly allocated char*
 *     containing the DL* string from the given plist. It is up to the caller
 *     to free the allocated memory. If this parameter is NULL
 *     it will be ignored.
 *
 * @return MOBILEBACKUP2_E_SUCCESS if a DL* message was received,
 *    MOBILEBACKUP2_E_INVALID_ARG if client or message is invalid,
 *    MOBILEBACKUP2_E_PLIST_ERROR if the received plist is invalid
 *    or is not a DL* message plist, or MOBILEBACKUP2_E_MUX_ERROR if
 *    receiving from the device failed.
 */
mobilebackup2_error_t mobilebackup2_receive_message(mobilebackup2_client_t client, plist_t *msg_plist, char **dlmessage);

/**
 * Send binary data to the device.
 *
 * @note This function returns MOBILEBACKUP2_E_SUCCESS even if less than the
 *     requested length has been sent. The fourth parameter is required and
 *     must be checked to ensure if the whole data has been sent.
 *
 * @param client The MobileBackup client to send to.
 * @param data Pointer to the data to send
 * @param length Number of bytes to send
 * @param bytes Number of bytes actually sent
 *
 * @return MOBILEBACKUP2_E_SUCCESS if any data was successfully sent,
 *     MOBILEBACKUP2_E_INVALID_ARG if one of the parameters is invalid,
 *     or MOBILEBACKUP2_E_MUX_ERROR if sending of the data failed.
 */
mobilebackup2_error_t mobilebackup2_send_raw(mobilebackup2_client_t client, const char *data, uint32_t length, uint32_t *bytes);

/**
 * Receive binary from the device.
 *
 * @note This function returns MOBILEBACKUP2_E_SUCCESS even if no data
 *     has been received (unless a communication error occurred).
 *     The fourth parameter is required and must be checked to know how
 *     many bytes were actually received.
 *
 * @param client The MobileBackup client to receive from.
 * @param data Pointer to a buffer that will be filled with the received data.
 * @param length Number of bytes to receive. The data buffer needs to be large
 *     enough to store this amount of data.
 * @paran bytes Number of bytes actually received.
 *
 * @return MOBILEBACKUP2_E_SUCCESS if any or no data was received,
 *     MOBILEBACKUP2_E_INVALID_ARG if one of the parameters is invalid,
 *     or MOBILEBACKUP2_E_MUX_ERROR if receiving the data failed.
 */
mobilebackup2_error_t mobilebackup2_receive_raw(mobilebackup2_client_t client, char *data, uint32_t length, uint32_t *bytes);

/**
 * Performs the mobilebackup2 protocol version exchange.
 *
 * @param client The MobileBackup client to use.
 * @param local_versions An array of supported versions to send to the remote.
 * @param count The number of items in local_versions.
 * @param remote_version Holds the protocol version of the remote on success.
 *
 * @return MOBILEBACKUP2_E_SUCCESS on success, or a MOBILEBACKUP2_E_* error
 *     code otherwise.
 */
mobilebackup2_error_t mobilebackup2_version_exchange(mobilebackup2_client_t client, double local_versions[], char count, double *remote_version);

/**
 * Send a request to the connected mobilebackup2 service.
 *
 * @param client
 * @param request The request to send to the backup service.
 *     Currently, this is one of "Backup", "Restore", "Info", or "List".
 * @param target_identifier UDID of the target device.
 * @param source_identifier UDID of backup data?
 * @param options Additional options in a plist of type PLIST_DICT.
 *
 * @return MOBILEBACKUP2_E_SUCCESS if the request was successfully sent,
 *     or a MOBILEBACKUP2_E_* error value otherwise.
 */
mobilebackup2_error_t mobilebackup2_send_request(mobilebackup2_client_t client, const char *request, const char *target_identifier, const char *source_identifier, plist_t options);

/**
 * Sends a DLMessageStatusResponse to the device.
 *
 * @param client The MobileBackup client to use.
 * @param status_code The status code to send.
 * @param status1 A status message to send. Can be NULL if not required.
 * @param status2 An additional status plist to attach to the response.
 *     Can be NULL if not required.
 *
 * @return MOBILEBACKUP2_E_SUCCESS on success, MOBILEBACKUP2_E_INVALID_ARG
 *     if client is invalid, or another MOBILEBACKUP2_E_* otherwise.
 */
mobilebackup2_error_t mobilebackup2_send_status_response(mobilebackup2_client_t client, int status_code, const char *status1, plist_t status2);

#ifdef __cplusplus
}
#endif

#endif
