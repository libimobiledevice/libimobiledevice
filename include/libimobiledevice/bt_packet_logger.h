/**
 * @file libimobiledevice/bt_packet_logger.h
 * @brief Capture the Bluetooth HCI trace from a device
 * \internal
 *
 * Copyright (c) 2021 Geoffrey Kruse, All Rights Reserved.
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

#ifndef IBT_PACKET_LOGGER_H
#define IBT_PACKET_LOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define BT_PACKETLOGGER_SERVICE_NAME "com.apple.bluetooth.BTPacketLogger"
#define BT_MAX_PACKET_SIZE 65535

/** Error Codes */
typedef enum {
	BT_PACKET_LOGGER_E_SUCCESS         =  0,
	BT_PACKET_LOGGER_E_INVALID_ARG     = -1,
	BT_PACKET_LOGGER_E_MUX_ERROR       = -2,
	BT_PACKET_LOGGER_E_SSL_ERROR       = -3,
	BT_PACKET_LOGGER_E_NOT_ENOUGH_DATA = -4,
	BT_PACKET_LOGGER_E_TIMEOUT         = -5,
	BT_PACKET_LOGGER_E_UNKNOWN_ERROR   = -256
} bt_packet_logger_error_t;

typedef struct {
	uint32_t length;
	uint32_t ts_secs;
	uint32_t ts_usecs;
} bt_packet_logger_header_t;

typedef struct bt_packet_logger_client_private bt_packet_logger_client_private;
typedef bt_packet_logger_client_private *bt_packet_logger_client_t; /**< The client handle. */

/** Receives each hci packet received from the device. */
typedef void (*bt_packet_logger_receive_cb_t)(uint8_t * data, uint16_t len, void *user_data);

/* Interface */

/**
 * Connects to the bt_packet_logger service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     bt_packet_logger_client_t upon successful return. Must be freed using
 *     bt_packet_logger_client_free() after use.
 *
 * @return BT_PACKET_LOGGER_E_SUCCESS on success, BT_PACKET_LOGGER_E_INVALID_ARG when
 *     client is NULL, or an BT_PACKET_LOGGER_E_* error code otherwise.
 */
LIBIMOBILEDEVICE_API bt_packet_logger_error_t bt_packet_logger_client_new(idevice_t device, lockdownd_service_descriptor_t service, bt_packet_logger_client_t * client);

/**
 * Starts a new bt_packet_logger service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     bt_packet_logger_client_t upon successful return. Must be freed using
 *     bt_packet_logger_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return BT_PACKET_LOGGER_E_SUCCESS on success, or an BT_PACKET_LOGGER_E_* error
 *     code otherwise.
 */
LIBIMOBILEDEVICE_API bt_packet_logger_error_t bt_packet_logger_client_start_service(idevice_t device, bt_packet_logger_client_t * client, const char* label);

/**
 * Disconnects a bt_packet_logger client from the device and frees up the
 * bt_packet_logger client data.
 *
 * @param client The bt_packet_logger client to disconnect and free.
 *
 * @return BT_PACKET_LOGGER_E_SUCCESS on success, BT_PACKET_LOGGER_E_INVALID_ARG when
 *     client is NULL, or an BT_PACKET_LOGGER_E_* error code otherwise.
 */
LIBIMOBILEDEVICE_API bt_packet_logger_error_t bt_packet_logger_client_free(bt_packet_logger_client_t client);


/**
 * Starts capturing the hci interface from the device using a callback.
 *
 * Use bt_packet_logger_stop_capture() to stop receiving hci data.
 *
 * @param client The bt_packet_logger client to use
 * @param callback Callback to receive each packet from the hci interface.
 * @param user_data Custom pointer passed to the callback function.
 *
 * @return BT_PACKET_LOGGER_E_SUCCESS on success,
 *      BT_PACKET_LOGGER_E_INVALID_ARG when one or more parameters are
 *      invalid or BT_PACKET_LOGGER_E_UNKNOWN_ERROR when an unspecified
 *      error occurs or an hci capture has already been started.
 */
LIBIMOBILEDEVICE_API bt_packet_logger_error_t bt_packet_logger_start_capture(bt_packet_logger_client_t client, bt_packet_logger_receive_cb_t callback, void* user_data);

/**
 * Stops capturing the hci interface from the device.
 *
 * Use bt_packet_logger_start_capture() to start receiving the hci data.
 *
 * @param client The bt_packet_logger client to use
 *
 * @return BT_PACKET_LOGGER_E_SUCCESS on success,
 *      BT_PACKET_LOGGER_E_INVALID_ARG when one or more parameters are
 *      invalid or BT_PACKET_LOGGER_E_UNKNOWN_ERROR when an unspecified
 *      error occurs or an hci capture has already been started.
 */
LIBIMOBILEDEVICE_API bt_packet_logger_error_t bt_packet_logger_stop_capture(bt_packet_logger_client_t client);

/* Receiving */

/**
 * Receives data using the given bt_packet_logger client with specified timeout.
 *
 * @param client The bt_packet_logger client to use for receiving
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return BT_PACKET_LOGGER_E_SUCCESS on success,
 *      BT_PACKET_LOGGER_E_INVALID_ARG when one or more parameters are
 *      invalid, BT_PACKET_LOGGER_E_MUX_ERROR when a communication error
 *      occurs, or BT_PACKET_LOGGER_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
LIBIMOBILEDEVICE_API bt_packet_logger_error_t bt_packet_logger_receive_with_timeout(bt_packet_logger_client_t client, char *data, uint32_t size, uint32_t *received, unsigned int timeout);


#ifdef __cplusplus
}
#endif

#endif
