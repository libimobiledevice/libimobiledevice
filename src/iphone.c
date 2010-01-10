/* 
 * iphone.c
 * Device discovery and communication interface.
 *
 * Copyright (c) 2008 Zach C. All Rights Reserved.
 * Copyright (c) 2009 Nikias Bassen. All Rights Reserved.
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <usbmuxd.h>
#include "iphone.h"
#include "utils.h"

static iphone_event_cb_t event_cb = NULL;

static void usbmux_event_cb(const usbmuxd_event_t *event, void *user_data)
{
	iphone_event_t ev;

	ev.event = event->event;
	ev.uuid = event->device.uuid;
	ev.conn_type = CONNECTION_USBMUXD;

	if (event_cb) {
		event_cb(&ev, user_data);
	}
}

/**
 * Register a callback function that will be called when device add/remove
 * events occur.
 *
 * @param callback Callback function to call.
 * @param user_data Application-specific data passed as parameter
 *   to the registered callback function.
 *
 * @return IPHONE_E_SUCCESS on success or an error value when an error occured.
 */
iphone_error_t iphone_event_subscribe(iphone_event_cb_t callback, void *user_data)
{
	event_cb = callback;
	int res = usbmuxd_subscribe(usbmux_event_cb, user_data);
        if (res != 0) {
		event_cb = NULL;
		log_debug_msg("%s: Error %d when subscribing usbmux event callback!\n", __func__, res);
		return IPHONE_E_UNKNOWN_ERROR;
	}
	return IPHONE_E_SUCCESS;
}

/**
 * Release the event callback function that has been registered with
 *  iphone_event_subscribe().
 *
 * @return IPHONE_E_SUCCESS on success or an error value when an error occured.
 */
iphone_error_t iphone_event_unsubscribe()
{
	event_cb = NULL;
	int res = usbmuxd_unsubscribe();
	if (res != 0) {
		log_debug_msg("%s: Error %d when unsubscribing usbmux event callback!\n", __func__, res);
		return IPHONE_E_UNKNOWN_ERROR;
	}
	return IPHONE_E_SUCCESS;
}

/**
 * Get a list of currently available devices.
 *
 * @param devices List of uuids of devices that are currently available.
 *   This list is terminated by a NULL pointer.
 * @param count Number of devices found.
 *
 * @return IPHONE_E_SUCCESS on success or an error value when an error occured.
 */
iphone_error_t iphone_get_device_list(char ***devices, int *count)
{
	usbmuxd_device_info_t *dev_list;

	*devices = NULL;
	*count = 0;

	if (usbmuxd_get_device_list(&dev_list) < 0) {
		log_debug_msg("%s: ERROR: usbmuxd is not running!\n", __func__);
		return IPHONE_E_NO_DEVICE;
	}

	char **newlist = NULL;
	int i, newcount = 0;

	for (i = 0; dev_list[i].handle > 0; i++) {
		newlist = realloc(*devices, sizeof(char*) * (newcount+1));
		newlist[newcount++] = strdup(dev_list[i].uuid);
		*devices = newlist;
	}
	usbmuxd_device_list_free(&dev_list);

	*count = newcount;
	newlist = realloc(*devices, sizeof(char*) * (newcount+1));
	newlist[newcount] = NULL;
	*devices = newlist;

	return IPHONE_E_SUCCESS;
}

/**
 * Free a list of device uuids.
 *
 * @param devices List of uuids to free.
 *
 * @return Always returnes IPHONE_E_SUCCESS.
 */
iphone_error_t iphone_device_list_free(char **devices)
{
	if (devices) {
		int i = 0;
		while (devices[i++]) {
			free(devices[i]);
		}
		free(devices);
	}
	return IPHONE_E_SUCCESS;
}

/**
 * Creates an iphone_device_t structure for the device specified by uuid,
 *  if the device is available.
 *
 * @note The resulting iphone_device_t structure has to be freed with
 * iphone_device_free() if it is no longer used.
 *
 * @param device Upon calling this function, a pointer to a location of type
 *  iphone_device_t. On successful return, this location will be populated.
 * @param uuid The UUID to match.
 *
 * @return IPHONE_E_SUCCESS if ok, otherwise an error code.
 */
iphone_error_t iphone_device_new(iphone_device_t * device, const char *uuid)
{
	usbmuxd_device_info_t muxdev;
	int res = usbmuxd_get_device_by_uuid(uuid, &muxdev);
	if (res > 0) {
		iphone_device_t phone = (iphone_device_t) malloc(sizeof(struct iphone_device_int));
		phone->uuid = strdup(muxdev.uuid);
		phone->conn_type = CONNECTION_USBMUXD;
		phone->conn_data = (void*)muxdev.handle;
		*device = phone;
		return IPHONE_E_SUCCESS;
	}
	/* other connection types could follow here */

	return IPHONE_E_NO_DEVICE;
}

/** Cleans up an iPhone structure, then frees the structure itself.  
 * This is a library-level function; deals directly with the iPhone to tear
 *  down relations, but otherwise is mostly internal.
 * 
 * @param device A pointer to an iPhone structure.
 */
iphone_error_t iphone_device_free(iphone_device_t device)
{
	if (!device)
		return IPHONE_E_INVALID_ARG;
	iphone_error_t ret = IPHONE_E_UNKNOWN_ERROR;

	ret = IPHONE_E_SUCCESS;

	free(device->uuid);

	if (device->conn_type == CONNECTION_USBMUXD) {
		device->conn_data = 0;
	}
	if (device->conn_data) {
		free(device->conn_data);
	}
	free(device);
	return ret;
}

/**
 * Set up a connection to the given device.
 *
 * @param device The device to connect to.
 * @param dst_port The destination port to connect to.
 * @param connection Pointer to an iphone_connection_t that will be filled
 *   with the necessary data of the connection.
 *
 * @return IPHONE_E_SUCCESS if ok, otherwise an error code.
 */
iphone_error_t iphone_device_connect(iphone_device_t device, uint16_t dst_port, iphone_connection_t *connection)
{
	if (!device) {
		return IPHONE_E_INVALID_ARG;
	}

	if (device->conn_type == CONNECTION_USBMUXD) {
		int sfd = usbmuxd_connect((uint32_t)(device->conn_data), dst_port);
		if (sfd < 0) {
			log_debug_msg("%s: ERROR: Connecting to usbmuxd failed: %d (%s)\n", __func__, sfd, strerror(-sfd));
			return IPHONE_E_UNKNOWN_ERROR;
		}
		iphone_connection_t new_connection = (iphone_connection_t)malloc(sizeof(struct iphone_connection_int));
		new_connection->type = CONNECTION_USBMUXD;
		new_connection->data = (void*)sfd;
		*connection = new_connection;
		return IPHONE_E_SUCCESS;
	} else {
		log_debug_msg("%s: Unknown connection type %d\n", __func__, device->conn_type);
	}

	return IPHONE_E_UNKNOWN_ERROR;
}

/**
 * Disconnect from the device and clean up the connection structure.
 *
 * @param connection The connection to close.
 *
 * @return IPHONE_E_SUCCESS if ok, otherwise an error code.
 */
iphone_error_t iphone_device_disconnect(iphone_connection_t connection)
{
	if (!connection) {
		return IPHONE_E_INVALID_ARG;
	}
	iphone_error_t result = IPHONE_E_UNKNOWN_ERROR;
	if (connection->type == CONNECTION_USBMUXD) {
		usbmuxd_disconnect((int)(connection->data));
		result = IPHONE_E_SUCCESS;
	} else {
		log_debug_msg("%s: Unknown connection type %d\n", __func__, connection->type);
	}
	free(connection);
	return result;
}

/**
 * Send data to a device via the given connection.
 *
 * @param connection The connection to send data over.
 * @param data Buffer with data to send.
 * @param len Size of the buffer to send.
 * @param sent_bytes Pointer to an uint32_t that will be filled
 *   with the number of bytes actually sent.
 *
 * @return IPHONE_E_SUCCESS if ok, otherwise an error code.
 */
iphone_error_t iphone_device_send(iphone_connection_t connection, const char *data, uint32_t len, uint32_t *sent_bytes)
{
	if (!connection || !data) {
		return IPHONE_E_INVALID_ARG;
	}

	if (connection->type == CONNECTION_USBMUXD) {
		int res = usbmuxd_send((int)(connection->data), data, len, sent_bytes);
		if (res < 0) {
			log_debug_msg("%s: ERROR: usbmuxd_send returned %d (%s)\n", __func__, res, strerror(-res));
			return IPHONE_E_UNKNOWN_ERROR;
		}
		return IPHONE_E_SUCCESS;
	} else {
		log_debug_msg("%s: Unknown connection type %d\n", __func__, connection->type);
	}
	return IPHONE_E_UNKNOWN_ERROR;
}

/**
 * Receive data from a device via the given connection.
 * This function will return after the given timeout even if no data has been
 * received.
 *
 * @param connection The connection to receive data from.
 * @param data Buffer that will be filled with the received data.
 *   This buffer has to be large enough to hold len bytes.
 * @param len Buffer size or number of bytes to receive.
 * @param recv_bytes Number of bytes actually received.
 * @param timeout Timeout in milliseconds after which this function should
 *   return even if no data has been received.
 *
 * @return IPHONE_E_SUCCESS if ok, otherwise an error code.
 */
iphone_error_t iphone_device_recv_timeout(iphone_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout)
{
	if (!connection) {
		return IPHONE_E_INVALID_ARG;
	}

	if (connection->type == CONNECTION_USBMUXD) {
		int res = usbmuxd_recv_timeout((int)(connection->data), data, len, recv_bytes, timeout);
		if (res < 0) {
			log_debug_msg("%s: ERROR: usbmuxd_recv_timeout returned %d (%s)\n", __func__, res, strerror(-res));
			return IPHONE_E_UNKNOWN_ERROR;
		}
		return IPHONE_E_SUCCESS;
	} else {
		log_debug_msg("%s: Unknown connection type %d\n", __func__, connection->type);
	}
	return IPHONE_E_UNKNOWN_ERROR;
}

/**
 * Receive data from a device via the given connection.
 * This function is like iphone_device_recv_timeout, but with a predefined
 *  reasonable timeout.
 *
 * @param connection The connection to receive data from.
 * @param data Buffer that will be filled with the received data.
 *   This buffer has to be large enough to hold len bytes.
 * @param len Buffer size or number of bytes to receive.
 * @param recv_bytes Number of bytes actually received.
 *
 * @return IPHONE_E_SUCCESS if ok, otherwise an error code.
 */
iphone_error_t iphone_device_recv(iphone_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes)
{
	if (!connection) {
		return -EINVAL;
	}

	if (connection->type == CONNECTION_USBMUXD) {
		int res = usbmuxd_recv((int)(connection->data), data, len, recv_bytes);
		if (res < 0) {
			log_debug_msg("%s: ERROR: usbmuxd_recv returned %d (%s)\n", __func__, res, strerror(-res));
			return IPHONE_E_UNKNOWN_ERROR;
		}

		return IPHONE_E_SUCCESS;
	} else {
		log_debug_msg("%s: Unknown connection type %d\n", __func__, connection->type);
	}
	return IPHONE_E_UNKNOWN_ERROR;
}

/**
 * Sends a plist over the given connection.
 * Internally used generic plist send function.
 *
 * @param connection The connection to use for sending.
 *        Can be NULL if ssl_session is non-NULL.
 * @param plist plist to send
 * @param binary 1 = send binary plist, 0 = send xml plist
 * @param ssl_session If set to NULL, the communication will be unencrypted.
 *        For encrypted communication, pass a valid and properly initialized
 *        gnutls_session_t. connection is ignored when ssl_session is non-NULL.
 *
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_INVALID_ARG when one or more
 *      parameters are invalid, IPHONE_E_PLIST_ERROR when dict is not a valid
 *      plist, or IPHONE_E_UNKNOWN_ERROR when an unspecified error occurs.
 */
static iphone_error_t internal_plist_send(iphone_connection_t connection, plist_t plist, int binary, gnutls_session_t ssl_session)
{
	iphone_error_t res = IPHONE_E_UNKNOWN_ERROR;
	char *content = NULL;
	uint32_t length = 0;
	uint32_t nlen = 0;
	int bytes = 0;

	if ((!connection && !ssl_session) || !plist) {
		return IPHONE_E_INVALID_ARG;
	}

	if (binary) {
		plist_to_bin(plist, &content, &length);
	} else {
		plist_to_xml(plist, &content, &length);
	}

	if (!content || length == 0) {
		return IPHONE_E_PLIST_ERROR;
	}

	nlen = htonl(length);
	log_debug_msg("%s: sending %d bytes\n", __func__, length);
	if (ssl_session) {
		bytes = gnutls_record_send(ssl_session, (const char*)&nlen, sizeof(nlen));
	} else {
		iphone_device_send(connection, (const char*)&nlen, sizeof(nlen), (uint32_t*)&bytes);
	}
	if (bytes == sizeof(nlen)) {
		if (ssl_session) {
			bytes = gnutls_record_send(ssl_session, content, length);
		} else {
			iphone_device_send(connection, content, length, (uint32_t*)&bytes);
		}
		if (bytes > 0) {
			log_debug_msg("%s: sent %d bytes\n", __func__, bytes);
			log_debug_buffer(content, bytes);
			if ((uint32_t)bytes == length) {
				res = IPHONE_E_SUCCESS;
			} else {
				log_debug_msg("%s: ERROR: Could not send all data (%d of %d)!\n", __func__, bytes, length);
			}
		}
	}
	if (bytes <= 0) {
		log_debug_msg("%s: ERROR: sending to device failed.\n", __func__);
	}

	free(content);

	return res;
}

/**
 * Sends an XML plist over the given connection.
 *
 * @param connection The connection to send data over
 * @param plist plist to send
 *
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_INVALID_ARG when connection
 *      or plist is NULL, IPHONE_E_PLIST_ERROR when dict is not a valid plist,
 *      or IPHONE_E_UNKNOWN_ERROR when an unspecified error occurs.
 */
iphone_error_t iphone_device_send_xml_plist(iphone_connection_t connection, plist_t plist)
{
	return internal_plist_send(connection, plist, 0, NULL);
}

/**
 * Sends a binary plist over the given connection.
 *
 * @param connection The connection to send data over
 * @param plist plist to send
 *
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_INVALID_ARG when connection
 *      or plist is NULL, IPHONE_E_PLIST_ERROR when dict is not a valid plist,
 *      or IPHONE_E_UNKNOWN_ERROR when an unspecified error occurs.
 */
iphone_error_t iphone_device_send_binary_plist(iphone_connection_t connection, plist_t plist)
{
	return internal_plist_send(connection, plist, 1, NULL);
}

/**
 * Sends an encrypted XML plist.
 *
 * @param ssl_session Valid and properly initialized gnutls_session_t.
 * @param plist plist to send
 *
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_INVALID_ARG when ssl_session
 *      or plist is NULL, IPHONE_E_PLIST_ERROR when dict is not a valid plist,
 *      or IPHONE_E_UNKNOWN_ERROR when an unspecified error occurs.
 */
iphone_error_t iphone_device_send_encrypted_xml_plist(gnutls_session_t ssl_session, plist_t plist)
{
	return internal_plist_send(NULL, plist, 0, ssl_session);
}

/**
 * Sends an encrypted binary plist.
 *
 * @param ssl_session Valid and properly initialized gnutls_session_t.
 * @param plist plist to send
 *
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_INVALID_ARG when ssl_session
 *      or plist is NULL, IPHONE_E_PLIST_ERROR when dict is not a valid plist,
 *      or IPHONE_E_UNKNOWN_ERROR when an unspecified error occurs.
 */
iphone_error_t iphone_device_send_encrypted_binary_plist(gnutls_session_t ssl_session, plist_t plist)
{
	return internal_plist_send(NULL, plist, 1, ssl_session);
}

/**
 * Receives a plist over the given connection. 
 * Internally used generic plist send function.
 *
 * @param connection The connection to receive data on
 * @param plist pointer to a plist_t that will point to the received plist
 *              upon successful return
 * @param timeout Maximum time in milliseconds to wait for data.
 * @param ssl_session If set to NULL, the communication will be unencrypted.
 *        For encrypted communication, pass a valid and properly initialized
 *        gnutls_session_t.
 *
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_INVALID_ARG when connection
 *    or *plist is NULL, IPHONE_E_PLIST_ERROR when the received data cannot be
 *    converted to a plist, or IPHONE_E_UNKNOWN_ERROR when an unspecified
 *    error occurs.
 */
static iphone_error_t internal_plist_recv_timeout(iphone_connection_t connection, plist_t *plist, unsigned int timeout, gnutls_session_t ssl_session)
{
	iphone_error_t res = IPHONE_E_UNKNOWN_ERROR;
	uint32_t pktlen = 0;
	uint32_t bytes = 0;

	if ((!connection && !ssl_session) || !plist) {
		return IPHONE_E_INVALID_ARG;
	}

	if (ssl_session) {
		bytes = gnutls_record_recv(ssl_session, (char*)&pktlen, sizeof(pktlen));
	} else {
		iphone_device_recv_timeout(connection, (char*)&pktlen, sizeof(pktlen), &bytes, timeout);
	}
	log_debug_msg("%s: initial read=%i\n", __func__, bytes);
	if (bytes < 4) {
		log_debug_msg("%s: initial read failed!\n", __func__);
		return IPHONE_E_NOT_ENOUGH_DATA;
	} else {
		if ((char)pktlen == 0) { /* prevent huge buffers */
			uint32_t curlen = 0;
			char *content = NULL;
			pktlen = ntohl(pktlen);
			log_debug_msg("%s: %d bytes following\n", __func__, pktlen);
			content = (char*)malloc(pktlen);

			while (curlen < pktlen) {
				if (ssl_session) {
					bytes = gnutls_record_recv(ssl_session, content+curlen, pktlen-curlen);
				} else {
					iphone_device_recv(connection, content+curlen, pktlen-curlen, &bytes);
				}
				if (bytes <= 0) {
					res = IPHONE_E_UNKNOWN_ERROR;
					break;
				}
				log_debug_msg("%s: received %d bytes\n", __func__, bytes);
				curlen += bytes;
			}
			log_debug_buffer(content, pktlen);
			if (!memcmp(content, "bplist00", 8)) {
				plist_from_bin(content, pktlen, plist);
			} else {
				plist_from_xml(content, pktlen, plist);
			}
			if (*plist) {
				res = IPHONE_E_SUCCESS;
			} else {
				res = IPHONE_E_PLIST_ERROR;
			}
			free(content);
			content = NULL;
		} else {
			res = IPHONE_E_UNKNOWN_ERROR;
		}
	}
	return res;
}

/**
 * Receives a plist over the given connection with specified timeout.
 * Binary or XML plists are automatically handled.
 *
 * @param connection The connection to receive data on
 * @param plist pointer to a plist_t that will point to the received plist
 *              upon successful return
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_INVALID_ARG when connection
 *    or *plist is NULL, IPHONE_E_PLIST_ERROR when the received data cannot be
 *    converted to a plist, or IPHONE_E_UNKNOWN_ERROR when an unspecified
 *    error occurs.
 */
iphone_error_t iphone_device_receive_plist_with_timeout(iphone_connection_t connection, plist_t *plist, unsigned int timeout)
{
	return internal_plist_recv_timeout(connection, plist, timeout, NULL);
}

/**
 * Receives a plist over the given connection.
 * Binary or XML plists are automatically handled.
 *
 * This function is like iphone_device_receive_plist_with_timeout
 *   using a timeout of 10 seconds.
 * @see iphone_device_receive_plist_with_timeout
 *
 * @param connection The connection to receive data on
 * @param plist pointer to a plist_t that will point to the received plist
 *              upon successful return
 *
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_INVALID_ARG when connection
 *    or *plist is NULL, IPHONE_E_PLIST_ERROR when the received data cannot be
 *    converted to a plist, or IPHONE_E_UNKNOWN_ERROR when an unspecified
 *    error occurs.
 */
iphone_error_t iphone_device_receive_plist(iphone_connection_t connection, plist_t *plist)
{
	return internal_plist_recv_timeout(connection, plist, 10000, NULL);
}

/**
 * Receives an encrypted plist with specified timeout.
 * Binary or XML plists are automatically handled.
 *
 * @param ssl_session Valid and properly initialized gnutls_session_t.
 * @param plist pointer to a plist_t that will point to the received plist
 *              upon successful return
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_INVALID_ARG when ssl_session
 *    or *plist is NULL, IPHONE_E_PLIST_ERROR when the received data cannot be
 *    converted to a plist, or IPHONE_E_UNKNOWN_ERROR when an unspecified
 *    error occurs.
 */
iphone_error_t iphone_device_receive_encrypted_plist_with_timeout(gnutls_session_t ssl_session, plist_t *plist, unsigned int timeout)
{
	return internal_plist_recv_timeout(NULL, plist, timeout, ssl_session);
}

/**
 * Receives an encrypted plist.
 * Binary or XML plists are automatically handled.
 * This function is like iphone_device_receive_encrypted_plist_with_timeout
 *   with a timeout value of 10 seconds.
 *
 * @param ssl_session Valid and properly initialized gnutls_session_t.
 * @param connection The connection to receive data on
 * @param plist pointer to a plist_t that will point to the received plist
 *              upon successful return
 *
 * @return IPHONE_E_SUCCESS on success, IPHONE_E_INVALID_ARG when ssl_session
 *    or *plist is NULL, IPHONE_E_PLIST_ERROR when the received data cannot be
 *    converted to a plist, or IPHONE_E_UNKNOWN_ERROR when an unspecified
 *    error occurs.
 */
iphone_error_t iphone_device_receive_encrypted_plist(gnutls_session_t ssl_session, plist_t *plist)
{
	return internal_plist_recv_timeout(NULL, plist, 10000, ssl_session);
}

iphone_error_t iphone_device_get_handle(iphone_device_t device, uint32_t *handle)
{
	if (!device)
		return IPHONE_E_INVALID_ARG;

	if (device->conn_type == CONNECTION_USBMUXD) {
		*handle = (uint32_t)device->conn_data;
		return IPHONE_E_SUCCESS;
	} else {
		log_debug_msg("%s: Unknown connection type %d\n", __func__, device->conn_type);
	}
	return IPHONE_E_UNKNOWN_ERROR;
}

iphone_error_t iphone_device_get_uuid(iphone_device_t device, char **uuid)
{
	if (!device)
		return IPHONE_E_INVALID_ARG;

	*uuid = strdup(device->uuid);
	return IPHONE_E_SUCCESS;
}

