/* 
 * idevice.c
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
#include <gnutls/gnutls.h>
#include "idevice.h"
#include "debug.h"

static idevice_event_cb_t event_cb = NULL;

static void usbmux_event_cb(const usbmuxd_event_t *event, void *user_data)
{
	idevice_event_t ev;

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
 * @return IDEVICE_E_SUCCESS on success or an error value when an error occured.
 */
idevice_error_t idevice_event_subscribe(idevice_event_cb_t callback, void *user_data)
{
	event_cb = callback;
	int res = usbmuxd_subscribe(usbmux_event_cb, user_data);
        if (res != 0) {
		event_cb = NULL;
		debug_info("Error %d when subscribing usbmux event callback!", res);
		return IDEVICE_E_UNKNOWN_ERROR;
	}
	return IDEVICE_E_SUCCESS;
}

/**
 * Release the event callback function that has been registered with
 *  idevice_event_subscribe().
 *
 * @return IDEVICE_E_SUCCESS on success or an error value when an error occured.
 */
idevice_error_t idevice_event_unsubscribe()
{
	event_cb = NULL;
	int res = usbmuxd_unsubscribe();
	if (res != 0) {
		debug_info("Error %d when unsubscribing usbmux event callback!", res);
		return IDEVICE_E_UNKNOWN_ERROR;
	}
	return IDEVICE_E_SUCCESS;
}

/**
 * Get a list of currently available devices.
 *
 * @param devices List of uuids of devices that are currently available.
 *   This list is terminated by a NULL pointer.
 * @param count Number of devices found.
 *
 * @return IDEVICE_E_SUCCESS on success or an error value when an error occured.
 */
idevice_error_t idevice_get_device_list(char ***devices, int *count)
{
	usbmuxd_device_info_t *dev_list;

	*devices = NULL;
	*count = 0;

	if (usbmuxd_get_device_list(&dev_list) < 0) {
		debug_info("ERROR: usbmuxd is not running!\n", __func__);
		return IDEVICE_E_NO_DEVICE;
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

	return IDEVICE_E_SUCCESS;
}

/**
 * Free a list of device uuids.
 *
 * @param devices List of uuids to free.
 *
 * @return Always returnes IDEVICE_E_SUCCESS.
 */
idevice_error_t idevice_device_list_free(char **devices)
{
	if (devices) {
		int i = 0;
		while (devices[i++]) {
			free(devices[i]);
		}
		free(devices);
	}
	return IDEVICE_E_SUCCESS;
}

/**
 * Creates an idevice_t structure for the device specified by uuid,
 *  if the device is available.
 *
 * @note The resulting idevice_t structure has to be freed with
 * idevice_free() if it is no longer used.
 *
 * @param device Upon calling this function, a pointer to a location of type
 *  idevice_t. On successful return, this location will be populated.
 * @param uuid The UUID to match.
 *
 * @return IDEVICE_E_SUCCESS if ok, otherwise an error code.
 */
idevice_error_t idevice_new(idevice_t * device, const char *uuid)
{
	usbmuxd_device_info_t muxdev;
	int res = usbmuxd_get_device_by_uuid(uuid, &muxdev);
	if (res > 0) {
		idevice_t phone = (idevice_t) malloc(sizeof(struct idevice_private));
		phone->uuid = strdup(muxdev.uuid);
		phone->conn_type = CONNECTION_USBMUXD;
		phone->conn_data = (void*)muxdev.handle;
		*device = phone;
		return IDEVICE_E_SUCCESS;
	}
	/* other connection types could follow here */

	return IDEVICE_E_NO_DEVICE;
}

/**
 * Cleans up an idevice structure, then frees the structure itself.
 * This is a library-level function; deals directly with the device to tear
 *  down relations, but otherwise is mostly internal.
 * 
 * @param device idevice_t to free.
 */
idevice_error_t idevice_free(idevice_t device)
{
	if (!device)
		return IDEVICE_E_INVALID_ARG;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;

	ret = IDEVICE_E_SUCCESS;

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
 * @param port The destination port to connect to.
 * @param connection Pointer to an idevice_connection_t that will be filled
 *   with the necessary data of the connection.
 *
 * @return IDEVICE_E_SUCCESS if ok, otherwise an error code.
 */
idevice_error_t idevice_connect(idevice_t device, uint16_t port, idevice_connection_t *connection)
{
	if (!device) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (device->conn_type == CONNECTION_USBMUXD) {
		int sfd = usbmuxd_connect((uint32_t)(device->conn_data), port);
		if (sfd < 0) {
			debug_info("ERROR: Connecting to usbmuxd failed: %d (%s)", sfd, strerror(-sfd));
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		idevice_connection_t new_connection = (idevice_connection_t)malloc(sizeof(struct idevice_connection_private));
		new_connection->type = CONNECTION_USBMUXD;
		new_connection->data = (void*)sfd;
		new_connection->ssl_data = NULL;
		*connection = new_connection;
		return IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", device->conn_type);
	}

	return IDEVICE_E_UNKNOWN_ERROR;
}

/**
 * Disconnect from the device and clean up the connection structure.
 *
 * @param connection The connection to close.
 *
 * @return IDEVICE_E_SUCCESS if ok, otherwise an error code.
 */
idevice_error_t idevice_disconnect(idevice_connection_t connection)
{
	if (!connection) {
		return IDEVICE_E_INVALID_ARG;
	}
	/* shut down ssl if enabled */
	if (connection->ssl_data) {
		idevice_connection_disable_ssl(connection);
	}
	idevice_error_t result = IDEVICE_E_UNKNOWN_ERROR;
	if (connection->type == CONNECTION_USBMUXD) {
		usbmuxd_disconnect((int)(connection->data));
		result = IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", connection->type);
	}
	free(connection);
	return result;
}

/**
 * Internally used function to send raw data over the given connection.
 */
static idevice_error_t internal_connection_send(idevice_connection_t connection, const char *data, uint32_t len, uint32_t *sent_bytes)
{
	if (!connection || !data) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->type == CONNECTION_USBMUXD) {
		int res = usbmuxd_send((int)(connection->data), data, len, sent_bytes);
		if (res < 0) {
			debug_info("ERROR: usbmuxd_send returned %d (%s)", res, strerror(-res));
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		return IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", connection->type);
	}
	return IDEVICE_E_UNKNOWN_ERROR;

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
 * @return IDEVICE_E_SUCCESS if ok, otherwise an error code.
 */
idevice_error_t idevice_connection_send(idevice_connection_t connection, const char *data, uint32_t len, uint32_t *sent_bytes)
{
	if (!connection || !data || (connection->ssl_data && !connection->ssl_data->session)) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->ssl_data) {
		ssize_t sent = gnutls_record_send(connection->ssl_data->session, (void*)data, (size_t)len);
		if ((uint32_t)sent == (uint32_t)len) {
			*sent_bytes = sent;
			return IDEVICE_E_SUCCESS;
		}
		*sent_bytes = 0;
		return IDEVICE_E_SSL_ERROR;
	}
	return internal_connection_send(connection, data, len, sent_bytes);
}

/**
 * Internally used function for receiving raw data over the given connection
 * using a timeout.
 */
static idevice_error_t internal_connection_receive_timeout(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout)
{
	if (!connection) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->type == CONNECTION_USBMUXD) {
		int res = usbmuxd_recv_timeout((int)(connection->data), data, len, recv_bytes, timeout);
		if (res < 0) {
			debug_info("ERROR: usbmuxd_recv_timeout returned %d (%s)", res, strerror(-res));
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		return IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", connection->type);
	}
	return IDEVICE_E_UNKNOWN_ERROR;
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
 * @return IDEVICE_E_SUCCESS if ok, otherwise an error code.
 */
idevice_error_t idevice_connection_receive_timeout(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout)
{
	if (!connection || (connection->ssl_data && !connection->ssl_data->session)) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->ssl_data) {
		ssize_t received = gnutls_record_recv(connection->ssl_data->session, (void*)data, (size_t)len);
		if (received > 0) {
			*recv_bytes = received;
			return IDEVICE_E_SUCCESS;
		}
		*recv_bytes = 0;
		return IDEVICE_E_SSL_ERROR;
	}
	return internal_connection_receive_timeout(connection, data, len, recv_bytes, timeout);
}

/**
 * Internally used function for receiving raw data over the given connection.
 */
static idevice_error_t internal_connection_receive(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes)
{
	if (!connection) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->type == CONNECTION_USBMUXD) {
		int res = usbmuxd_recv((int)(connection->data), data, len, recv_bytes);
		if (res < 0) {
			debug_info("ERROR: usbmuxd_recv returned %d (%s)", res, strerror(-res));
			return IDEVICE_E_UNKNOWN_ERROR;
		}

		return IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", connection->type);
	}
	return IDEVICE_E_UNKNOWN_ERROR;
}

/**
 * Receive data from a device via the given connection.
 * This function is like idevice_connection_receive_timeout, but with a
 * predefined reasonable timeout.
 *
 * @param connection The connection to receive data from.
 * @param data Buffer that will be filled with the received data.
 *   This buffer has to be large enough to hold len bytes.
 * @param len Buffer size or number of bytes to receive.
 * @param recv_bytes Number of bytes actually received.
 *
 * @return IDEVICE_E_SUCCESS if ok, otherwise an error code.
 */
idevice_error_t idevice_connection_receive(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes)
{
	if (!connection || (connection->ssl_data && !connection->ssl_data->session)) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->ssl_data) {
		ssize_t received = gnutls_record_recv(connection->ssl_data->session, (void*)data, (size_t)len);
		if (received > 0) {
			*recv_bytes = received;
			return IDEVICE_E_SUCCESS;
		}
		*recv_bytes = 0;
		return IDEVICE_E_SSL_ERROR;
	}
	return internal_connection_receive(connection, data, len, recv_bytes);
}

/**
 * Gets the handle of the device. Depends on the connection type.
 */
idevice_error_t idevice_get_handle(idevice_t device, uint32_t *handle)
{
	if (!device)
		return IDEVICE_E_INVALID_ARG;

	if (device->conn_type == CONNECTION_USBMUXD) {
		*handle = (uint32_t)device->conn_data;
		return IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", device->conn_type);
	}
	return IDEVICE_E_UNKNOWN_ERROR;
}

/**
 * Gets the unique id for the device.
 */
idevice_error_t idevice_get_uuid(idevice_t device, char **uuid)
{
	if (!device)
		return IDEVICE_E_INVALID_ARG;

	*uuid = strdup(device->uuid);
	return IDEVICE_E_SUCCESS;
}

/**
 * Internally used gnutls callback function for receiving encrypted data.
 */
static ssize_t internal_ssl_read(gnutls_transport_ptr_t transport, char *buffer, size_t length)
{
	int bytes = 0, pos_start_fill = 0;
	size_t tbytes = 0;
	int this_len = length;
	idevice_error_t res;
	idevice_connection_t connection = (idevice_connection_t)transport;
	char *recv_buffer;

	debug_info("pre-read client wants %zi bytes", length);

	recv_buffer = (char *) malloc(sizeof(char) * this_len);

	/* repeat until we have the full data or an error occurs */
	do {
		if ((res = internal_connection_receive(connection, recv_buffer, this_len, (uint32_t*)&bytes)) != IDEVICE_E_SUCCESS) {
			debug_info("ERROR: idevice_connection_receive returned %d", res);
			return res;
		}
		debug_info("post-read we got %i bytes", bytes);

		/* increase read count */
		tbytes += bytes;

		/* fill the buffer with what we got right now */
		memcpy(buffer + pos_start_fill, recv_buffer, bytes);
		pos_start_fill += bytes;

		if (tbytes >= length) {
			break;
		}

		this_len = length - tbytes;
		debug_info("re-read trying to read missing %i bytes", this_len);
	} while (tbytes < length);

	if (recv_buffer) {
		free(recv_buffer);
	}
	return tbytes;
}

/**
 * Internally used gnutls callback function for sending encrypted data.
 */
static ssize_t internal_ssl_write(gnutls_transport_ptr_t transport, char *buffer, size_t length)
{
	uint32_t bytes = 0;
	idevice_connection_t connection = (idevice_connection_t)transport;
	debug_info("pre-send length = %zi", length);
	internal_connection_send(connection, buffer, length, &bytes);
	debug_info("post-send sent %i bytes", bytes);
	return bytes;
}

/**
 * Internally used function for cleaning up SSL stuff.
 */
static void internal_ssl_cleanup(ssl_data_t ssl_data)
{
	if (!ssl_data)
		return;

	if (ssl_data->session) {
		gnutls_deinit(ssl_data->session);
	}
	if (ssl_data->certificate) {
		gnutls_certificate_free_credentials(ssl_data->certificate);
	}
}

/**
 * Enables SSL for the given connection.
 *
 * @param connection The connection to enable SSL for.
 *
 * @return IDEVICE_E_SUCCESS on success, IDEVICE_E_INVALID_ARG when connection
 *     is NULL or connection->ssl_data is non-NULL, or IDEVICE_E_SSL_ERROR when
 *     SSL initialization, setup, or handshake fails.
 */
idevice_error_t idevice_connection_enable_ssl(idevice_connection_t connection)
{
	if (!connection || connection->ssl_data)
		return IDEVICE_E_INVALID_ARG;

	idevice_error_t ret = IDEVICE_E_SSL_ERROR;
	uint32_t return_me = 0;

	ssl_data_t ssl_data_loc = (ssl_data_t)malloc(sizeof(struct ssl_data_private));

	/* Set up GnuTLS... */
	debug_info("enabling SSL mode");
	errno = 0;
	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&ssl_data_loc->certificate);
	gnutls_certificate_set_x509_trust_file(ssl_data_loc->certificate, "hostcert.pem", GNUTLS_X509_FMT_PEM);
	gnutls_init(&ssl_data_loc->session, GNUTLS_CLIENT);
	{
		int protocol_priority[16] = { GNUTLS_SSL3, 0 };
		int kx_priority[16] = { GNUTLS_KX_ANON_DH, GNUTLS_KX_RSA, 0 };
		int cipher_priority[16] = { GNUTLS_CIPHER_AES_128_CBC, GNUTLS_CIPHER_AES_256_CBC, 0 };
		int mac_priority[16] = { GNUTLS_MAC_SHA1, GNUTLS_MAC_MD5, 0 };
		int comp_priority[16] = { GNUTLS_COMP_NULL, 0 };

		gnutls_cipher_set_priority(ssl_data_loc->session, cipher_priority);
		gnutls_compression_set_priority(ssl_data_loc->session, comp_priority);
		gnutls_kx_set_priority(ssl_data_loc->session, kx_priority);
		gnutls_protocol_set_priority(ssl_data_loc->session, protocol_priority);
		gnutls_mac_set_priority(ssl_data_loc->session, mac_priority);
	}
	gnutls_credentials_set(ssl_data_loc->session, GNUTLS_CRD_CERTIFICATE, ssl_data_loc->certificate); /* this part is killing me. */

	debug_info("GnuTLS step 1...");
	gnutls_transport_set_ptr(ssl_data_loc->session, (gnutls_transport_ptr_t)connection);
	debug_info("GnuTLS step 2...");
	gnutls_transport_set_push_function(ssl_data_loc->session, (gnutls_push_func) & internal_ssl_write);
	debug_info("GnuTLS step 3...");
	gnutls_transport_set_pull_function(ssl_data_loc->session, (gnutls_pull_func) & internal_ssl_read);
	debug_info("GnuTLS step 4 -- now handshaking...");
	if (errno)
		debug_info("WARN: errno says %s before handshake!", strerror(errno));
	return_me = gnutls_handshake(ssl_data_loc->session);
	debug_info("GnuTLS handshake done...");

	if (return_me != GNUTLS_E_SUCCESS) {
		internal_ssl_cleanup(ssl_data_loc);
		free(ssl_data_loc);
		debug_info("GnuTLS reported something wrong.");
		gnutls_perror(return_me);
		debug_info("oh.. errno says %s", strerror(errno));
	} else {
		connection->ssl_data = ssl_data_loc;
		ret = IDEVICE_E_SUCCESS;
		debug_info("SSL mode enabled");
	}
	return ret;
}

/**
 * Disable SSL for the given connection.
 *
 * @param connection The connection to disable SSL for.
 *
 * @return IDEVICE_E_SUCCESS on success, IDEVICE_E_INVALID_ARG when connection
 *     is NULL. This function also returns IDEVICE_E_SUCCESS when SSL is not
 *     enabled and does no further error checking on cleanup.
 */
idevice_error_t idevice_connection_disable_ssl(idevice_connection_t connection)
{
	if (!connection)
		return IDEVICE_E_INVALID_ARG;
	if (!connection->ssl_data) {
		/* ignore if ssl is not enabled */ 
		return IDEVICE_E_SUCCESS;
	}

	if (connection->ssl_data->session) {
		gnutls_bye(connection->ssl_data->session, GNUTLS_SHUT_RDWR);
	}
	internal_ssl_cleanup(connection->ssl_data);
	free(connection->ssl_data);
	connection->ssl_data = NULL;

	debug_info("SSL mode disabled");

	return IDEVICE_E_SUCCESS;
}

