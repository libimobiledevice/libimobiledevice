/*
 * idevice.c
 * Device discovery and communication interface.
 *
 * Copyright (c) 2009-2019 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2014 Martin Szulecki All Rights Reserved.
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <usbmuxd.h>
#ifdef HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#else
#include <gnutls/gnutls.h>
#endif

#include "idevice.h"
#include "common/userpref.h"
#include "common/socket.h"
#include "common/thread.h"
#include "common/debug.h"

#ifdef WIN32
#include <windows.h>
#endif

#ifndef ETIMEDOUT
#define ETIMEDOUT 138
#endif

#ifdef HAVE_OPENSSL

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x20020000L))
#define TLS_method TLSv1_method
#endif

#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
static void SSL_COMP_free_compression_methods(void)
{
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
}
#endif

static void openssl_remove_thread_state(void)
{
/*  ERR_remove_thread_state() is available since OpenSSL 1.0.0-beta1, but
 *  deprecated in OpenSSL 1.1.0 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#if OPENSSL_VERSION_NUMBER >= 0x10000001L
	ERR_remove_thread_state(NULL);
#else
	ERR_remove_state(0);
#endif
#endif
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
static mutex_t *mutex_buf = NULL;
static void locking_function(int mode, int n, const char* file, int line)
{
	if (mode & CRYPTO_LOCK)
		mutex_lock(&mutex_buf[n]);
	else
		mutex_unlock(&mutex_buf[n]);
}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
static unsigned long id_function(void)
{
	return ((unsigned long)THREAD_ID);
}
#else
static void id_function(CRYPTO_THREADID *thread)
{
	CRYPTO_THREADID_set_numeric(thread, (unsigned long)THREAD_ID);
}
#endif
#endif
#endif /* HAVE_OPENSSL */

static void internal_idevice_init(void)
{
#ifdef HAVE_OPENSSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	int i;
	SSL_library_init();

	mutex_buf = malloc(CRYPTO_num_locks() * sizeof(mutex_t));
	if (!mutex_buf)
		return;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		mutex_init(&mutex_buf[i]);

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	CRYPTO_set_id_callback(id_function);
#else
	CRYPTO_THREADID_set_callback(id_function);
#endif
	CRYPTO_set_locking_callback(locking_function);
#endif
#else
	gnutls_global_init();
#endif
}

static void internal_idevice_deinit(void)
{
#ifdef HAVE_OPENSSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	int i;
	if (mutex_buf) {
#if OPENSSL_VERSION_NUMBER < 0x10000000L
		CRYPTO_set_id_callback(NULL);
#else
		CRYPTO_THREADID_set_callback(NULL);
#endif
		CRYPTO_set_locking_callback(NULL);
		for (i = 0; i < CRYPTO_num_locks(); i++)
			mutex_destroy(&mutex_buf[i]);
		free(mutex_buf);
		mutex_buf = NULL;
	}

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	SSL_COMP_free_compression_methods();
	openssl_remove_thread_state();
#endif
#else
	gnutls_global_deinit();
#endif
}

static thread_once_t init_once = THREAD_ONCE_INIT;
static thread_once_t deinit_once = THREAD_ONCE_INIT;

#ifdef WIN32
BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		thread_once(&init_once,	internal_idevice_init);
		break;
	case DLL_PROCESS_DETACH:
		thread_once(&deinit_once, internal_idevice_deinit);
		break;
	default:
		break;
	}
	return 1;
}
#else
static void __attribute__((constructor)) libimobiledevice_initialize(void)
{
	thread_once(&init_once, internal_idevice_init);
}

static void __attribute__((destructor)) libimobiledevice_deinitialize(void)
{
	thread_once(&deinit_once, internal_idevice_deinit);
}
#endif

static idevice_event_cb_t event_cb = NULL;

static void usbmux_event_cb(const usbmuxd_event_t *event, void *user_data)
{
	idevice_event_t ev;

	ev.event = event->event;
	ev.udid = event->device.udid;
	ev.conn_type = 0;
	if (event->device.conn_type == CONNECTION_TYPE_USB) {
		ev.conn_type = CONNECTION_USBMUXD;
	} else if (event->device.conn_type == CONNECTION_TYPE_NETWORK) {
		ev.conn_type = CONNECTION_NETWORK;
	} else {
		debug_info("Unknown connection type %d", event->device.conn_type);
	}

	if (event_cb) {
		event_cb(&ev, user_data);
	}
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_event_subscribe(idevice_event_cb_t callback, void *user_data)
{
	event_cb = callback;
	int res = usbmuxd_subscribe(usbmux_event_cb, user_data);
	if (res != 0) {
		event_cb = NULL;
		debug_info("ERROR: usbmuxd_subscribe() returned %d!", res);
		return IDEVICE_E_UNKNOWN_ERROR;
	}
	return IDEVICE_E_SUCCESS;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_event_unsubscribe(void)
{
	event_cb = NULL;
	int res = usbmuxd_unsubscribe();
	if (res != 0) {
		debug_info("ERROR: usbmuxd_unsubscribe() returned %d!", res);
		return IDEVICE_E_UNKNOWN_ERROR;
	}
	return IDEVICE_E_SUCCESS;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_get_device_list_extended(idevice_info_t **devices, int *count)
{
	usbmuxd_device_info_t *dev_list;

	*devices = NULL;
	*count = 0;

	if (usbmuxd_get_device_list(&dev_list) < 0) {
		debug_info("ERROR: usbmuxd is not running!", __func__);
		return IDEVICE_E_NO_DEVICE;
	}

	idevice_info_t *newlist = NULL;
	int i, newcount = 0;

	for (i = 0; dev_list[i].handle > 0; i++) {
		newlist = realloc(*devices, sizeof(idevice_info_t) * (newcount+1));
		newlist[newcount] = malloc(sizeof(struct idevice_info));
		newlist[newcount]->udid = strdup(dev_list[i].udid);
		if (dev_list[i].conn_type == CONNECTION_TYPE_USB) {
			newlist[newcount]->conn_type = CONNECTION_USBMUXD;
			newlist[newcount]->conn_data = NULL;
		} else if (dev_list[i].conn_type == CONNECTION_TYPE_NETWORK) {
			newlist[newcount]->conn_type = CONNECTION_NETWORK;
			size_t addrlen = dev_list[i].conn_data[0];
			newlist[newcount]->conn_data = malloc(addrlen);
			memcpy(newlist[newcount]->conn_data, dev_list[i].conn_data, addrlen);
		}
		newcount++;
		*devices = newlist;
	}
	usbmuxd_device_list_free(&dev_list);

	*count = newcount;
	newlist = realloc(*devices, sizeof(idevice_info_t) * (newcount+1));
	newlist[newcount] = NULL;
	*devices = newlist;

	return IDEVICE_E_SUCCESS;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_device_list_extended_free(idevice_info_t *devices)
{
	if (devices) {
		int i = 0;
		while (devices[i]) {
			free(devices[i]->udid);
			free(devices[i]->conn_data);
			free(devices[i]);
			i++;
		}
		free(devices);
	}
	return IDEVICE_E_SUCCESS;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_get_device_list(char ***devices, int *count)
{
	usbmuxd_device_info_t *dev_list;

	*devices = NULL;
	*count = 0;

	if (usbmuxd_get_device_list(&dev_list) < 0) {
		debug_info("ERROR: usbmuxd is not running!", __func__);
		return IDEVICE_E_NO_DEVICE;
	}

	char **newlist = NULL;
	int i, newcount = 0;

	for (i = 0; dev_list[i].handle > 0; i++) {
		if (dev_list[i].conn_type == CONNECTION_TYPE_USB) {
			newlist = realloc(*devices, sizeof(char*) * (newcount+1));
			newlist[newcount++] = strdup(dev_list[i].udid);
			*devices = newlist;
		}
	}
	usbmuxd_device_list_free(&dev_list);

	*count = newcount;
	newlist = realloc(*devices, sizeof(char*) * (newcount+1));
	newlist[newcount] = NULL;
	*devices = newlist;

	return IDEVICE_E_SUCCESS;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_device_list_free(char **devices)
{
	if (devices) {
		int i = 0;
		while (devices[i]) {
			free(devices[i]);
			i++;
		}
		free(devices);
	}
	return IDEVICE_E_SUCCESS;
}

LIBIMOBILEDEVICE_API void idevice_set_debug_level(int level)
{
	internal_set_debug_level(level);
}

static idevice_t idevice_from_mux_device(usbmuxd_device_info_t *muxdev)
{
	if (!muxdev)
		return NULL;

	idevice_t device = (idevice_t)malloc(sizeof(struct idevice_private));
	if (!device)
		return NULL;

	device->udid = strdup(muxdev->udid);
	device->mux_id = muxdev->handle;
	device->version = 0;
	switch (muxdev->conn_type) {
	case CONNECTION_TYPE_USB:
		device->conn_type = CONNECTION_USBMUXD;
		device->conn_data = NULL;
		break;
	case CONNECTION_TYPE_NETWORK:
		device->conn_type = CONNECTION_NETWORK;
		size_t len = ((uint8_t*)muxdev->conn_data)[0];
		device->conn_data = malloc(len);
		memcpy(device->conn_data, muxdev->conn_data, len);
		break;
	default:
		device->conn_type = 0;
		device->conn_data = NULL;
		break;
	}
	return device;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_new_with_options(idevice_t * device, const char *udid, enum idevice_options options)
{
	usbmuxd_device_info_t muxdev;
	int usbmux_options = 0;
	if (options & IDEVICE_LOOKUP_USBMUX) {
		usbmux_options |= DEVICE_LOOKUP_USBMUX;
	}
	if (options & IDEVICE_LOOKUP_NETWORK) {
		usbmux_options |= DEVICE_LOOKUP_NETWORK;
	}
	if (options & IDEVICE_LOOKUP_PREFER_NETWORK) {
		usbmux_options |= DEVICE_LOOKUP_PREFER_NETWORK;
	}
	int res = usbmuxd_get_device(udid, &muxdev, usbmux_options);
	if (res > 0) {
		*device = idevice_from_mux_device(&muxdev);
		if (!*device) {
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		return IDEVICE_E_SUCCESS;
	}
	return IDEVICE_E_NO_DEVICE;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_new(idevice_t * device, const char *udid)
{
	return idevice_new_with_options(device, udid, 0);
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_free(idevice_t device)
{
	if (!device)
		return IDEVICE_E_INVALID_ARG;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;

	ret = IDEVICE_E_SUCCESS;

	free(device->udid);

	if (device->conn_data) {
		free(device->conn_data);
	}
	free(device);
	return ret;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_connect(idevice_t device, uint16_t port, idevice_connection_t *connection)
{
	if (!device) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (device->conn_type == CONNECTION_USBMUXD) {
		int sfd = usbmuxd_connect(device->mux_id, port);
		if (sfd < 0) {
			debug_info("ERROR: Connecting to usbmuxd failed: %d (%s)", sfd, strerror(-sfd));
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		idevice_connection_t new_connection = (idevice_connection_t)malloc(sizeof(struct idevice_connection_private));
		new_connection->type = CONNECTION_USBMUXD;
		new_connection->data = (void*)(long)sfd;
		new_connection->ssl_data = NULL;
		new_connection->device = device;
		*connection = new_connection;
		return IDEVICE_E_SUCCESS;
	} else if (device->conn_type == CONNECTION_NETWORK) {
		struct sockaddr_storage saddr_storage;
		struct sockaddr* saddr = (struct sockaddr*)&saddr_storage;

		/* FIXME: Improve handling of this platform/host dependent connection data */
		if (((char*)device->conn_data)[1] == 0x02) { // AF_INET
			saddr->sa_family = AF_INET;
			memcpy(&saddr->sa_data[0], (char*)device->conn_data + 2, 14);
		}
		else if (((char*)device->conn_data)[1] == 0x1E) { // AF_INET6 (bsd)
#ifdef AF_INET6
			saddr->sa_family = AF_INET6;
			/* copy the address and the host dependent scope id */
			memcpy(&saddr->sa_data[0], (char*)device->conn_data + 2, 26);
#else
			debug_info("ERROR: Got an IPv6 address but this system doesn't support IPv6");
			return IDEVICE_E_UNKNOWN_ERROR;
#endif
		}
		else {
			debug_info("Unsupported address family 0x%02x", ((char*)device->conn_data)[1]);
			return IDEVICE_E_UNKNOWN_ERROR;
		}

		char addrtxt[48];
		addrtxt[0] = '\0';

		if (!socket_addr_to_string(saddr, addrtxt, sizeof(addrtxt))) {
			debug_info("Failed to convert network address: %d (%s)", errno, strerror(errno));
		}

		debug_info("Connecting to %s port %d...", addrtxt, port);

		int sfd = socket_connect_addr(saddr, port);
		if (sfd < 0) {
			debug_info("ERROR: Connecting to network device failed: %d (%s)", errno, strerror(errno));
			return IDEVICE_E_NO_DEVICE;
		}

		idevice_connection_t new_connection = (idevice_connection_t)malloc(sizeof(struct idevice_connection_private));
		new_connection->type = CONNECTION_NETWORK;
		new_connection->data = (void*)(long)sfd;
		new_connection->ssl_data = NULL;
		new_connection->device = device;

		*connection = new_connection;

		return IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", device->conn_type);
	}

	return IDEVICE_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_disconnect(idevice_connection_t connection)
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
		usbmuxd_disconnect((int)(long)connection->data);
		connection->data = NULL;
		result = IDEVICE_E_SUCCESS;
	} else if (connection->type == CONNECTION_NETWORK) {
		socket_close((int)(long)connection->data);
		connection->data = NULL;
		result = IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", connection->type);
	}

	free(connection);
	connection = NULL;

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
		int res = usbmuxd_send((int)(long)connection->data, data, len, sent_bytes);
		if (res < 0) {
			debug_info("ERROR: usbmuxd_send returned %d (%s)", res, strerror(-res));
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		return IDEVICE_E_SUCCESS;
	} else if (connection->type == CONNECTION_NETWORK) {
		int s = socket_send((int)(long)connection->data, (void*)data, len);
		if (s < 0) {
			*sent_bytes = 0;
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		*sent_bytes = s;
		return IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", connection->type);
	}
	return IDEVICE_E_UNKNOWN_ERROR;

}

LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_send(idevice_connection_t connection, const char *data, uint32_t len, uint32_t *sent_bytes)
{
	if (!connection || !data || (connection->ssl_data && !connection->ssl_data->session)) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->ssl_data) {
		uint32_t sent = 0;
		while (sent < len) {
#ifdef HAVE_OPENSSL
			int c = socket_check_fd((int)(long)connection->data, FDM_WRITE, 100);
			if (c == 0 || c == -ETIMEDOUT || c == -EAGAIN) {
				continue;
			} else if (c < 0) {
				break;
			}
			int s = SSL_write(connection->ssl_data->session, (const void*)(data+sent), (int)(len-sent));
			if (s <= 0) {
				int sslerr = SSL_get_error(connection->ssl_data->session, s);
				if (sslerr == SSL_ERROR_WANT_WRITE) {
					continue;
				}
				break;
			}
#else
			ssize_t s = gnutls_record_send(connection->ssl_data->session, (void*)(data+sent), (size_t)(len-sent));
#endif
			if (s < 0) {
				break;
			}
			sent += s;
		}
		debug_info("SSL_write %d, sent %d", len, sent);
		if (sent < len) {
			*sent_bytes = 0;
			return IDEVICE_E_SSL_ERROR;
		}
		*sent_bytes = sent;
		return IDEVICE_E_SUCCESS;
	} else {
		uint32_t sent = 0;
		while (sent < len) {
			uint32_t bytes = 0;
			int s = internal_connection_send(connection, data+sent, len-sent, &bytes);
			if (s < 0) {
				break;
			}
			sent += bytes;
		}
		debug_info("internal_connection_send %d, sent %d", len, sent);
		if (sent < len) {
			*sent_bytes = 0;
			return IDEVICE_E_NOT_ENOUGH_DATA;
		}
		*sent_bytes = sent;
		return IDEVICE_E_SUCCESS;
	}
}

static idevice_error_t socket_recv_to_idevice_error(int conn_error, uint32_t len, uint32_t received)
{
	if (conn_error < 0) {
		switch (conn_error) {
			case -EAGAIN:
				debug_info("ERROR: received partial data %d/%d (%s)", received, len, strerror(-conn_error));
				return IDEVICE_E_NOT_ENOUGH_DATA;
			case -ETIMEDOUT:
				return IDEVICE_E_TIMEOUT;
			default:
				return IDEVICE_E_UNKNOWN_ERROR;
		}
	}

	return IDEVICE_E_SUCCESS;
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
		int conn_error = usbmuxd_recv_timeout((int)(long)connection->data, data, len, recv_bytes, timeout);
		idevice_error_t error = socket_recv_to_idevice_error(conn_error, len, *recv_bytes);

		if (error == IDEVICE_E_UNKNOWN_ERROR) {
			debug_info("ERROR: usbmuxd_recv_timeout returned %d (%s)", conn_error, strerror(-conn_error));
		}

		return error;
	} else if (connection->type == CONNECTION_NETWORK) {
		int res = socket_receive_timeout((int)(long)connection->data, data, len, 0, timeout);
		if (res < 0) {
			debug_info("ERROR: socket_receive_timeout failed: %d (%s)", res, strerror(-res));
			return (res == -EAGAIN ? IDEVICE_E_NOT_ENOUGH_DATA : IDEVICE_E_UNKNOWN_ERROR);
		}
		*recv_bytes = (uint32_t)res;
		return IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", connection->type);
	}
	return IDEVICE_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_receive_timeout(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout)
{
	if (!connection || (connection->ssl_data && !connection->ssl_data->session) || len == 0) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->ssl_data) {
		uint32_t received = 0;
		int do_select = 1;

		while (received < len) {
#ifdef HAVE_OPENSSL
			do_select = (SSL_pending(connection->ssl_data->session) == 0);
#endif
			if (do_select) {
				int conn_error = socket_check_fd((int)(long)connection->data, FDM_READ, timeout);
				idevice_error_t error = socket_recv_to_idevice_error(conn_error, len, received);

				switch (error) {
					case IDEVICE_E_SUCCESS:
						break;
					case IDEVICE_E_UNKNOWN_ERROR:
					default:
						debug_info("ERROR: socket_check_fd returned %d (%s)", conn_error, strerror(-conn_error));
						return error;
				}
			}

#ifdef HAVE_OPENSSL
			int r = SSL_read(connection->ssl_data->session, (void*)((char*)(data+received)), (int)len-received);
			if (r > 0) {
				received += r;
			} else {
				int sslerr = SSL_get_error(connection->ssl_data->session, r);
				if (sslerr == SSL_ERROR_WANT_READ) {
					continue;
				}
				break;
			}
#else
			ssize_t r = gnutls_record_recv(connection->ssl_data->session, (void*)(data+received), (size_t)len-received);
			if (r > 0) {
				received += r;
			} else {
				break;
			}
#endif
		}

		debug_info("SSL_read %d, received %d", len, received);
		if (received < len) {
			*recv_bytes = 0;
			return IDEVICE_E_SSL_ERROR;
		}

		*recv_bytes = received;
		return IDEVICE_E_SUCCESS;
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
		int res = usbmuxd_recv((int)(long)connection->data, data, len, recv_bytes);
		if (res < 0) {
			debug_info("ERROR: usbmuxd_recv returned %d (%s)", res, strerror(-res));
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		return IDEVICE_E_SUCCESS;
	} else if (connection->type == CONNECTION_NETWORK) {
		int res = socket_receive((int)(long)connection->data, data, len);
		if (res < 0) {
			debug_info("ERROR: socket_receive returned %d (%s)", res, strerror(-res));
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		*recv_bytes = (uint32_t)res;
		return IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", connection->type);
	}
	return IDEVICE_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_receive(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes)
{
	if (!connection || (connection->ssl_data && !connection->ssl_data->session)) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->ssl_data) {
#ifdef HAVE_OPENSSL
		int received = SSL_read(connection->ssl_data->session, (void*)data, (int)len);
		debug_info("SSL_read %d, received %d", len, received);
#else
		ssize_t received = gnutls_record_recv(connection->ssl_data->session, (void*)data, (size_t)len);
#endif
		if (received > 0) {
			*recv_bytes = received;
			return IDEVICE_E_SUCCESS;
		}
		*recv_bytes = 0;
		return IDEVICE_E_SSL_ERROR;
	}
	return internal_connection_receive(connection, data, len, recv_bytes);
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_get_fd(idevice_connection_t connection, int *fd)
{
	if (!connection || !fd) {
		return IDEVICE_E_INVALID_ARG;
	}

	idevice_error_t result = IDEVICE_E_UNKNOWN_ERROR;
	if (connection->type == CONNECTION_USBMUXD) {
		*fd = (int)(long)connection->data;
		result = IDEVICE_E_SUCCESS;
	} else if (connection->type == CONNECTION_NETWORK) {
		*fd = (int)(long)connection->data;
		result = IDEVICE_E_SUCCESS;
	} else {
		debug_info("Unknown connection type %d", connection->type);
	}
	return result;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_get_handle(idevice_t device, uint32_t *handle)
{
	if (!device || !handle)
		return IDEVICE_E_INVALID_ARG;

	*handle = device->mux_id;
	return IDEVICE_E_SUCCESS;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_get_udid(idevice_t device, char **udid)
{
	if (!device || !udid)
		return IDEVICE_E_INVALID_ARG;

	*udid = strdup(device->udid);
	return IDEVICE_E_SUCCESS;
}

#ifndef HAVE_OPENSSL
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

	recv_buffer = (char *)malloc(sizeof(char) * this_len);

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
	idevice_error_t res;
	idevice_connection_t connection = (idevice_connection_t)transport;
	debug_info("pre-send length = %zi", length);
	if ((res = internal_connection_send(connection, buffer, length, &bytes)) != IDEVICE_E_SUCCESS) {
		debug_info("ERROR: internal_connection_send returned %d", res);
		return -1;
	}
	debug_info("post-send sent %i bytes", bytes);
	return bytes;
}
#endif

/**
 * Internally used function for cleaning up SSL stuff.
 */
static void internal_ssl_cleanup(ssl_data_t ssl_data)
{
	if (!ssl_data)
		return;

#ifdef HAVE_OPENSSL
	if (ssl_data->session) {
		SSL_free(ssl_data->session);
	}
	if (ssl_data->ctx) {
		SSL_CTX_free(ssl_data->ctx);
	}
#else
	if (ssl_data->session) {
		gnutls_deinit(ssl_data->session);
	}
	if (ssl_data->certificate) {
		gnutls_certificate_free_credentials(ssl_data->certificate);
	}
	if (ssl_data->root_cert) {
		gnutls_x509_crt_deinit(ssl_data->root_cert);
	}
	if (ssl_data->host_cert) {
		gnutls_x509_crt_deinit(ssl_data->host_cert);
	}
	if (ssl_data->root_privkey) {
		gnutls_x509_privkey_deinit(ssl_data->root_privkey);
	}
	if (ssl_data->host_privkey) {
		gnutls_x509_privkey_deinit(ssl_data->host_privkey);
	}
#endif
}

#ifdef HAVE_OPENSSL
static int ssl_verify_callback(int ok, X509_STORE_CTX *ctx)
{
	return 1;
}

#ifndef STRIP_DEBUG_CODE
static const char *ssl_error_to_string(int e)
{
	switch(e) {
		case SSL_ERROR_NONE:
			return "SSL_ERROR_NONE";
		case SSL_ERROR_SSL:
			return ERR_error_string(ERR_get_error(), NULL);
		case SSL_ERROR_WANT_READ:
			return "SSL_ERROR_WANT_READ";
		case SSL_ERROR_WANT_WRITE:
			return "SSL_ERROR_WANT_WRITE";
		case SSL_ERROR_WANT_X509_LOOKUP:
			return "SSL_ERROR_WANT_X509_LOOKUP";
		case SSL_ERROR_SYSCALL:
			return "SSL_ERROR_SYSCALL";
		case SSL_ERROR_ZERO_RETURN:
			return "SSL_ERROR_ZERO_RETURN";
		case SSL_ERROR_WANT_CONNECT:
			return "SSL_ERROR_WANT_CONNECT";
		case SSL_ERROR_WANT_ACCEPT:
			return "SSL_ERROR_WANT_ACCEPT";
		default:
			return "UNKOWN_ERROR_VALUE";
	}
}
#endif
#endif

#ifndef HAVE_OPENSSL
/**
 * Internally used gnutls callback function that gets called during handshake.
 */
#if GNUTLS_VERSION_NUMBER >= 0x020b07
static int internal_cert_callback(gnutls_session_t session, const gnutls_datum_t * req_ca_rdn, int nreqs, const gnutls_pk_algorithm_t * sign_algos, int sign_algos_length, gnutls_retr2_st * st)
#else
static int internal_cert_callback(gnutls_session_t session, const gnutls_datum_t * req_ca_rdn, int nreqs, const gnutls_pk_algorithm_t * sign_algos, int sign_algos_length, gnutls_retr_st * st)
#endif
{
	int res = -1;
	gnutls_certificate_type_t type = gnutls_certificate_type_get(session);
	if (type == GNUTLS_CRT_X509) {
		ssl_data_t ssl_data = (ssl_data_t)gnutls_session_get_ptr(session);
		if (ssl_data && ssl_data->host_privkey && ssl_data->host_cert) {
			debug_info("Passing certificate");
#if GNUTLS_VERSION_NUMBER >= 0x020b07
			st->cert_type = type;
			st->key_type = GNUTLS_PRIVKEY_X509;
#else
			st->type = type;
#endif
			st->ncerts = 1;
			st->cert.x509 = &ssl_data->host_cert;
			st->key.x509 = ssl_data->host_privkey;
			st->deinit_all = 0;
			res = 0;
		}
	}
	return res;
}
#endif

LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_enable_ssl(idevice_connection_t connection)
{
	if (!connection || connection->ssl_data)
		return IDEVICE_E_INVALID_ARG;

	idevice_error_t ret = IDEVICE_E_SSL_ERROR;
	plist_t pair_record = NULL;

	userpref_read_pair_record(connection->device->udid, &pair_record);
	if (!pair_record) {
		debug_info("ERROR: Failed enabling SSL. Unable to read pair record for udid %s.", connection->device->udid);
		return ret;
	}

#ifdef HAVE_OPENSSL
	key_data_t root_cert = { NULL, 0 };
	key_data_t root_privkey = { NULL, 0 };

	pair_record_import_crt_with_name(pair_record, USERPREF_ROOT_CERTIFICATE_KEY, &root_cert);
	pair_record_import_key_with_name(pair_record, USERPREF_ROOT_PRIVATE_KEY_KEY, &root_privkey);

	if (pair_record)
		plist_free(pair_record);

	BIO *ssl_bio = BIO_new(BIO_s_socket());
	if (!ssl_bio) {
		debug_info("ERROR: Could not create SSL bio.");
		return ret;
	}
	BIO_set_fd(ssl_bio, (int)(long)connection->data, BIO_NOCLOSE);

	SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
	if (ssl_ctx == NULL) {
		debug_info("ERROR: Could not create SSL context.");
		BIO_free(ssl_bio);
		return ret;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	SSL_CTX_set_security_level(ssl_ctx, 0);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100002L || \
	(defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x2060000fL))
	/* force use of TLSv1 for older devices */
	if (connection->device->version < DEVICE_VERSION(10,0,0)) {
#ifdef SSL_OP_NO_TLSv1_1
		long opts = SSL_CTX_get_options(ssl_ctx);
		opts |= SSL_OP_NO_TLSv1_1;
#ifdef SSL_OP_NO_TLSv1_2
		opts |= SSL_OP_NO_TLSv1_2;
#endif
#ifdef SSL_OP_NO_TLSv1_3
		opts |= SSL_OP_NO_TLSv1_3;
#endif
		SSL_CTX_set_options(ssl_ctx, opts);
#endif
	}
#else
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION);
	if (connection->device->version < DEVICE_VERSION(10,0,0)) {
		SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_VERSION);
	}
#endif

	BIO* membp;
	X509* rootCert = NULL;
	membp = BIO_new_mem_buf(root_cert.data, root_cert.size);
	PEM_read_bio_X509(membp, &rootCert, NULL, NULL);
	BIO_free(membp);
	if (SSL_CTX_use_certificate(ssl_ctx, rootCert) != 1) {
		debug_info("WARNING: Could not load RootCertificate");
	}
	X509_free(rootCert);
	free(root_cert.data);

	RSA* rootPrivKey = NULL;
	membp = BIO_new_mem_buf(root_privkey.data, root_privkey.size);
	PEM_read_bio_RSAPrivateKey(membp, &rootPrivKey, NULL, NULL);
	BIO_free(membp);
	if (SSL_CTX_use_RSAPrivateKey(ssl_ctx, rootPrivKey) != 1) {
		debug_info("WARNING: Could not load RootPrivateKey");
	}
	RSA_free(rootPrivKey);
	free(root_privkey.data);

	SSL *ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		debug_info("ERROR: Could not create SSL object");
		BIO_free(ssl_bio);
		SSL_CTX_free(ssl_ctx);
		return ret;
	}
	SSL_set_connect_state(ssl);
	SSL_set_verify(ssl, 0, ssl_verify_callback);
	SSL_set_bio(ssl, ssl_bio, ssl_bio);

	debug_info("Performing SSL handshake");
	int ssl_error = 0;
	do {
		ssl_error = SSL_get_error(ssl, SSL_do_handshake(ssl));
		if (ssl_error == 0 || ssl_error != SSL_ERROR_WANT_READ) {
			break;
		}
#ifdef WIN32
		Sleep(100);
#else
		struct timespec ts = { 0, 100000000 };
		nanosleep(&ts, NULL);
#endif
	} while (1);
	if (ssl_error != 0) {
		debug_info("ERROR during SSL handshake: %s", ssl_error_to_string(ssl_error));
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
	} else {
		ssl_data_t ssl_data_loc = (ssl_data_t)malloc(sizeof(struct ssl_data_private));
		ssl_data_loc->session = ssl;
		ssl_data_loc->ctx = ssl_ctx;
		connection->ssl_data = ssl_data_loc;
		ret = IDEVICE_E_SUCCESS;
		debug_info("SSL mode enabled, %s, cipher: %s", SSL_get_version(ssl), SSL_get_cipher(ssl));
	}
	/* required for proper multi-thread clean up to prevent leaks */
	openssl_remove_thread_state();
#else
	ssl_data_t ssl_data_loc = (ssl_data_t)malloc(sizeof(struct ssl_data_private));

	/* Set up GnuTLS... */
	debug_info("enabling SSL mode");
	errno = 0;
	gnutls_certificate_allocate_credentials(&ssl_data_loc->certificate);
#if GNUTLS_VERSION_NUMBER >= 0x020b07
	gnutls_certificate_set_retrieve_function(ssl_data_loc->certificate, internal_cert_callback);
#else
	gnutls_certificate_client_set_retrieve_function(ssl_data_loc->certificate, internal_cert_callback);
#endif
	gnutls_init(&ssl_data_loc->session, GNUTLS_CLIENT);
	gnutls_priority_set_direct(ssl_data_loc->session, "NONE:+VERS-TLS1.0:+ANON-DH:+RSA:+AES-128-CBC:+AES-256-CBC:+SHA1:+MD5:+COMP-NULL", NULL);
	gnutls_credentials_set(ssl_data_loc->session, GNUTLS_CRD_CERTIFICATE, ssl_data_loc->certificate);
	gnutls_session_set_ptr(ssl_data_loc->session, ssl_data_loc);

	gnutls_x509_crt_init(&ssl_data_loc->root_cert);
	gnutls_x509_crt_init(&ssl_data_loc->host_cert);
	gnutls_x509_privkey_init(&ssl_data_loc->root_privkey);
	gnutls_x509_privkey_init(&ssl_data_loc->host_privkey);

	pair_record_import_crt_with_name(pair_record, USERPREF_ROOT_CERTIFICATE_KEY, ssl_data_loc->root_cert);
	pair_record_import_crt_with_name(pair_record, USERPREF_HOST_CERTIFICATE_KEY, ssl_data_loc->host_cert);
	pair_record_import_key_with_name(pair_record, USERPREF_ROOT_PRIVATE_KEY_KEY, ssl_data_loc->root_privkey);
	pair_record_import_key_with_name(pair_record, USERPREF_HOST_PRIVATE_KEY_KEY, ssl_data_loc->host_privkey);

	if (pair_record)
		plist_free(pair_record);

	debug_info("GnuTLS step 1...");
	gnutls_transport_set_ptr(ssl_data_loc->session, (gnutls_transport_ptr_t)connection);
	debug_info("GnuTLS step 2...");
	gnutls_transport_set_push_function(ssl_data_loc->session, (gnutls_push_func) & internal_ssl_write);
	debug_info("GnuTLS step 3...");
	gnutls_transport_set_pull_function(ssl_data_loc->session, (gnutls_pull_func) & internal_ssl_read);
	debug_info("GnuTLS step 4 -- now handshaking...");
	if (errno) {
		debug_info("WARNING: errno says %s before handshake!", strerror(errno));
	}

	int return_me = 0;
	do {
		return_me = gnutls_handshake(ssl_data_loc->session);
	} while(return_me == GNUTLS_E_AGAIN || return_me == GNUTLS_E_INTERRUPTED);

	debug_info("GnuTLS handshake done...");

	if (return_me != GNUTLS_E_SUCCESS) {
		internal_ssl_cleanup(ssl_data_loc);
		free(ssl_data_loc);
		debug_info("GnuTLS reported something wrong: %s", gnutls_strerror(return_me));
		debug_info("oh.. errno says %s", strerror(errno));
	} else {
		connection->ssl_data = ssl_data_loc;
		ret = IDEVICE_E_SUCCESS;
		debug_info("SSL mode enabled");
	}
#endif
	return ret;
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_disable_ssl(idevice_connection_t connection)
{
	return idevice_connection_disable_bypass_ssl(connection, 0);
}

LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_disable_bypass_ssl(idevice_connection_t connection, uint8_t sslBypass)
{
	if (!connection)
		return IDEVICE_E_INVALID_ARG;
	if (!connection->ssl_data) {
		/* ignore if ssl is not enabled */
		return IDEVICE_E_SUCCESS;
	}

	// some services require plain text communication after SSL handshake
	// sending out SSL_shutdown will cause bytes
	if (!sslBypass) {
#ifdef HAVE_OPENSSL
		if (connection->ssl_data->session) {
			/* see: https://www.openssl.org/docs/ssl/SSL_shutdown.html#RETURN_VALUES */
			if (SSL_shutdown(connection->ssl_data->session) == 0) {
				/* Only try bidirectional shutdown if we know it can complete */
				int ssl_error;
				if ((ssl_error = SSL_get_error(connection->ssl_data->session, 0)) == SSL_ERROR_NONE) {
					SSL_shutdown(connection->ssl_data->session);
				} else  {
					debug_info("Skipping bidirectional SSL shutdown. SSL error code: %i\n", ssl_error);
				}
			}
		}
#else
		if (connection->ssl_data->session) {
			gnutls_bye(connection->ssl_data->session, GNUTLS_SHUT_RDWR);
		}
#endif
	}

	internal_ssl_cleanup(connection->ssl_data);
	free(connection->ssl_data);
	connection->ssl_data = NULL;

	debug_info("SSL mode disabled");

	return IDEVICE_E_SUCCESS;
}
