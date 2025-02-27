/*
 * idevice.c
 * Device discovery and communication interface.
 *
 * Copyright (c) 2009-2021 Nikias Bassen. All Rights Reserved.
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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <usbmuxd.h>

#if defined(HAVE_OPENSSL)
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#elif defined(HAVE_GNUTLS)
#include <gnutls/gnutls.h>
#elif defined(HAVE_MBEDTLS)
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#else
#error No supported TLS/SSL library enabled
#endif

#include <libimobiledevice-glue/socket.h>
#include <libimobiledevice-glue/thread.h>

#include "idevice.h"
#include "lockdown.h"
#include "common/userpref.h"
#include "common/debug.h"

#ifndef ECONNREFUSED
#define ECONNREFUSED 107
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

// Reference: https://stackoverflow.com/a/2390626/1806760
// Initializer/finalizer sample for MSVC and GCC/Clang.
// 2010-2016 Joe Lowe. Released into the public domain.

#ifdef __cplusplus
    #define INITIALIZER(f) \
        static void f(void); \
        struct f##_t_ { f##_t_(void) { f(); } }; static f##_t_ f##_; \
        static void f(void)
#elif defined(_MSC_VER)
    #pragma section(".CRT$XCU",read)
    #define INITIALIZER2_(f,p) \
        static void f(void); \
        __declspec(allocate(".CRT$XCU")) void (*f##_)(void) = f; \
        __pragma(comment(linker,"/include:" p #f "_")) \
        static void f(void)
    #ifdef _WIN64
        #define INITIALIZER(f) INITIALIZER2_(f,"")
    #else
        #define INITIALIZER(f) INITIALIZER2_(f,"_")
    #endif
#else
    #define INITIALIZER(f) \
        static void f(void) __attribute__((__constructor__)); \
        static void f(void)
#endif

static void internal_idevice_deinit(void)
{
#if defined(HAVE_OPENSSL)
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
#elif defined(HAVE_GNUTLS)
	gnutls_global_deinit();
#elif defined(HAVE_MBEDTLS)
	// NO-OP
#endif
}

INITIALIZER(internal_idevice_init)
{
#if defined(HAVE_OPENSSL)
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
#elif defined(HAVE_GNUTLS)
	gnutls_global_init();
#elif defined(HAVE_MBEDTLS)
	// NO-OP
#endif
	atexit(internal_idevice_deinit);
}

const char* libimobiledevice_version()
{
#ifndef PACKAGE_VERSION
#error PACKAGE_VERSION is not defined!
#endif
	return PACKAGE_VERSION;
}

struct idevice_subscription_context {
	idevice_event_cb_t callback;
	void *user_data;
	usbmuxd_subscription_context_t ctx;
};

static idevice_subscription_context_t event_ctx = NULL;

static void usbmux_event_cb(const usbmuxd_event_t *event, void *user_data)
{
	idevice_subscription_context_t context = (idevice_subscription_context_t)user_data;
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

	if (context->callback) {
		context->callback(&ev, context->user_data);
	}
}

idevice_error_t idevice_events_subscribe(idevice_subscription_context_t *context, idevice_event_cb_t callback, void *user_data)
{
	if (!context || !callback) {
		return IDEVICE_E_INVALID_ARG;
	}
	*context = malloc(sizeof(struct idevice_subscription_context));
	if (!*context) {
		debug_info("ERROR: %s: Failed to allocate subscription context\n", __func__);
		return IDEVICE_E_UNKNOWN_ERROR;
	}
	(*context)->callback = callback;
	(*context)->user_data = user_data;
	int res = usbmuxd_events_subscribe(&(*context)->ctx, usbmux_event_cb, *context);
	if (res != 0) {
		free(*context);
		*context = NULL;
		debug_info("ERROR: usbmuxd_subscribe() returned %d!", res);
		return IDEVICE_E_UNKNOWN_ERROR;
	}
	return IDEVICE_E_SUCCESS;
}

idevice_error_t idevice_events_unsubscribe(idevice_subscription_context_t context)
{
	if (!context) {
		return IDEVICE_E_INVALID_ARG;
	}
	int res = usbmuxd_events_unsubscribe(context->ctx);
	if (res != 0) {
		debug_info("ERROR: usbmuxd_unsubscribe() returned %d!", res);
		return IDEVICE_E_UNKNOWN_ERROR;
	}
	if (context == event_ctx) {
		event_ctx = NULL;
	}
	free(context);
	return IDEVICE_E_SUCCESS;
}

idevice_error_t idevice_event_subscribe(idevice_event_cb_t callback, void *user_data)
{
	if (event_ctx) {
		idevice_events_unsubscribe(event_ctx);
	}
	return idevice_events_subscribe(&event_ctx, callback, user_data);
}

idevice_error_t idevice_event_unsubscribe(void)
{
	if (!event_ctx) {
		return IDEVICE_E_SUCCESS;
	}
	event_ctx->callback = NULL;
	return idevice_events_unsubscribe(event_ctx);
}

idevice_error_t idevice_get_device_list_extended(idevice_info_t **devices, int *count)
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
			struct sockaddr* saddr = (struct sockaddr*)(dev_list[i].conn_data);
			size_t addrlen = 0;
			switch (saddr->sa_family) {
				case AF_INET:
					addrlen = sizeof(struct sockaddr_in);
					break;
#ifdef AF_INET6
				case AF_INET6:
					addrlen = sizeof(struct sockaddr_in6);
					break;
#endif
				default:
					debug_info("Unsupported address family 0x%02x\n", saddr->sa_family);
					continue;
			}
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

idevice_error_t idevice_device_list_extended_free(idevice_info_t *devices)
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

idevice_error_t idevice_get_device_list(char ***devices, int *count)
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

idevice_error_t idevice_device_list_free(char **devices)
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

void idevice_set_debug_level(int level)
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
	device->device_class = 0;
	switch (muxdev->conn_type) {
	case CONNECTION_TYPE_USB:
		device->conn_type = CONNECTION_USBMUXD;
		device->conn_data = NULL;
		break;
	case CONNECTION_TYPE_NETWORK:
		device->conn_type = CONNECTION_NETWORK;
		struct sockaddr* saddr = (struct sockaddr*)(muxdev->conn_data);
		size_t addrlen = 0;
		switch (saddr->sa_family) {
			case AF_INET:
				addrlen = sizeof(struct sockaddr_in);
				break;
#ifdef AF_INET6
			case AF_INET6:
				addrlen = sizeof(struct sockaddr_in6);
				break;
#endif
			default:
				debug_info("Unsupported address family 0x%02x\n", saddr->sa_family);
				free(device->udid);
				free(device);
				return NULL;
		}
		device->conn_data = malloc(addrlen);
		memcpy(device->conn_data, muxdev->conn_data, addrlen);
		break;
	default:
		device->conn_type = 0;
		device->conn_data = NULL;
		break;
	}
	return device;
}

idevice_error_t idevice_new_with_options(idevice_t * device, const char *udid, enum idevice_options options)
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

idevice_error_t idevice_new(idevice_t * device, const char *udid)
{
	return idevice_new_with_options(device, udid, 0);
}

idevice_error_t idevice_free(idevice_t device)
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

idevice_error_t idevice_connect(idevice_t device, uint16_t port, idevice_connection_t *connection)
{
	if (!device) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (device->conn_type == CONNECTION_USBMUXD) {
		int sfd = usbmuxd_connect(device->mux_id, port);
		if (sfd < 0) {
			debug_info("ERROR: Connecting to usbmux device failed: %d (%s)", sfd, strerror(-sfd));
			switch (-sfd) {
			case ECONNREFUSED:
				return IDEVICE_E_CONNREFUSED;
			case ENODEV:
				return IDEVICE_E_NO_DEVICE;
			default:
				break;
			}
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		idevice_connection_t new_connection = (idevice_connection_t)malloc(sizeof(struct idevice_connection_private));
		new_connection->type = CONNECTION_USBMUXD;
		new_connection->data = (void*)(uintptr_t)sfd;
		new_connection->ssl_data = NULL;
		new_connection->device = device;
		new_connection->ssl_recv_timeout = (unsigned int)-1;
		new_connection->status = IDEVICE_E_SUCCESS;
		*connection = new_connection;
		return IDEVICE_E_SUCCESS;
	}
	if (device->conn_type == CONNECTION_NETWORK) {
		struct sockaddr* saddr = (struct sockaddr*)(device->conn_data);
		switch (saddr->sa_family) {
			case AF_INET:
#ifdef AF_INET6
			case AF_INET6:
#endif
				break;
			default:
				debug_info("Unsupported address family 0x%02x", saddr->sa_family);
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
			int result = errno;
			debug_info("ERROR: Connecting to network device failed: %d (%s)", result, strerror(result));
			switch (result) {
			case ECONNREFUSED:
				return IDEVICE_E_CONNREFUSED;
			default:
				break;
			}
			return IDEVICE_E_NO_DEVICE;
		}

		idevice_connection_t new_connection = (idevice_connection_t)malloc(sizeof(struct idevice_connection_private));
		new_connection->type = CONNECTION_NETWORK;
		new_connection->data = (void*)(uintptr_t)sfd;
		new_connection->ssl_data = NULL;
		new_connection->device = device;
		new_connection->ssl_recv_timeout = (unsigned int)-1;

		*connection = new_connection;

		return IDEVICE_E_SUCCESS;
	}

	debug_info("Unknown connection type %d", device->conn_type);
	return IDEVICE_E_UNKNOWN_ERROR;
}

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
		usbmuxd_disconnect((int)(uintptr_t)connection->data);
		connection->data = NULL;
		result = IDEVICE_E_SUCCESS;
	} else if (connection->type == CONNECTION_NETWORK) {
		socket_close((int)(uintptr_t)connection->data);
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
		int res;
		do {
			res = usbmuxd_send((int)(uintptr_t)connection->data, data, len, sent_bytes);
		} while (res == -EAGAIN);
		if (res < 0) {
			debug_info("ERROR: usbmuxd_send returned %d (%s)", res, strerror(-res));
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		return IDEVICE_E_SUCCESS;
	}
	if (connection->type == CONNECTION_NETWORK) {
		int s = socket_send((int)(uintptr_t)connection->data, (void*)data, len);
		if (s < 0) {
			*sent_bytes = 0;
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		*sent_bytes = s;
		return IDEVICE_E_SUCCESS;
	}

	debug_info("Unknown connection type %d", connection->type);
	return IDEVICE_E_UNKNOWN_ERROR;

}

idevice_error_t idevice_connection_send(idevice_connection_t connection, const char *data, uint32_t len, uint32_t *sent_bytes)
{
	if (!connection || !data
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
		|| (connection->ssl_data && !connection->ssl_data->session)
#endif
	) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->ssl_data) {
		connection->status = IDEVICE_E_SUCCESS;
		uint32_t sent = 0;
		while (sent < len) {
#if defined(HAVE_OPENSSL)
			int s = SSL_write(connection->ssl_data->session, (const void*)(data+sent), (int)(len-sent));
			if (s <= 0) {
				int sslerr = SSL_get_error(connection->ssl_data->session, s);
				if (sslerr == SSL_ERROR_WANT_WRITE) {
					continue;
				}
				break;
			}
#elif defined(HAVE_GNUTLS)
			ssize_t s = gnutls_record_send(connection->ssl_data->session, (void*)(data+sent), (size_t)(len-sent));
#elif defined(HAVE_MBEDTLS)
			int s = mbedtls_ssl_write(&connection->ssl_data->ctx, (const unsigned char*)(data+sent), (size_t)(len-sent));
#endif
			if (s < 0) {
				break;
			}
			sent += s;
		}
		debug_info("SSL_write %d, sent %d", len, sent);
		if (sent < len) {
			*sent_bytes = 0;
			return connection->status == IDEVICE_E_SUCCESS ? IDEVICE_E_SSL_ERROR : connection->status;
		}
		*sent_bytes = sent;
		return IDEVICE_E_SUCCESS;
	}
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
		*sent_bytes = sent;
		if (sent == 0) {
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		return IDEVICE_E_NOT_ENOUGH_DATA;
	}
	*sent_bytes = sent;
	return IDEVICE_E_SUCCESS;
}

static inline idevice_error_t socket_recv_to_idevice_error(int conn_error, uint32_t len, uint32_t received)
{
	if (conn_error < 0) {
		switch (conn_error) {
			case -EAGAIN:
				if (len) {
					debug_info("ERROR: received partial data %d/%d (%s)", received, len, strerror(-conn_error));
				} else {
					debug_info("ERROR: received partial data (%s)", strerror(-conn_error));
				}
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
		int conn_error = usbmuxd_recv_timeout((int)(uintptr_t)connection->data, data, len, recv_bytes, timeout);
		idevice_error_t error = socket_recv_to_idevice_error(conn_error, len, *recv_bytes);
		if (error == IDEVICE_E_UNKNOWN_ERROR) {
			debug_info("ERROR: usbmuxd_recv_timeout returned %d (%s)", conn_error, strerror(-conn_error));
		}
		return error;
	}
	if (connection->type == CONNECTION_NETWORK) {
		int res = socket_receive_timeout((int)(uintptr_t)connection->data, data, len, 0, timeout);
		idevice_error_t error = socket_recv_to_idevice_error(res, 0, 0);
		if (error == IDEVICE_E_SUCCESS) {
			*recv_bytes = (uint32_t)res;
		} else if (error == IDEVICE_E_UNKNOWN_ERROR) {
			debug_info("ERROR: socket_receive_timeout returned %d (%s)", res, strerror(-res));
		}
		return error;
	}

	debug_info("Unknown connection type %d", connection->type);
	return IDEVICE_E_UNKNOWN_ERROR;
}

idevice_error_t idevice_connection_receive_timeout(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout)
{
	if (!connection
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
		|| (connection->ssl_data && !connection->ssl_data->session)
#endif
		|| len == 0
	) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->ssl_data) {
		uint32_t received = 0;

		if (connection->ssl_recv_timeout != (unsigned int)-1) {
			debug_info("WARNING: ssl_recv_timeout was not properly reset in idevice_connection_receive_timeout");
		}

		// this should be reset after the SSL_read call on all codepaths, as
		// the supplied timeout should only apply to the current read.
		connection->ssl_recv_timeout = timeout;
		connection->status = IDEVICE_E_SUCCESS;
		while (received < len) {
#if defined(HAVE_OPENSSL)
			int r = SSL_read(connection->ssl_data->session, (void*)((char*)(data+received)), (int)len-received);
			if (r > 0) {
				received += r;
			} else {
				int sslerr = SSL_get_error(connection->ssl_data->session, r);
				if (sslerr == SSL_ERROR_WANT_READ) {
					continue;
				} else if (sslerr == SSL_ERROR_ZERO_RETURN) {
					if (connection->status == IDEVICE_E_TIMEOUT) {
						SSL_set_shutdown(connection->ssl_data->session, 0);
					}
				}
				break;
			}
#elif defined(HAVE_GNUTLS)
			ssize_t r = gnutls_record_recv(connection->ssl_data->session, (void*)(data+received), (size_t)len-received);
			if (r > 0) {
				received += r;
			} else {
				break;
			}
#elif defined(HAVE_MBEDTLS)
			int r = mbedtls_ssl_read(&connection->ssl_data->ctx, (void*)(data+received), (size_t)len-received);
			if (r > 0) {
				received += r;
			} else {
				break;
			}
#endif
		}
		connection->ssl_recv_timeout = (unsigned int)-1;

		debug_info("SSL_read %d, received %d", len, received);
		if (received < len) {
			*recv_bytes = received;
			return connection->status == IDEVICE_E_SUCCESS ? IDEVICE_E_SSL_ERROR : connection->status;
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
		int res = usbmuxd_recv((int)(uintptr_t)connection->data, data, len, recv_bytes);
		if (res < 0) {
			debug_info("ERROR: usbmuxd_recv returned %d (%s)", res, strerror(-res));
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		return IDEVICE_E_SUCCESS;
	}
	if (connection->type == CONNECTION_NETWORK) {
		int res = socket_receive((int)(uintptr_t)connection->data, data, len);
		if (res < 0) {
			debug_info("ERROR: socket_receive returned %d (%s)", res, strerror(-res));
			return IDEVICE_E_UNKNOWN_ERROR;
		}
		*recv_bytes = (uint32_t)res;
		return IDEVICE_E_SUCCESS;
	}

	debug_info("Unknown connection type %d", connection->type);
	return IDEVICE_E_UNKNOWN_ERROR;
}

idevice_error_t idevice_connection_receive(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes)
{
	if (!connection
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
		|| (connection->ssl_data && !connection->ssl_data->session)
#endif
	) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->ssl_data) {
		if (connection->ssl_recv_timeout != (unsigned int)-1) {
			debug_info("WARNING: ssl_recv_timeout was not properly reset in idevice_connection_receive_timeout");
			connection->ssl_recv_timeout = (unsigned int)-1;
		}
#if defined(HAVE_OPENSSL)
		int received = SSL_read(connection->ssl_data->session, (void*)data, (int)len);
		debug_info("SSL_read %d, received %d", len, received);
#elif defined(HAVE_GNUTLS)
		ssize_t received = gnutls_record_recv(connection->ssl_data->session, (void*)data, (size_t)len);
#elif defined(HAVE_MBEDTLS)
		int received = mbedtls_ssl_read(&connection->ssl_data->ctx, (unsigned char*)data, (size_t)len);
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

idevice_error_t idevice_connection_get_fd(idevice_connection_t connection, int *fd)
{
	if (!connection || !fd) {
		return IDEVICE_E_INVALID_ARG;
	}

	if (connection->type == CONNECTION_USBMUXD) {
		*fd = (int)(uintptr_t)connection->data;
		return IDEVICE_E_SUCCESS;
	}
	if (connection->type == CONNECTION_NETWORK) {
		*fd = (int)(uintptr_t)connection->data;
		return IDEVICE_E_SUCCESS;
	}

	debug_info("Unknown connection type %d", connection->type);
	return IDEVICE_E_UNKNOWN_ERROR;
}

idevice_error_t idevice_get_handle(idevice_t device, uint32_t *handle)
{
	if (!device || !handle)
		return IDEVICE_E_INVALID_ARG;

	*handle = device->mux_id;
	return IDEVICE_E_SUCCESS;
}

idevice_error_t idevice_get_udid(idevice_t device, char **udid)
{
	if (!device || !udid)
		return IDEVICE_E_INVALID_ARG;

	if (device->udid) {
		*udid = strdup(device->udid);
	}
	return IDEVICE_E_SUCCESS;
}

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
typedef ssize_t ssl_cb_ret_type_t;
#elif defined(HAVE_MBEDTLS)
typedef int ssl_cb_ret_type_t;
#endif

/**
 * Internally used SSL callback function for receiving encrypted data.
 */
static ssl_cb_ret_type_t internal_ssl_read(idevice_connection_t connection, char *buffer, size_t length)
{
	uint32_t bytes = 0;
	uint32_t pos = 0;
	idevice_error_t res;
	unsigned int timeout = connection->ssl_recv_timeout;

	debug_info("pre-read length = %zi bytes", length);

	/* repeat until we have the full data or an error occurs */
	do {
		bytes = 0;
		if (timeout == (unsigned int)-1) {
			res = internal_connection_receive(connection, buffer + pos, (uint32_t)length - pos, &bytes);
		} else {
			res = internal_connection_receive_timeout(connection, buffer + pos, (uint32_t)length - pos, &bytes, (unsigned int)timeout);
		}
		if (res != IDEVICE_E_SUCCESS) {
			if (res != IDEVICE_E_TIMEOUT) {
				debug_info("ERROR: %s returned %d", (timeout == (unsigned int)-1) ? "internal_connection_receive" : "internal_connection_receive_timeout", res);
			}
			connection->status = res;
			return -1;
		}
		debug_info("read %i bytes", bytes);

		/* increase read count */
		pos += bytes;
		if (pos < (uint32_t)length) {
			debug_info("re-read trying to read missing %i bytes", (uint32_t)length - pos);
		}
	} while (pos < (uint32_t)length);

	debug_info("post-read received %i bytes", pos);

	return pos;
}

/**
 * Internally used SSL callback function for sending encrypted data.
 */
static ssl_cb_ret_type_t internal_ssl_write(idevice_connection_t connection, const char *buffer, size_t length)
{
	uint32_t bytes = 0;
	idevice_error_t res;
	debug_info("pre-send length = %zi bytes", length);
	if ((res = internal_connection_send(connection, buffer, length, &bytes)) != IDEVICE_E_SUCCESS) {
		debug_info("ERROR: internal_connection_send returned %d", res);
		connection->status = res;
		return -1;
	}
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

#if defined(HAVE_OPENSSL)
	if (ssl_data->session) {
		SSL_free(ssl_data->session);
	}
	if (ssl_data->ctx) {
		SSL_CTX_free(ssl_data->ctx);
	}
#elif defined(HAVE_GNUTLS)
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
#elif defined(HAVE_MBEDTLS)
	mbedtls_pk_free(&ssl_data->root_privkey);
	mbedtls_x509_crt_free(&ssl_data->certificate);
	mbedtls_entropy_free(&ssl_data->entropy);
	mbedtls_ctr_drbg_free(&ssl_data->ctr_drbg);
	mbedtls_ssl_config_free(&ssl_data->config);
	mbedtls_ssl_free(&ssl_data->ctx);
#endif
}

#ifdef HAVE_OPENSSL
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static long ssl_idevice_bio_callback(BIO *b, int oper, const char *argp, size_t len, int argi, long argl, int retvalue, size_t *processed)
#else
static long ssl_idevice_bio_callback(BIO *b, int oper, const char *argp, int argi, long argl, long retvalue)
#endif
{
	ssize_t bytes = 0;
	idevice_connection_t conn = (idevice_connection_t)BIO_get_callback_arg(b);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	size_t len = (size_t)argi;
	size_t *processed = (size_t*)&bytes;
#endif
	switch (oper) {
	case (BIO_CB_READ|BIO_CB_RETURN):
		if (argp) {
			bytes = internal_ssl_read(conn, (char *)argp, len);
			*processed = bytes;
			return (long)bytes;
		}
		return 0;
	case (BIO_CB_PUTS|BIO_CB_RETURN):
		len = strlen(argp);
		// fallthrough
	case (BIO_CB_WRITE|BIO_CB_RETURN):
		bytes = internal_ssl_write(conn, argp, len);
		*processed = bytes;
		return (long)bytes;
	default:
		return retvalue;
	}
}

static BIO *ssl_idevice_bio_new(idevice_connection_t conn)
{
	BIO *b = BIO_new(BIO_s_null());
	if (!b) return NULL;
	BIO_set_callback_arg(b, (char *)conn);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	BIO_set_callback_ex(b, ssl_idevice_bio_callback);
#else
	BIO_set_callback(b, ssl_idevice_bio_callback);
#endif
	return b;
}

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

#if defined(HAVE_GNUTLS)
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
#elif defined(HAVE_MBEDTLS)
static void _mbedtls_log_cb(void* ctx, int level, const char* filename, int line, const char* message)
{
	fprintf(stderr, "[mbedtls][%d] %s:%d => %s", level, filename, line, message);
}

static int cert_verify_cb(void* ctx, mbedtls_x509_crt* cert, int depth, uint32_t *flags)
{
	*flags = 0;
	return 0;
}

static int _mbedtls_f_rng(void* p_rng, unsigned char* buf, size_t len)
{
	memset(buf, 4, len);
	return 0;
}
#endif

idevice_error_t idevice_connection_enable_ssl(idevice_connection_t connection)
{
	if (!connection || connection->ssl_data)
		return IDEVICE_E_INVALID_ARG;

	idevice_error_t ret = IDEVICE_E_SSL_ERROR;
	plist_t pair_record = NULL;

	userpref_error_t uerr = userpref_read_pair_record(connection->device->udid, &pair_record);
	if (uerr != USERPREF_E_SUCCESS) {
		debug_info("ERROR: Failed enabling SSL. Unable to read pair record for udid %s (%d)", connection->device->udid, uerr);
		return ret;
	}

#if defined(HAVE_OPENSSL)
	key_data_t root_cert = { NULL, 0 };
	key_data_t root_privkey = { NULL, 0 };

	pair_record_import_crt_with_name(pair_record, USERPREF_ROOT_CERTIFICATE_KEY, &root_cert);
	pair_record_import_key_with_name(pair_record, USERPREF_ROOT_PRIVATE_KEY_KEY, &root_privkey);

	if (pair_record)
		plist_free(pair_record);

	BIO *ssl_bio = ssl_idevice_bio_new(connection);
	if (!ssl_bio) {
		debug_info("ERROR: Could not create SSL bio.");
		return ret;
	}

	SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
	if (ssl_ctx == NULL) {
		debug_info("ERROR: Could not create SSL context.");
		BIO_free(ssl_bio);
		return ret;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER) || \
	(defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER >= 0x3060000fL))
	SSL_CTX_set_security_level(ssl_ctx, 0);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100002L || \
	(defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x2060000fL))
	/* force use of TLSv1 for older devices */
	if (connection->device->version < DEVICE_VERSION(10,0,0)) {
#ifdef SSL_OP_NO_TLSv1_1
		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_1);
#endif
#ifdef SSL_OP_NO_TLSv1_2
		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);
#endif
#ifdef SSL_OP_NO_TLSv1_3
		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_3);
#endif
	}
#else
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION);
	if (connection->device->version < DEVICE_VERSION(10,0,0)) {
		SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_VERSION);
		if (connection->device->version == 0) {
			/*
				iOS 1 doesn't understand TLS1_VERSION, it can only speak SSL3_VERSION.
				However, modern OpenSSL is usually compiled without SSLv3 support.
				So if we set min_proto_version to SSL3_VERSION on an OpenSSL instance which doesn't support it,
				it will just ignore min_proto_version altogether and fall back to an even higher version.
				To avoid accidentally breaking iOS 2.0+, we set min version to 0 instead.
				Here is what documentation says:
					Setting the minimum or maximum version to 0,
					will enable protocol versions down to the lowest version,
					or up to the highest version supported by the library, respectively.
			*/
			SSL_CTX_set_min_proto_version(ssl_ctx, 0);
		}
	}
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#if defined(SSL_OP_IGNORE_UNEXPECTED_EOF)
	/*
	 * For OpenSSL 3 and later, mark close_notify alerts as optional.
	 * For prior versions of OpenSSL we check for SSL_ERROR_SYSCALL when
	 * reading instead (this error changes to SSL_ERROR_SSL in OpenSSL 3).
	 */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
#if defined(SSL_OP_LEGACY_SERVER_CONNECT)
	/*
	 * Without setting SSL_OP_LEGACY_SERVER_CONNECT, OpenSSL 3 fails with
	 * error "unsafe legacy renegotiation disabled" when talking to iOS 5
	 */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_LEGACY_SERVER_CONNECT);
#endif
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY* rootPrivKey = NULL;
	membp = BIO_new_mem_buf(root_privkey.data, root_privkey.size);
	PEM_read_bio_PrivateKey(membp, &rootPrivKey, NULL, NULL);
	BIO_free(membp);
	if (SSL_CTX_use_PrivateKey(ssl_ctx, rootPrivKey) != 1) {
		debug_info("WARNING: Could not load RootPrivateKey");
	}
	EVP_PKEY_free(rootPrivKey);
#else
	RSA* rootPrivKey = NULL;
	membp = BIO_new_mem_buf(root_privkey.data, root_privkey.size);
	PEM_read_bio_RSAPrivateKey(membp, &rootPrivKey, NULL, NULL);
	BIO_free(membp);
	if (SSL_CTX_use_RSAPrivateKey(ssl_ctx, rootPrivKey) != 1) {
		debug_info("WARNING: Could not load RootPrivateKey");
	}
	RSA_free(rootPrivKey);
#endif
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
#ifdef _WIN32
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
#elif defined(HAVE_GNUTLS)
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
#elif defined(HAVE_MBEDTLS)
	key_data_t root_cert = { NULL, 0 };
	key_data_t root_privkey = { NULL, 0 };

	pair_record_import_crt_with_name(pair_record, USERPREF_ROOT_CERTIFICATE_KEY, &root_cert);
	pair_record_import_key_with_name(pair_record, USERPREF_ROOT_PRIVATE_KEY_KEY, &root_privkey);

	plist_free(pair_record);

	ssl_data_t ssl_data_loc = (ssl_data_t)malloc(sizeof(struct ssl_data_private));

	mbedtls_ssl_init(&ssl_data_loc->ctx);
	mbedtls_ssl_config_init(&ssl_data_loc->config);
	mbedtls_entropy_init(&ssl_data_loc->entropy);
	mbedtls_ctr_drbg_init(&ssl_data_loc->ctr_drbg);

	int r = mbedtls_ctr_drbg_seed(&ssl_data_loc->ctr_drbg, mbedtls_entropy_func, &ssl_data_loc->entropy, NULL, 0);
	if (r != 0) {
		debug_info("ERROR: [mbedtls] mbedtls_ctr_drbg_seed failed: %d", r);
		return ret;
	}

	if (mbedtls_ssl_config_defaults(&ssl_data_loc->config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
		debug_info("ERROR: [mbedtls] Failed to set config defaults");
		return ret;
	}

	mbedtls_ssl_conf_rng(&ssl_data_loc->config, mbedtls_ctr_drbg_random, &ssl_data_loc->ctr_drbg);

	mbedtls_ssl_conf_dbg(&ssl_data_loc->config, _mbedtls_log_cb, NULL);

	mbedtls_ssl_conf_verify(&ssl_data_loc->config, cert_verify_cb, NULL);

	mbedtls_ssl_setup(&ssl_data_loc->ctx, &ssl_data_loc->config);

	mbedtls_ssl_set_bio(&ssl_data_loc->ctx, connection, (mbedtls_ssl_send_t*)&internal_ssl_write, (mbedtls_ssl_recv_t*)&internal_ssl_read, NULL);

	mbedtls_x509_crt_init(&ssl_data_loc->certificate);

	int crterr = mbedtls_x509_crt_parse(&ssl_data_loc->certificate, root_cert.data, root_cert.size);
	if (crterr < 0) {
		debug_info("ERROR: [mbedtls] parsing root cert failed: %d", crterr);
		return ret;
	}

	mbedtls_ssl_conf_ca_chain(&ssl_data_loc->config, &ssl_data_loc->certificate, NULL);

	mbedtls_pk_init(&ssl_data_loc->root_privkey);

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
	int pkerr = mbedtls_pk_parse_key(&ssl_data_loc->root_privkey, root_privkey.data, root_privkey.size, NULL, 0, &_mbedtls_f_rng, NULL);
#else
	int pkerr = mbedtls_pk_parse_key(&ssl_data_loc->root_privkey, root_privkey.data, root_privkey.size, NULL, 0);
#endif
	if (pkerr < 0) {
		debug_info("ERROR: [mbedtls] parsing private key failed: %d (size=%d)", pkerr, root_privkey.size);
		return ret;
	}

	mbedtls_ssl_conf_own_cert(&ssl_data_loc->config, &ssl_data_loc->certificate, &ssl_data_loc->root_privkey);

	int return_me = 0;
	do {
		return_me = mbedtls_ssl_handshake(&ssl_data_loc->ctx);
	} while (return_me == MBEDTLS_ERR_SSL_WANT_READ || return_me == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (return_me != 0) {
		debug_info("ERROR during SSL handshake: %d", return_me);
		internal_ssl_cleanup(ssl_data_loc);
		free(ssl_data_loc);
	} else {
		connection->ssl_data = ssl_data_loc;
		ret = IDEVICE_E_SUCCESS;
		debug_info("SSL mode enabled, %s, cipher: %s", mbedtls_ssl_get_version(&ssl_data_loc->ctx), mbedtls_ssl_get_ciphersuite(&ssl_data_loc->ctx));
		debug_info("SSL mode enabled");
	}
#endif
	return ret;
}

idevice_error_t idevice_connection_disable_ssl(idevice_connection_t connection)
{
	return idevice_connection_disable_bypass_ssl(connection, 0);
}

idevice_error_t idevice_connection_disable_bypass_ssl(idevice_connection_t connection, uint8_t sslBypass)
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
#if defined(HAVE_OPENSSL)
		if (connection->ssl_data->session) {
			/* see: https://www.openssl.org/docs/ssl/SSL_shutdown.html#RETURN_VALUES */
			if (SSL_shutdown(connection->ssl_data->session) == 0) {
				/* Only try bidirectional shutdown if we know it can complete */
				int ssl_error;
				if ((ssl_error = SSL_get_error(connection->ssl_data->session, 0)) == SSL_ERROR_NONE) {
					SSL_shutdown(connection->ssl_data->session);
				} else  {
					debug_info("Skipping bidirectional SSL shutdown. SSL error code: %i", ssl_error);
				}
			}
		}
#elif defined(HAVE_GNUTLS)
		if (connection->ssl_data->session) {
			gnutls_bye(connection->ssl_data->session, GNUTLS_SHUT_RDWR);
		}
#elif defined(HAVE_MBEDTLS)
		mbedtls_ssl_close_notify(&connection->ssl_data->ctx);
#endif
	}

	internal_ssl_cleanup(connection->ssl_data);
	free(connection->ssl_data);
	connection->ssl_data = NULL;

	debug_info("SSL mode disabled");

	return IDEVICE_E_SUCCESS;
}
