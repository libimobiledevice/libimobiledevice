/**
 * @file libimobiledevice/libimobiledevice.h
 * @brief Device/Connection handling and communication
 * \internal
 *
 * Copyright (c) 2010-2019 Nikias Bassen All Rights Reserved.
 * Copyright (c) 2010-2014 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2014 Christophe Fergeau All Rights Reserved.
 * Copyright (c) 2008 Jonathan Beck All Rights Reserved.
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

#ifndef IMOBILEDEVICE_H
#define IMOBILEDEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <plist/plist.h>

#if defined(_MSC_VER)
#include <basetsd.h>
typedef SSIZE_T ssize_t;
#endif

#ifndef LIBIMOBILEDEVICE_API
  #ifdef LIBIMOBILEDEVICE_STATIC
    #define LIBIMOBILEDEVICE_API
  #elif defined(_WIN32)
    #define LIBIMOBILEDEVICE_API __declspec(dllimport)
  #else
    #define LIBIMOBILEDEVICE_API
  #endif
#endif

/** Error Codes */
typedef enum {
	IDEVICE_E_SUCCESS         =  0,
	IDEVICE_E_INVALID_ARG     = -1,
	IDEVICE_E_UNKNOWN_ERROR   = -2,
	IDEVICE_E_NO_DEVICE       = -3,
	IDEVICE_E_NOT_ENOUGH_DATA = -4,
	IDEVICE_E_CONNREFUSED     = -5,
	IDEVICE_E_SSL_ERROR       = -6,
	IDEVICE_E_TIMEOUT         = -7
} idevice_error_t;

typedef struct idevice_private idevice_private; /**< \private */
typedef idevice_private *idevice_t; /**< The device handle. */

typedef struct idevice_connection_private idevice_connection_private; /**< \private */
typedef idevice_connection_private *idevice_connection_t; /**< The connection handle. */

/** Options for idevice_new_with_options() */
enum idevice_options {
	IDEVICE_LOOKUP_USBMUX = 1 << 1,  /**< include USBMUX devices during lookup */
	IDEVICE_LOOKUP_NETWORK = 1 << 2, /**< include network devices during lookup */
	IDEVICE_LOOKUP_PREFER_NETWORK = 1 << 3 /**< prefer network connection if device is available via USBMUX *and* network */
};

/** Type of connection a device is available on */
enum idevice_connection_type {
	CONNECTION_USBMUXD = 1, /**< device is available via USBMUX */
	CONNECTION_NETWORK /**< device is available via network */
};

/** Device information returned by #idevice_get_device_list_extended API */
struct idevice_info {
	char *udid; /**< UDID of the device */
	enum idevice_connection_type conn_type; /**< Type of connection the device is available on */
	void* conn_data; /**< Connection data, depending on the connection type */
};
typedef struct idevice_info* idevice_info_t;

/* discovery (events/asynchronous) */
/** The event type for device add or removal */
enum idevice_event_type {
	IDEVICE_DEVICE_ADD = 1, /**< device was added */
	IDEVICE_DEVICE_REMOVE, /**< device was removed */
	IDEVICE_DEVICE_PAIRED /**< device completed pairing process */
};

/* event data structure */
/** Provides information about the occurred event. */
typedef struct {
	enum idevice_event_type event; /**< The event type. */
	const char *udid; /**< The device unique id. */
	enum idevice_connection_type conn_type; /**< The connection type. */
} idevice_event_t;

/* event callback function prototype */
/** Callback to notifiy if a device was added or removed. */
typedef void (*idevice_event_cb_t) (const idevice_event_t *event, void *user_data);

/** Event subscription context type */
typedef struct idevice_subscription_context* idevice_subscription_context_t;

/* functions */

/**
 * Set the level of debugging.
 *
 * @param level Set to 0 for no debug output or 1 to enable debug output.
 */
LIBIMOBILEDEVICE_API void idevice_set_debug_level(int level);

/**
 * Subscribe a callback function that will be called when device add/remove
 * events occur.
 *
 * @param context A pointer to a idevice_subscription_context_t that will be
 *    set upon creation of the subscription. The returned context must be
 *    passed to idevice_events_unsubscribe() to unsubscribe the callback.
 * @param callback Callback function to call.
 * @param user_data Application-specific data passed as parameter
 *   to the registered callback function.
 *
 * @return IDEVICE_E_SUCCESS on success or an error value when an error occurred.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_events_subscribe(idevice_subscription_context_t *context, idevice_event_cb_t callback, void *user_data);

/**
 * Unsubscribe the event callback function that has been registered with
 * idevice_events_subscribe().
 *
 * @param context A valid context as returned from idevice_events_subscribe().
 *
 * @return IDEVICE_E_SUCCESS on success or an error value when an error occurred.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_events_unsubscribe(idevice_subscription_context_t context);

/**
 * (DEPRECATED) Register a callback function that will be called when device add/remove
 * events occur.
 *
 * @deprecated Use idevice_events_subscribe() instead.
 *
 * @param callback Callback function to call.
 * @param user_data Application-specific data passed as parameter
 *   to the registered callback function.
 *
 * @return IDEVICE_E_SUCCESS on success or an error value when an error occurred.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_event_subscribe(idevice_event_cb_t callback, void *user_data);

/**
 * (DEPRECATED) Release the event callback function that has been registered with
 *  idevice_event_subscribe().
 *
 * @deprecated Use idevice_events_unsubscribe() instead.
 *
 * @return IDEVICE_E_SUCCESS on success or an error value when an error occurred.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_event_unsubscribe(void);

/* discovery (synchronous) */

/**
 * Get a list of UDIDs of currently available devices (USBMUX devices only).
 *
 * @param devices List of UDIDs of devices that are currently available.
 *   This list is terminated by a NULL pointer.
 * @param count Number of devices found.
 *
 * @return IDEVICE_E_SUCCESS on success or an error value when an error occurred.
 *
 * @note This function only returns the UDIDs of USBMUX devices. To also include
 *   network devices in the list, use idevice_get_device_list_extended().
 * @see idevice_get_device_list_extended
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_get_device_list(char ***devices, int *count);

/**
 * Free a list of device UDIDs.
 *
 * @param devices List of UDIDs to free.
 *
 * @return Always returnes IDEVICE_E_SUCCESS.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_device_list_free(char **devices);

/**
 * Get a list of currently available devices
 *
 * @param devices List of idevice_info_t records with device information.
 *   This list is terminated by a NULL pointer.
 * @param count Number of devices included in the list.
 *
 * @return IDEVICE_E_SUCCESS on success or an error value when an error occurred.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_get_device_list_extended(idevice_info_t **devices, int *count);

/**
 * Free an extended device list retrieved through idevice_get_device_list_extended().
 *
 * @param devices Device list to free.
 *
 * @return IDEVICE_E_SUCCESS on success or an error value when an error occurred.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_device_list_extended_free(idevice_info_t *devices);

/* device structure creation and destruction */

/**
 * Creates an idevice_t structure for the device specified by UDID,
 *  if the device is available (USBMUX devices only).
 *
 * @note The resulting idevice_t structure has to be freed with
 * idevice_free() if it is no longer used.
 * If you need to connect to a device available via network, use
 * idevice_new_with_options() and include IDEVICE_LOOKUP_NETWORK in options.
 *
 * @see idevice_new_with_options
 *
 * @param device Upon calling this function, a pointer to a location of type
 *  idevice_t. On successful return, this location will be populated.
 * @param udid The UDID to match.
 *
 * @return IDEVICE_E_SUCCESS if ok, otherwise an error code.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_new(idevice_t *device, const char *udid);

/**
 * Creates an idevice_t structure for the device specified by UDID,
 *  if the device is available, with the given lookup options.
 *
 * @note The resulting idevice_t structure has to be freed with
 * idevice_free() if it is no longer used.
 *
 * @param device Upon calling this function, a pointer to a location of type
 *   idevice_t. On successful return, this location will be populated.
 * @param udid The UDID to match.
 * @param options Specifies what connection types should be considered
 *   when looking up devices. Accepts bitwise or'ed values of idevice_options.
 *   If 0 (no option) is specified it will default to IDEVICE_LOOKUP_USBMUX.
 *   To lookup both USB and network-connected devices, pass
 *   IDEVICE_LOOKUP_USBMUX | IDEVICE_LOOKUP_NETWORK. If a device is available
 *   both via USBMUX *and* network, it will select the USB connection.
 *   This behavior can be changed by adding IDEVICE_LOOKUP_PREFER_NETWORK
 *   to the options in which case it will select the network connection.
 *
 * @return IDEVICE_E_SUCCESS if ok, otherwise an error code.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_new_with_options(idevice_t *device, const char *udid, enum idevice_options options);

/**
 * Cleans up an idevice structure, then frees the structure itself.
 *
 * @param device idevice_t to free.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_free(idevice_t device);

/* connection/disconnection */

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
LIBIMOBILEDEVICE_API idevice_error_t idevice_connect(idevice_t device, uint16_t port, idevice_connection_t *connection);

/**
 * Disconnect from the device and clean up the connection structure.
 *
 * @param connection The connection to close.
 *
 * @return IDEVICE_E_SUCCESS if ok, otherwise an error code.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_disconnect(idevice_connection_t connection);

/* communication */

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
LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_send(idevice_connection_t connection, const char *data, uint32_t len, uint32_t *sent_bytes);

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
LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_receive_timeout(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout);

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
LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_receive(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes);

/**
 * Enables SSL for the given connection.
 *
 * @param connection The connection to enable SSL for.
 *
 * @return IDEVICE_E_SUCCESS on success, IDEVICE_E_INVALID_ARG when connection
 *     is NULL or connection->ssl_data is non-NULL, or IDEVICE_E_SSL_ERROR when
 *     SSL initialization, setup, or handshake fails.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_enable_ssl(idevice_connection_t connection);

/**
 * Disable SSL for the given connection.
 *
 * @param connection The connection to disable SSL for.
 *
 * @return IDEVICE_E_SUCCESS on success, IDEVICE_E_INVALID_ARG when connection
 *     is NULL. This function also returns IDEVICE_E_SUCCESS when SSL is not
 *     enabled and does no further error checking on cleanup.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_disable_ssl(idevice_connection_t connection);

/**
 * Disable bypass SSL for the given connection without sending out terminate messages.
 *
 * @param connection The connection to disable SSL for.
 * @param sslBypass  if true ssl connection will not be terminated but just cleaned up, allowing
 *                   plain text data going on underlying connection
 *
 * @return IDEVICE_E_SUCCESS on success, IDEVICE_E_INVALID_ARG when connection
 *     is NULL. This function also returns IDEVICE_E_SUCCESS when SSL is not
 *     enabled and does no further error checking on cleanup.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_disable_bypass_ssl(idevice_connection_t connection, uint8_t sslBypass);


/**
 * Get the underlying file descriptor for a connection
 *
 * @param connection The connection to get fd of
 * @param fd Pointer to an int where the fd is stored
 *
 * @return IDEVICE_E_SUCCESS if ok, otherwise an error code.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_connection_get_fd(idevice_connection_t connection, int *fd);

/* misc */

/**
 * Gets the handle or (USBMUX device id) of the device.
 *
 * @param device The device to get the USBMUX device id for.
 * @param handle Pointer to a uint32_t that will be set to the USBMUX handle value.
 *
 * @return IDEVICE_E_SUCCESS on success, otherwise an error code.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_get_handle(idevice_t device, uint32_t *handle);

/**
 * Gets the Unique Device ID for the device.
 *
 * @param device The device to get the Unique Device ID for.
 * @param udid Pointer that will be set to an allocated buffer with the device UDID. The consumer is responsible for releasing the allocated memory.
 *
 * @return IDEVICE_E_SUCCESS on success, otherwise an error code.
 */
LIBIMOBILEDEVICE_API idevice_error_t idevice_get_udid(idevice_t device, char **udid);

/**
 * Returns the device ProductVersion in numerical form, where "X.Y.Z"
 * will be returned as (X << 16) | (Y << 8) | Z .
 * Use IDEVICE_DEVICE_VERSION macro for easy version comparison.
 * @see IDEVICE_DEVICE_VERSION
 *
 * @param client Initialized device client
 *
 * @return A numerical representation of the X.Y.Z ProductVersion string
 *         or 0 if the version cannot be retrieved.
 */
LIBIMOBILEDEVICE_API unsigned int idevice_get_device_version(idevice_t device);

/**
 * Gets a readable error string for a given idevice error code.
 *
 * @param err An idevice error code
 *
 * @return A readable error string
 */
LIBIMOBILEDEVICE_API const char* idevice_strerror(idevice_error_t err);

/**
 * Returns a static string of the libimobiledevice version.
 *
 * @return The libimobiledevice version as static ascii string
 */
LIBIMOBILEDEVICE_API const char* libimobiledevice_version();

/* macros */
/** Helper macro to get a numerical representation of a product version tuple */
#define IDEVICE_DEVICE_VERSION(maj, min, patch) ((((maj) & 0xFF) << 16) | (((min) & 0xFF) << 8) | ((patch) & 0xFF))

#ifdef __cplusplus
}
#endif

#endif

