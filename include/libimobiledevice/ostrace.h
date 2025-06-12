/**
 * @file libimobiledevice/ostrace.h
 * @brief System log and tracing capabilities.
 * \internal
 *
 * Copyright (c) 2020-2025 Nikias Bassen, All Rights Reserved.
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

#ifndef OSTRACE_H
#define OSTRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

/** Service identifier passed to lockdownd_start_service() to start the os trace relay service */
#define OSTRACE_SERVICE_NAME "com.apple.os_trace_relay"

/** Error Codes */
typedef enum {
	OSTRACE_E_SUCCESS         =  0,
	OSTRACE_E_INVALID_ARG     = -1,
	OSTRACE_E_MUX_ERROR       = -2,
	OSTRACE_E_SSL_ERROR       = -3,
	OSTRACE_E_NOT_ENOUGH_DATA = -4,
	OSTRACE_E_TIMEOUT         = -5,
	OSTRACE_E_PLIST_ERROR     = -6,
	OSTRACE_E_REQUEST_FAILED  = -7,
	OSTRACE_E_UNKNOWN_ERROR   = -256
} ostrace_error_t;

typedef struct ostrace_client_private ostrace_client_private; /**< \private */
typedef ostrace_client_private *ostrace_client_t; /**< The client handle. */

#pragma pack(push,1)	
struct ostrace_packet_header_t {
	uint8_t marker;
	uint32_t type;
	uint32_t header_size; // 0x81
	uint32_t pid;
	uint64_t procid; // == pid
	unsigned char procuuid[16]; // procuuid
	uint16_t procpath_len; // path to process
	uint64_t aid; // activity id, usually 0
	uint64_t paid; // (parent?) activity id, usually 0
	uint64_t time_sec; // tv.tv_sec 64 bit
	uint32_t time_usec; // tv.usec 32 bit
	uint8_t unk06;
	uint8_t level; // Notice=0, Info=0x01, Debug=0x02, Error=0x10, Fault=0x11
	uint8_t unk07;
	uint8_t unk08;
	uint8_t unk09;
	uint8_t unk10;
	uint8_t unk11;
	uint8_t unk12;
	uint64_t timestamp; // ?
	uint32_t thread_id;
	uint32_t unk13; // 0
	unsigned char imageuuid[16]; // framework/dylib uuid
	uint16_t imagepath_len; // framework/dylib	
	uint32_t message_len; // actual log message
	uint32_t offset; // offset for like timestamp or sth
	uint16_t subsystem_len; // "subsystem"
	uint16_t unk14;
	uint16_t category_len; // "category"
	uint16_t unk15;
	uint32_t unk16; // 0
};
#pragma pack(pop)

/** Receives unparsed ostrace data from the ostrace service */
typedef void (*ostrace_activity_cb_t)(const void* buf, size_t len, void *user_data);

/** Receives archive data from the ostrace service */
typedef int (*ostrace_archive_write_cb_t)(const void* buf, size_t len, void *user_data);

/* Interface */

/**
 * Connects to the os_trace_relay service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     ostrace_client_t upon successful return. Must be freed using
 *     ostrace_client_free() after use.
 *
 * @return OSTRACE_E_SUCCESS on success, OSTRACE_E_INVALID_ARG when
 *     client is NULL, or an OSTRACE_E_* error code otherwise.
 */
LIBIMOBILEDEVICE_API ostrace_error_t ostrace_client_new(idevice_t device, lockdownd_service_descriptor_t service, ostrace_client_t * client);

/**
 * Starts a new os_trace_relay service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     ostrace_client_t upon successful return. Must be freed using
 *     ostrace_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return OSTRACE_E_SUCCESS on success, or an OSTRACE_E_* error code otherwise.
 */
LIBIMOBILEDEVICE_API ostrace_error_t ostrace_client_start_service(idevice_t device, ostrace_client_t * client, const char* label);

/**
 * Disconnects a ostrace client from the device and frees up the
 * ostrace client data.
 *
 * @param client The ostrace client to disconnect and free.
 *
 * @return OSTRACE_E_SUCCESS on success, OSTRACE_E_INVALID_ARG when
 *     client is NULL, or an OSTRACE_E_* error code otherwise.
 */
LIBIMOBILEDEVICE_API ostrace_error_t ostrace_client_free(ostrace_client_t client);

/**
 * Starts capturing OS trace activity data of the device using a callback.
 *
 * Use ostrace_stop_activity() to stop receiving the ostrace.
 *
 * @param client The ostrace client to use
 * @param options Options dictionary to pass to StartActivity request.
 *      Valid options are MessageFilter (PLIST_INT, default 65535),
 *         Pid (PLIST_INT, default -1), and StreamFlags (PLIST_INT, default 60)
 * @param callback Callback to receive data from ostrace.
 * @param user_data Custom pointer passed to the callback function.
 * @param user_data_free_func Function pointer that will be called when the
 *      activity is stopped to release user_data. Can be NULL for none.
 *
 * @return OSTRACE_E_SUCCESS on success,
 *      OSTRACE_E_INVALID_ARG when one or more parameters are
 *      invalid or OSTRACE_E_UNKNOWN_ERROR when an unspecified
 *      error occurs or an ostrace activity has already been started.
 */
LIBIMOBILEDEVICE_API ostrace_error_t ostrace_start_activity(ostrace_client_t client, plist_t options, ostrace_activity_cb_t callback, void* user_data);

/**
 * Stops the ostrace activity.
 *
 * Use ostrace_start_activity() to start receiving OS trace data.
 *
 * @param client The ostrace client to use
 *
 * @return OSTRACE_E_SUCCESS on success,
 *      OSTRACE_E_INVALID_ARG when one or more parameters are
 *      invalid or OSTRACE_E_UNKNOWN_ERROR when an unspecified
 *      error occurs or an ostrace activity has already been started.
 */
LIBIMOBILEDEVICE_API ostrace_error_t ostrace_stop_activity(ostrace_client_t client);

/**
 * Returns a dictionary with all currently running processes on the device.
 *
 * @param client The ostrace client to use
 * @param list Pointer that will receive an allocated PLIST_DICT structure with the process data
 *
 * @return OSTRACE_E_SUCCESS on success, or an OSTRACE_E_* error code otherwise
 */
LIBIMOBILEDEVICE_API ostrace_error_t ostrace_get_pid_list(ostrace_client_t client, plist_t* list);

/**
 * Creates a syslog archive.
 *
 * @note The device will close the connection once the transfer is complete. The client
 *      is not usable after that anymore and must be disposed with ostrace_client_free.
 *
 * @param client The ostrace client to use
 * @param options A dictionary with options for the request.
 *      Valid parameters are StartTime (PLIST_UINT), SizeLimit (PLIST_UINT), and AgeLimit (PLIST_UINT).
 *
 * @return OSTRACE_E_SUCCESS on success, or an OSTRACE_E_* error code otherwise
 */
LIBIMOBILEDEVICE_API ostrace_error_t ostrace_create_archive(ostrace_client_t client, plist_t options, ostrace_archive_write_cb_t callback, void* user_data);

#ifdef __cplusplus
}
#endif

#endif
