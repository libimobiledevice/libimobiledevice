/**
 * @file libimobiledevice/debugserver.h
 * @brief Communicate with debugserver on the device.
 * \internal
 *
 * Copyright (c) 2014 Martin Szulecki All Rights Reserved.
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

#ifndef IDEBUGSERVER_H
#define IDEBUGSERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define DEBUGSERVER_SERVICE_NAME "com.apple.debugserver"

/** Error Codes */
typedef enum {
	DEBUGSERVER_E_SUCCESS        =  0,
	DEBUGSERVER_E_INVALID_ARG    = -1,
	DEBUGSERVER_E_MUX_ERROR      = -2,
	DEBUGSERVER_E_SSL_ERROR      = -3,
	DEBUGSERVER_E_RESPONSE_ERROR = -4,
	DEBUGSERVER_E_UNKNOWN_ERROR  = -256
} debugserver_error_t;

typedef struct debugserver_client_private debugserver_client_private;
typedef debugserver_client_private *debugserver_client_t; /**< The client handle. */

typedef struct debugserver_command_private debugserver_command_private;
typedef debugserver_command_private *debugserver_command_t; /**< The command handle. */

/* Interface */

/**
 * Connects to the debugserver service on the specified device.
 *
 * @param device The device to connect to.
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will point to a newly allocated
 *     debugserver_client_t upon successful return. Must be freed using
 *     debugserver_client_free() after use.
 *
 * @return DEBUGSERVER_E_SUCCESS on success, DEBUGSERVER_E_INVALID_ARG when
 *     client is NULL, or an DEBUGSERVER_E_* error code otherwise.
 */
debugserver_error_t debugserver_client_new(idevice_t device, lockdownd_service_descriptor_t service, debugserver_client_t * client);

/**
 * Starts a new debugserver service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     debugserver_client_t upon successful return. Must be freed using
 *     debugserver_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return DEBUGSERVER_E_SUCCESS on success, or an DEBUGSERVER_E_* error
 *     code otherwise.
 */
debugserver_error_t debugserver_client_start_service(idevice_t device, debugserver_client_t * client, const char* label);

/**
 * Disconnects a debugserver client from the device and frees up the
 * debugserver client data.
 *
 * @param client The debugserver client to disconnect and free.
 *
 * @return DEBUGSERVER_E_SUCCESS on success, DEBUGSERVER_E_INVALID_ARG when
 *     client is NULL, or an DEBUGSERVER_E_* error code otherwise.
 */
debugserver_error_t debugserver_client_free(debugserver_client_t client);

/**
 * Sends raw data using the given debugserver service client.
 *
 * @param client The debugserver client to use for sending
 * @param data Data to send
 * @param size Size of the data to send
 * @param sent Number of bytes sent (can be NULL to ignore)
 *
 * @return DEBUGSERVER_E_SUCCESS on success,
 *      DEBUGSERVER_E_INVALID_ARG when one or more parameters are
 *      invalid, or DEBUGSERVER_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
debugserver_error_t debugserver_client_send(debugserver_client_t client, const char* data, uint32_t size, uint32_t *sent);

/**
 * Receives raw data using the given debugserver client with specified timeout.
 *
 * @param client The debugserver client to use for receiving
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 * @param timeout Maximum time in milliseconds to wait for data.
 *
 * @return DEBUGSERVER_E_SUCCESS on success,
 *      DEBUGSERVER_E_INVALID_ARG when one or more parameters are
 *      invalid, DEBUGSERVER_E_MUX_ERROR when a communication error
 *      occurs, or DEBUGSERVER_E_UNKNOWN_ERROR when an unspecified
 *      error occurs.
 */
debugserver_error_t debugserver_client_receive_with_timeout(debugserver_client_t client, char *data, uint32_t size, uint32_t *received, unsigned int timeout);

/**
 * Receives raw data from the debugserver service.
 *
 * @param client The debugserver client
 * @param data Buffer that will be filled with the data received
 * @param size Number of bytes to receive
 * @param received Number of bytes received (can be NULL to ignore)
 * @note The default read timeout is 10 seconds.
 *
 * @return DEBUGSERVER_E_SUCCESS on success,
 *  DEBUGSERVER_E_INVALID_ARG when client or plist is NULL
 */
debugserver_error_t debugserver_client_receive(debugserver_client_t client, char *data, uint32_t size, uint32_t *received);

/**
 * Sends a command to the debugserver service.
 *
 * @param client The debugserver client
 * @param command Command to process and send
 * @param response Response received for the command (can be NULL to ignore)
 *
 * @return DEBUGSERVER_E_SUCCESS on success,
 *  DEBUGSERVER_E_INVALID_ARG when client or command is NULL
 */
debugserver_error_t debugserver_client_send_command(debugserver_client_t client, debugserver_command_t command, char** response);

/**
 * Receives and parses response of debugserver service.
 *
 * @param client The debugserver client
 * @param response Response received for last command (can be NULL to ignore)
 *
 * @return DEBUGSERVER_E_SUCCESS on success,
 *  DEBUGSERVER_E_INVALID_ARG when client is NULL
 */
debugserver_error_t debugserver_client_receive_response(debugserver_client_t client, char** response);

/**
 * Controls status of ACK mode when sending commands or receiving responses.
 *
 * @see debugserver_client_send_command, debugserver_client_receive_response
 *
 * @param client The debugserver client
 * @param enabled A boolean flag indicating whether the internal ACK mode
 *   handling should be enabled or disabled.
 *
 * @return DEBUGSERVER_E_SUCCESS on success, or an DEBUGSERVER_E_* error
 *     code otherwise.
 */
debugserver_error_t debugserver_client_set_ack_mode(debugserver_client_t client, int enabled);

/**
 * Sets the argv which launches an app.
 *
 * @param client The debugserver client
 * @param argc Number of arguments
 * @param argv Array starting with the executable to be run followed by it's arguments
 * @param response Response received for the command (can be NULL to ignore)
 *
 * @return DEBUGSERVER_E_SUCCESS on success,
 *  DEBUGSERVER_E_INVALID_ARG when client is NULL
 */
debugserver_error_t debugserver_client_set_argv(debugserver_client_t client, int argc, char* argv[], char** response);

/**
 * Adds or sets an environment variable.
 *
 * @param client The debugserver client
 * @param env The environment variable in "KEY=VALUE" notation
 * @param response Response received for the command (can be NULL to ignore)
 *
 * @return DEBUGSERVER_E_SUCCESS on success,
 *  DEBUGSERVER_E_INVALID_ARG when client is NULL
 */
debugserver_error_t debugserver_client_set_environment_hex_encoded(debugserver_client_t client, const char* env, char** response);

/**
 * Creates and initializes a new command object.
 *
 * @param name The name of the command which is sent in plain text
 * @param argv Array of tokens for the command ment to be encoded
 * @param argc Number of items in the token array
 * @param command New command object
 *
 * @return DEBUGSERVER_E_SUCCESS on success,
 *  DEBUGSERVER_E_INVALID_ARG when name or command is NULL
 */
debugserver_error_t debugserver_command_new(const char* name, int argc, char* argv[], debugserver_command_t* command);

/**
 * Frees memory of command object.
 *
 * @param command The command object
 *
 * @return DEBUGSERVER_E_SUCCESS on success,
 *  DEBUGSERVER_E_INVALID_ARG when command is NULL
 */
debugserver_error_t debugserver_command_free(debugserver_command_t command);

/**
 * Encodes a string into hex notation.
 *
 * @param buffer String to encode into hex notiation
 * @param encoded_buffer The buffer receives a hex encoded string
 * @param encoded_length Length of the hex encoded string
 */
void debugserver_encode_string(const char* buffer, char** encoded_buffer, uint32_t* encoded_length);

/**
 * Decodes a hex encoded string.
 *
 * @param encoded_buffer The buffer with a hex encoded string
 * @param encoded_length Length of the encoded buffer
 * @param buffer Decoded string to be freed by the caller
 */
void debugserver_decode_string(const char *encoded_buffer, size_t encoded_length, char** buffer);

#ifdef __cplusplus
}
#endif

#endif
