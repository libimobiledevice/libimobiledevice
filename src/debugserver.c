/*
 * debugserver.c
 * com.apple.debugserver service implementation.
 *
 * Copyright (c) 2019 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2014-2015 Martin Szulecki All Rights Reserved.
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
#include <string.h>
#include <stdlib.h>
#define _GNU_SOURCE 1
#define __USE_GNU 1
#include <stdio.h>

#include <libimobiledevice-glue/utils.h>

#include "debugserver.h"
#include "lockdown.h"
#include "common/debug.h"
#include "asprintf.h"

/**
 * Convert a service_error_t value to a debugserver_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err An service_error_t error code
 *
 * @return A matching debugserver_error_t error code,
 *     DEBUGSERVER_E_UNKNOWN_ERROR otherwise.
 */
static debugserver_error_t debugserver_error(service_error_t err)
{
	switch (err) {
		case SERVICE_E_SUCCESS:
			return DEBUGSERVER_E_SUCCESS;
		case SERVICE_E_INVALID_ARG:
			return DEBUGSERVER_E_INVALID_ARG;
		case SERVICE_E_MUX_ERROR:
			return DEBUGSERVER_E_MUX_ERROR;
		case SERVICE_E_SSL_ERROR:
			return DEBUGSERVER_E_SSL_ERROR;
		case SERVICE_E_TIMEOUT:
			return DEBUGSERVER_E_TIMEOUT;
		default:
			break;
	}
	return DEBUGSERVER_E_UNKNOWN_ERROR;
}

debugserver_error_t debugserver_client_new(idevice_t device, lockdownd_service_descriptor_t service, debugserver_client_t* client)
{
	*client = NULL;

	if (!device || !service || service->port == 0 || !client || *client) {
		debug_info("Incorrect parameter passed to debugserver_client_new.");
		return DEBUGSERVER_E_INVALID_ARG;
	}

	debug_info("Creating debugserver_client, port = %d.", service->port);

	service_client_t parent = NULL;
	debugserver_error_t ret = debugserver_error(service_client_new(device, service, &parent));
	if (ret != DEBUGSERVER_E_SUCCESS) {
		debug_info("Creating base service client failed. Error: %i", ret);
		return ret;
	}

	if (service->identifier && (strcmp(service->identifier, DEBUGSERVER_SECURE_SERVICE_NAME) != 0)) {
		service_disable_bypass_ssl(parent, 1);
	}

	debugserver_client_t client_loc = (debugserver_client_t) malloc(sizeof(struct debugserver_client_private));
	client_loc->parent = parent;
	client_loc->noack_mode = 0;
	client_loc->cancel_receive = NULL;
	client_loc->receive_loop_timeout = 1000;

	*client = client_loc;

	debug_info("debugserver_client successfully created.");
	return DEBUGSERVER_E_SUCCESS;
}

debugserver_error_t debugserver_client_start_service(idevice_t device, debugserver_client_t * client, const char* label)
{
	debugserver_error_t err = DEBUGSERVER_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, DEBUGSERVER_SECURE_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(debugserver_client_new), &err);
	if (err != DEBUGSERVER_E_SUCCESS) {
		err = DEBUGSERVER_E_UNKNOWN_ERROR;
		service_client_factory_start_service(device, DEBUGSERVER_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(debugserver_client_new), &err);
	}
	return err;
}

debugserver_error_t debugserver_client_free(debugserver_client_t client)
{
	if (!client)
		return DEBUGSERVER_E_INVALID_ARG;

	debugserver_error_t err = debugserver_error(service_client_free(client->parent));
	client->parent = NULL;
	free(client);

	return err;
}

debugserver_error_t debugserver_client_send(debugserver_client_t client, const char* data, uint32_t size, uint32_t *sent)
{
	debugserver_error_t res = DEBUGSERVER_E_UNKNOWN_ERROR;
	int bytes = 0;

	if (!client || !data || (size == 0)) {
		return DEBUGSERVER_E_INVALID_ARG;
	}

	debug_info("sending %d bytes", size);
	res = debugserver_error(service_send(client->parent, data, size, (uint32_t*)&bytes));
	if (bytes <= 0) {
		debug_info("ERROR: sending to device failed.");
	}
	if (sent) {
		*sent = (uint32_t)bytes;
	}

	return res;
}

debugserver_error_t debugserver_client_receive_with_timeout(debugserver_client_t client, char* data, uint32_t size, uint32_t *received, unsigned int timeout)
{
	debugserver_error_t res = DEBUGSERVER_E_UNKNOWN_ERROR;
	int bytes = 0;

	if (!client || !data || (size == 0)) {
		return DEBUGSERVER_E_INVALID_ARG;
	}

	res = debugserver_error(service_receive_with_timeout(client->parent, data, size, (uint32_t*)&bytes, timeout));
	if (bytes <= 0 && res != DEBUGSERVER_E_TIMEOUT) {
		debug_info("Could not read data, error %d", res);
	}
	if (received) {
		*received = (uint32_t)bytes;
	}

	return (bytes > 0) ? DEBUGSERVER_E_SUCCESS : res;
}

debugserver_error_t debugserver_client_receive(debugserver_client_t client, char* data, uint32_t size, uint32_t *received)
{
	debugserver_error_t res = DEBUGSERVER_E_UNKNOWN_ERROR;
	do {
		/* Is this allowed to return DEBUGSERVER_E_TIMEOUT and also set data and received? */
		res = debugserver_client_receive_with_timeout(client, data, size, received, client->receive_loop_timeout);
	} while (res == DEBUGSERVER_E_TIMEOUT && client->cancel_receive != NULL && !client->cancel_receive());
	return res;
}

debugserver_error_t debugserver_command_new(const char* name, int argc, char* argv[], debugserver_command_t* command)
{
	int i;
	debugserver_command_t tmp = (debugserver_command_t) malloc(sizeof(struct debugserver_command_private));

	/* copy name */
	tmp->name = strdup(name);

	/* copy arguments */
	tmp->argc = argc;
	tmp->argv = NULL;
	if (argc > 0) {
		tmp->argv = malloc(sizeof(char*) * (argc + 2));
		for (i = 0; i < argc; i++) {
			tmp->argv[i] = strdup(argv[i]);
		}
		tmp->argv[i+1] = NULL;
	}

	/* return */
	*command = tmp;

	return DEBUGSERVER_E_SUCCESS;
}

debugserver_error_t debugserver_command_free(debugserver_command_t command)
{
	int i;
	debugserver_error_t res = DEBUGSERVER_E_UNKNOWN_ERROR;

	if (!command)
		return DEBUGSERVER_E_INVALID_ARG;

	if (command) {
		if (command->name)
			free(command->name);
		if (command->argv && command->argc) {
			for (i = 0; i < command->argc; i++) {
				free(command->argv[i]);
			}
			free(command->argv);
		}
		free(command);
		res = DEBUGSERVER_E_SUCCESS;
	}

	return res;
}

static int debugserver_hex2int(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return 10 + c - 'a';
	else if (c >= 'A' && c <= 'F')
		return 10 + c - 'A';
	else
		return c;
}

static char debugserver_int2hex(int x)
{
	const char *hexchars = "0123456789ABCDEF";
	return hexchars[x];
}

#define DEBUGSERVER_HEX_ENCODE_FIRST_BYTE(byte) debugserver_int2hex(((byte) >> 0x4) & 0xf)
#define DEBUGSERVER_HEX_ENCODE_SECOND_BYTE(byte) debugserver_int2hex((byte) & 0xf)
#define DEBUGSERVER_HEX_DECODE_FIRST_BYTE(byte) (((byte) >> 0x4) & 0xf)
#define DEBUGSERVER_HEX_DECODE_SECOND_BYTE(byte) ((byte) & 0xf)

static uint32_t debugserver_get_checksum_for_buffer(const char* buffer, uint32_t size)
{
	uint32_t checksum = 0;
	uint32_t i;

	for (i = 0; i < size; i++) {
		checksum += buffer[i];
	}

	return checksum;
}

static int debugserver_response_is_checksum_valid(const char* response, uint32_t size)
{
	uint32_t checksum = 0;
	if ((size - DEBUGSERVER_CHECKSUM_HASH_LENGTH - 1) > 0)
		checksum = debugserver_get_checksum_for_buffer(&response[1], size - DEBUGSERVER_CHECKSUM_HASH_LENGTH - 1);

	debug_info("checksum: 0x%x", checksum);

	if ((unsigned)debugserver_hex2int(response[size - 2]) != DEBUGSERVER_HEX_DECODE_FIRST_BYTE(checksum))
		return 0;

	if ((unsigned)debugserver_hex2int(response[size - 1]) != DEBUGSERVER_HEX_DECODE_SECOND_BYTE(checksum))
		return 0;

	debug_info("valid checksum");

	return 1;
}

void debugserver_encode_string(const char* buffer, char** encoded_buffer, uint32_t* encoded_length)
{
	uint32_t position;
	uint32_t index;
	uint32_t length = strlen(buffer);
	*encoded_length = (2 * length) + DEBUGSERVER_CHECKSUM_HASH_LENGTH + 1;

	*encoded_buffer = malloc(sizeof(char) * (*encoded_length));
	memset(*encoded_buffer, '\0', *encoded_length);
	for (position = 0, index = 0; index < length; index++) {
		position = (index * (2 * sizeof(char)));
		(*encoded_buffer)[position] = DEBUGSERVER_HEX_ENCODE_FIRST_BYTE(buffer[index]);
		(*encoded_buffer)[position + 1] = DEBUGSERVER_HEX_ENCODE_SECOND_BYTE(buffer[index]);
	}
}

void debugserver_decode_string(const char *encoded_buffer, size_t encoded_length, char** buffer)
{
	*buffer = malloc(sizeof(char) * ((encoded_length / 2)+1));
	char* t = *buffer;
	const char *f = encoded_buffer;
	const char *fend = f + encoded_length;
	while (f < fend) {
		*t++ = debugserver_hex2int(*f) << 4 | debugserver_hex2int(f[1]);
		f += 2;
	}
	*t = '\0';
}

static void debugserver_format_command(const char* prefix, const char* command, const char* arguments, int calculate_checksum, char** buffer, uint32_t* size)
{
	char checksum_hash[DEBUGSERVER_CHECKSUM_HASH_LENGTH + 1] = {'#', '0', '0', '\0'};
	char* encoded = NULL;
	uint32_t encoded_length = 0;

	if (arguments) {
		/* arguments must be hex encoded */
		debugserver_encode_string(arguments, &encoded, &encoded_length);
	} else {
		encoded = NULL;
	}

	char* encoded_command = string_concat(command, encoded, NULL);
	encoded_length = strlen(encoded_command);

	if (calculate_checksum) {
		uint32_t checksum = debugserver_get_checksum_for_buffer(encoded_command, encoded_length);
		checksum_hash[1] = DEBUGSERVER_HEX_ENCODE_FIRST_BYTE(checksum);
		checksum_hash[2] = DEBUGSERVER_HEX_ENCODE_SECOND_BYTE(checksum);
	}

	*buffer = string_concat(prefix, encoded_command, checksum_hash, NULL);
	*size = strlen(prefix) + strlen(encoded_command) + DEBUGSERVER_CHECKSUM_HASH_LENGTH;

	debug_info("formatted command: %s size: %d checksum: 0x%s", *buffer, *size, checksum_hash);

	if (encoded_command)
		free(encoded_command);

	if (encoded)
		free(encoded);
}

static debugserver_error_t debugserver_client_send_ack(debugserver_client_t client)
{
	debug_info("sending ACK");
	return debugserver_client_send(client, "+", sizeof(char), NULL);
}

static debugserver_error_t debugserver_client_send_noack(debugserver_client_t client)
{
	debug_info("sending !ACK");
	return debugserver_client_send(client, "-", sizeof(char), NULL);
}

debugserver_error_t debugserver_client_set_ack_mode(debugserver_client_t client, int enabled)
{
	if (!client)
		return DEBUGSERVER_E_INVALID_ARG;

	client->noack_mode = (enabled == 0)? 1: 0;

	debug_info("ack mode: %s", client->noack_mode == 0 ? "on": "off");

	return DEBUGSERVER_E_SUCCESS;
}

debugserver_error_t debugserver_client_set_receive_params(debugserver_client_t client, int (*cancel_receive)(), int receive_loop_timeout)
{
	if (!client)
		return DEBUGSERVER_E_INVALID_ARG;

	client->cancel_receive = cancel_receive;
	client->receive_loop_timeout = receive_loop_timeout;

	debug_info("receive params: cancel_receive %s, receive_loop_timeout %dms", (client->cancel_receive == NULL ? "unset": "set"), client->receive_loop_timeout);

	return DEBUGSERVER_E_SUCCESS;
}

static debugserver_error_t debugserver_client_receive_internal_char(debugserver_client_t client, char* received_char)
{
	debugserver_error_t res = DEBUGSERVER_E_SUCCESS;
	uint32_t bytes = 0;

	/* we loop here as we expect an answer */
	res = debugserver_client_receive(client, received_char, sizeof(char), &bytes);
	if (res != DEBUGSERVER_E_SUCCESS) {
		return res;
	}
	if (bytes != 1) {
		debug_info("received %d bytes when asking for %d!", bytes, sizeof(char));
		return DEBUGSERVER_E_UNKNOWN_ERROR;
	}
	return res;
}

debugserver_error_t debugserver_client_receive_response(debugserver_client_t client, char** response, size_t* response_size)
{
	debugserver_error_t res = DEBUGSERVER_E_SUCCESS;

	char data = '\0';
	int skip_prefix = 0;

	char* buffer = malloc(1024);
	uint32_t buffer_size = 0;
	uint32_t buffer_capacity = 1024;

	if (response)
		*response = NULL;

	if (!client->noack_mode) {
		debug_info("attempting to receive ACK (+)");
		res = debugserver_client_receive_internal_char(client, &data);
		if (res != DEBUGSERVER_E_SUCCESS) {
			goto cleanup;
		}
		if (data == '+') {
			debug_info("received ACK (+)");
		} else if (data == '$') {
			debug_info("received prefix ($)");
			buffer[0] = '$';
			buffer_size = 1;
			skip_prefix = 1;
		} else {
			debug_info("unrecognized response when looking for ACK: %c", data);
			goto cleanup;
		}
	}

	debug_info("skip_prefix: %d", skip_prefix);

	if (!skip_prefix) {
		debug_info("attempting to receive prefix ($)");
		res = debugserver_client_receive_internal_char(client, &data);
		if (res != DEBUGSERVER_E_SUCCESS) {
			goto cleanup;
		}
		if (data == '$') {
			debug_info("received prefix ($)");
			buffer[0] = '$';
			buffer_size = 1;
		} else {
			debug_info("unrecognized response when looking for prefix: %c", data);
			goto cleanup;
		}
	}

	uint32_t checksum_length = DEBUGSERVER_CHECKSUM_HASH_LENGTH;
	int receiving_checksum_response = 0;
	debug_info("attempting to read up response until checksum");

	while ((checksum_length > 0)) {
		res = debugserver_client_receive_internal_char(client, &data);
		if (res != DEBUGSERVER_E_SUCCESS) {
			goto cleanup;
		}
		if (data == '#') {
			receiving_checksum_response = 1;
		}
		if (receiving_checksum_response) {
			checksum_length--;
		}
		if (buffer_size + 1 >= buffer_capacity) {
			char* newbuffer = realloc(buffer, buffer_capacity+1024);
			if (!newbuffer) {
				return DEBUGSERVER_E_UNKNOWN_ERROR;
			}
			buffer = newbuffer;
			buffer_capacity += 1024;
		}
		buffer[buffer_size] = data;
		buffer_size += sizeof(char);
	}
	debug_info("validating response checksum...");
	if (client->noack_mode || debugserver_response_is_checksum_valid(buffer, buffer_size)) {
		if (response) {
			/* assemble response string */
			uint32_t resp_size = sizeof(char) * (buffer_size - DEBUGSERVER_CHECKSUM_HASH_LENGTH - 1);
			*response = (char*)malloc(resp_size + 1);
			memcpy(*response, buffer + 1, resp_size);
			(*response)[resp_size] = '\0';
			if (response_size) *response_size = resp_size;
		}
		if (!client->noack_mode) {
			/* confirm valid command */
			debugserver_client_send_ack(client);
		}
	} else {
		/* response was invalid */
		res = DEBUGSERVER_E_RESPONSE_ERROR;
		if (!client->noack_mode) {
			/* report invalid command */
			debugserver_client_send_noack(client);
		}
	}

cleanup:
	if (response) {
		debug_info("response: %s", *response);
	}

	if (buffer)
		free(buffer);

	return res;
}

debugserver_error_t debugserver_client_send_command(debugserver_client_t client, debugserver_command_t command, char** response, size_t* response_size)
{
	debugserver_error_t res = DEBUGSERVER_E_SUCCESS;
	int i;
	uint32_t bytes = 0;

	char* send_buffer = NULL;
	uint32_t send_buffer_size = 0;

	char* command_arguments = NULL;

	/* concat all arguments */
	for (i = 0; i < command->argc; i++) {
		debug_info("argv[%d]: %s", i, command->argv[i]);
		command_arguments = string_append(command_arguments, command->argv[i], NULL);
	}

	debug_info("command_arguments(%d): %s", command->argc, command_arguments);

	/* encode command arguments, add checksum if required and assemble entire command */
	debugserver_format_command("$", command->name, command_arguments, 1, &send_buffer, &send_buffer_size);

	debug_info("sending encoded command: %s", send_buffer);

	res = debugserver_client_send(client, send_buffer, send_buffer_size, &bytes);
	debug_info("command result: %d", res);
	if (res != DEBUGSERVER_E_SUCCESS) {
		goto cleanup;
	}

	/* receive response */
	res = debugserver_client_receive_response(client, response, response_size);
	debug_info("response result: %d", res);
	if (res != DEBUGSERVER_E_SUCCESS) {
		goto cleanup;
	}

	if (response) {
		debug_info("received response: %s", *response);
	}

	/* disable sending ack on the client */
	if (!strncmp(command->name, "QStartNoAckMode", 16)) {
		debugserver_client_set_ack_mode(client, 0);
	}

cleanup:
	if (command_arguments)
		free(command_arguments);

	if (send_buffer)
		free(send_buffer);

	return res;
}

debugserver_error_t debugserver_client_set_environment_hex_encoded(debugserver_client_t client, const char* env, char** response)
{
	if (!client || !env)
		return DEBUGSERVER_E_INVALID_ARG;

	debugserver_error_t result = DEBUGSERVER_E_UNKNOWN_ERROR;
	char* env_tmp = strdup(env);
	char* env_arg[2] = { env_tmp, NULL };

	debugserver_command_t command = NULL;
	debugserver_command_new("QEnvironmentHexEncoded:", 1, env_arg, &command);
	result = debugserver_client_send_command(client, command, response, NULL);
	debugserver_command_free(command);

	free(env_tmp);

	return result;
}

debugserver_error_t debugserver_client_set_argv(debugserver_client_t client, int argc, char* argv[], char** response)
{
	if (!client || !argc)
		return DEBUGSERVER_E_INVALID_ARG;

	debugserver_error_t result = DEBUGSERVER_E_UNKNOWN_ERROR;
	char *pkt = NULL;
	size_t pkt_len = 0;
	int i = 0;

	/* calculate total length */
	while (i < argc && argv && argv[i]) {
		char *prefix = NULL;
		int ret = asprintf(&prefix, ",%zu,%d,", strlen(argv[i]) * 2, i);
		if (ret < 0 || prefix == NULL) {
			debug_info("asprintf failed, out of memory?");
			return DEBUGSERVER_E_UNKNOWN_ERROR;
		}
		pkt_len += strlen(prefix) + strlen(argv[i]) * 2;
		free(prefix);
		i++;
	}

	/* allocate packet and initialize it */
	pkt = (char *) malloc(pkt_len + 1);
	memset(pkt, 0, pkt_len + 1);

	char *pktp = pkt;

	i = 0;
	while (i < argc && argv && argv[i]) {
		debug_info("argv[%d] = \"%s\"", i, argv[i]);

		char *prefix = NULL;
		char *m = NULL;
		size_t arg_len = strlen(argv[i]);
		size_t arg_hexlen = arg_len * 2;

		int ret = asprintf(&prefix, ",%zu,%d,", arg_hexlen, i);
		if (ret < 0 || prefix == NULL) {
			debug_info("asprintf failed, out of memory?");
			return DEBUGSERVER_E_UNKNOWN_ERROR;
		}

		m = (char *) malloc(arg_hexlen);
		char *p = m;
		char *q = (char*)argv[i];
		while (*q) {
			*p++ = DEBUGSERVER_HEX_ENCODE_FIRST_BYTE(*q);
			*p++ = DEBUGSERVER_HEX_ENCODE_SECOND_BYTE(*q);
			q++;
		}

		memcpy(pktp, prefix, strlen(prefix));
		pktp += strlen(prefix);

		memcpy(pktp, m, arg_hexlen);
		pktp += arg_hexlen;

		free(prefix);
		free(m);

		i++;
	}

	pkt[0] = 'A';

	debugserver_command_t command = NULL;
	debugserver_command_new(pkt, 0, NULL, &command);
	result = debugserver_client_send_command(client, command, response, NULL);
	debugserver_command_free(command);

	if (pkt)
		free(pkt);

	return result;
}
