/*
 * reverse_proxy.c
 * com.apple.PurpleReverseProxy service implementation.
 *
 * Copyright (c) 2021 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2014 BALATON Zoltan. All Rights Reserved.
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
#include <errno.h>

#include <plist/plist.h>
#include <libimobiledevice-glue/thread.h>
#include <libimobiledevice-glue/socket.h>

#include "reverse_proxy.h"
#include "lockdown.h"
#include "common/debug.h"
#include "endianness.h"
#include "asprintf.h"

#ifndef ECONNRESET
#define ECONNRESET 108
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT 138
#endif

#define CTRL_PORT 1082
#define CTRLCMD  "BeginCtrl"
#define HELLOCTRLCMD "HelloCtrl"
#define HELLOCMD "HelloConn"

#define RP_SYNC_MSG  0x1
#define RP_PROXY_MSG 0x105
#define RP_PLIST_MSG 0xbbaa

/**
 * Convert a service_error_t value to a reverse_proxy_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err A service_error_t error code
 *
 * @return A matching reverse_proxy_error_t error code,
 *     REVERSE_PROXY_E_UNKNOWN_ERROR otherwise.
 */
static reverse_proxy_error_t reverse_proxy_error(service_error_t err)
{
	switch (err) {
		case SERVICE_E_SUCCESS:
			return REVERSE_PROXY_E_SUCCESS;
		case SERVICE_E_INVALID_ARG:
			return REVERSE_PROXY_E_INVALID_ARG;
		case SERVICE_E_MUX_ERROR:
			return REVERSE_PROXY_E_MUX_ERROR;
		case SERVICE_E_SSL_ERROR:
			return REVERSE_PROXY_E_SSL_ERROR;
		case SERVICE_E_NOT_ENOUGH_DATA:
			return REVERSE_PROXY_E_NOT_ENOUGH_DATA;
		case SERVICE_E_TIMEOUT:
			return REVERSE_PROXY_E_TIMEOUT;
		default:
			break;
	}
	return REVERSE_PROXY_E_UNKNOWN_ERROR;
}

static void _reverse_proxy_log(reverse_proxy_client_t client, const char* format, ...)
{
	if (!client || !client->log_cb) {
		return;
	}
	va_list args;
	va_start(args, format);
	char* buffer = NULL;
	if(vasprintf(&buffer, format, args)<0){}
	va_end(args);
	client->log_cb(client, buffer, client->log_cb_user_data);
	free(buffer);
}

static void _reverse_proxy_data(reverse_proxy_client_t client, int direction, char* buffer, uint32_t length)
{
	if (!client || !client->data_cb) {
		return;
	}
	client->data_cb(client, direction, buffer, length, client->data_cb_user_data);
}

static void _reverse_proxy_status(reverse_proxy_client_t client, int status, const char* format, ...)
{
	if (!client || !client->status_cb) {
		return;
	}
	va_list args;
	va_start(args, format);
	char* buffer = NULL;
	if(vasprintf(&buffer, format, args)<0){}
	va_end(args);
	client->status_cb(client, status, buffer, client->status_cb_user_data);
	free(buffer);
}

static int _reverse_proxy_handle_proxy_cmd(reverse_proxy_client_t client)
{
	reverse_proxy_error_t err = REVERSE_PROXY_E_SUCCESS;
	char *buf = NULL;
	size_t bufsize = 1048576;
	uint32_t sent = 0, bytes = 0;
	uint32_t sent_total = 0;
	uint32_t recv_total = 0;
	char *host = NULL;
	uint16_t port = 0;

	buf = malloc(bufsize);
	if (!buf) {
		_reverse_proxy_log(client, "ERROR: Failed to allocate buffer");
		return -1;
	}

	err = reverse_proxy_receive(client, buf, bufsize, &bytes);
	if (err != REVERSE_PROXY_E_SUCCESS) {
		free(buf);
		_reverse_proxy_log(client, "ERROR: Unable to read data for proxy command");
		return -1;
	}
	_reverse_proxy_log(client, "Handling proxy command");

	/* Just return success here unconditionally because we don't know
	 * anything else and we will eventually abort on failure anyway */
	uint16_t ack = 5;
	err = reverse_proxy_send(client, (char *)&ack, sizeof(ack), &sent);
	if (err != REVERSE_PROXY_E_SUCCESS || sent != sizeof(ack)) {
		free(buf);
		_reverse_proxy_log(client, "ERROR: Unable to send ack. Sent %u of %u bytes.", sent, (uint32_t)sizeof(ack));
		return -1;
	}

	if (bytes < 3) {
		free(buf);
		_reverse_proxy_log(client, "Proxy command data too short, retrying");
		return 0;
	}

	/* ack command data too */
	err = reverse_proxy_send(client, buf, bytes, &sent);
	if (err != REVERSE_PROXY_E_SUCCESS || sent != bytes) {
		free(buf);
		_reverse_proxy_log(client, "ERROR: Unable to send data. Sent %u of %u bytes.", sent, bytes);
		return -1;
	}

	/* Now try to handle actual messages */
	/* Connect: 0 3 hostlen <host> <port> */
	if (buf[0] == 0 && buf[1] == 3) {
		uint16_t *p = (uint16_t *)&buf[bytes - 2];
		port = be16toh(*p);
		buf[bytes - 2] = '\0';
		host = strdup(&buf[3]);
		_reverse_proxy_log(client, "Connect request to %s:%u", host, port);
	}

	if (!host || !buf[2]) {
		/* missing or zero length host name */
		free(buf);
		return 0;
	}

	/* else wait for messages and forward them */
	int sockfd = socket_connect(host, port);
	if (sockfd < 0) {
		free(buf);
		_reverse_proxy_log(client, "ERROR: Connection to %s:%u failed: %s", host, port, strerror(errno));
		free(host);
		return -1;
	}

	_reverse_proxy_status(client, RP_STATUS_CONNECTED, "Connected to %s:%u", host, port);

	int res = 0, bytes_ret;
	while (1) {
		bytes = 0;
		err = reverse_proxy_receive_with_timeout(client, buf, bufsize, &bytes, 100);
		if (err == REVERSE_PROXY_E_TIMEOUT || (err == REVERSE_PROXY_E_SUCCESS && !bytes)) {
			/* just a timeout condition */
		}
		else if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(client, "Connection closed");
			res = -1;
			break;
		}
		if (bytes) {
			_reverse_proxy_log(client, "Proxying %u bytes of data", bytes);
			_reverse_proxy_data(client, RP_DATA_DIRECTION_OUT, buf, bytes);
			sent = 0;
			while (sent < bytes) {
				int s = socket_send(sockfd, buf + sent, bytes - sent);
				if (s < 0) {
					break;
				}
				sent += s;
			}
			sent_total += sent;
			if (sent != bytes) {
				_reverse_proxy_log(client, "ERROR: Sending proxy payload failed: %s. Sent %u of %u bytes.", strerror(errno), sent, bytes);
				socket_close(sockfd);
				res = -1;
				break;
			}
		}
		bytes_ret = socket_receive_timeout(sockfd, buf, bufsize, 0, 100);
		if (bytes_ret == -ETIMEDOUT) {
			bytes_ret = 0;
		} else if (bytes_ret == -ECONNRESET) {
			res = 1;
			break;
		} else if (bytes_ret < 0) {
			_reverse_proxy_log(client, "ERROR: Failed to receive from host: %s", strerror(-bytes_ret));
			break;
		}

		bytes = bytes_ret;
		if (bytes) {
			_reverse_proxy_log(client, "Received %u bytes reply data, sending to device\n", bytes);
			_reverse_proxy_data(client, RP_DATA_DIRECTION_IN, buf, bytes);
			recv_total += bytes;
			sent = 0;
			while (sent < bytes) {
				uint32_t s;
				err = reverse_proxy_send(client, buf + sent, bytes - sent, &s);
				if (err != REVERSE_PROXY_E_SUCCESS) {
					break;
				}
				sent += s;
			}
			if (err != REVERSE_PROXY_E_SUCCESS || bytes != sent) {
				_reverse_proxy_log(client, "ERROR: Unable to send data (%d). Sent %u of %u bytes.", err, sent, bytes);
				res = -1;
				break;
			}
		}
	}
	socket_close(sockfd);
	free(host);
	free(buf);

	_reverse_proxy_status(client, RP_STATUS_DISCONNECTED, "Disconnected (out: %u / in: %u)", sent_total, recv_total);

	return res;
}

static int _reverse_proxy_handle_plist_cmd(reverse_proxy_client_t client)
{
	plist_t dict;
	reverse_proxy_error_t err;

	err = reverse_proxy_receive_plist(client, &dict);
	if (err != REVERSE_PROXY_E_SUCCESS) {
		_reverse_proxy_log(client, "ERROR: Unable to receive plist command, error", err);
		return -1;
	}
	plist_t node = plist_dict_get_item(dict, "Command");
	if (!node || (plist_get_node_type(node) != PLIST_STRING)) {
		_reverse_proxy_log(client, "ERROR: No 'Command' in reply", err);
		plist_free(dict);
		return -1;
	}
	char *command = NULL;
	plist_get_string_val(node, &command);
	plist_free(dict);

	if (!command) {
		_reverse_proxy_log(client, "ERROR: Empty 'Command' string");
		return -1;
	}

	if (!strcmp(command, "Ping")) {
		_reverse_proxy_log(client, "Received Ping command, replying with Pong");
		dict = plist_new_dict();
		plist_dict_set_item(dict, "Pong", plist_new_bool(1));
		err = reverse_proxy_send_plist(client, dict);
		plist_free(dict);
		if (err) {
			_reverse_proxy_log(client, "ERROR: Unable to send Ping command reply");
			free(command);
			return -1;
		}
	} else {
		_reverse_proxy_log(client, "WARNING: Received unhandled plist command '%s'", command);
		free(command);
		return -1;
	}

	free(command);
	/* reverse proxy connection will be terminated remotely. Next receive will get nothing, error and terminate this worker thread. */
	return 0;
}

static reverse_proxy_error_t reverse_proxy_client_new(idevice_t device, lockdownd_service_descriptor_t service, reverse_proxy_client_t * client)
{
	*client = NULL;

	if (!device || !service || service->port == 0 || !client || *client) {
		return REVERSE_PROXY_E_INVALID_ARG;
	}

	debug_info("Creating reverse_proxy_client, port = %d.", service->port);

	service_client_t sclient = NULL;
	reverse_proxy_error_t ret = reverse_proxy_error(service_client_new(device, service, &sclient));
	if (ret != REVERSE_PROXY_E_SUCCESS) {
		debug_info("Creating service client failed. Error: %i", ret);
		return ret;
	}

	reverse_proxy_client_t client_loc = (reverse_proxy_client_t) calloc(1, sizeof(struct reverse_proxy_client_private));
	client_loc->parent = sclient;
	client_loc->th_ctrl = THREAD_T_NULL;
	*client = client_loc;

	return 0;
}

static void* _reverse_proxy_connection_thread(void *cdata)
{
	reverse_proxy_client_t client = (reverse_proxy_client_t)cdata;
	uint32_t bytes = 0;
	reverse_proxy_client_t conn_client = NULL;
	reverse_proxy_error_t err = REVERSE_PROXY_E_UNKNOWN_ERROR;

	if (client->conn_port == 0) {
		service_client_factory_start_service(client->parent->connection->device, "com.apple.PurpleReverseProxy.Conn", (void**)&conn_client, client->label, SERVICE_CONSTRUCTOR(reverse_proxy_client_new), &err);
		if (!conn_client) {
			_reverse_proxy_log(client, "ERROR: Failed to start proxy connection service, error %d", err);
		}
	} else {
		struct lockdownd_service_descriptor svc;
		svc.port = client->conn_port;
		svc.ssl_enabled = 0;
		svc.identifier = NULL;
		err = reverse_proxy_client_new(client->parent->connection->device, &svc, &conn_client);
		if (!conn_client) {
			_reverse_proxy_log(client, "ERROR: Failed to connect to proxy connection port %u, error %d", client->conn_port, err);
		}
	}
	if (!conn_client) {
		goto leave;
	}
	conn_client->type = RP_TYPE_CONN;
	conn_client->protoversion = client->protoversion;
	conn_client->log_cb = client->log_cb;
	conn_client->log_cb_user_data = client->log_cb_user_data;
	conn_client->status_cb = client->status_cb;
	conn_client->status_cb_user_data = client->status_cb_user_data;

	err = reverse_proxy_send(conn_client, HELLOCMD, sizeof(HELLOCMD), &bytes);
	if (err != REVERSE_PROXY_E_SUCCESS || bytes != sizeof(HELLOCMD)) {
		_reverse_proxy_log(conn_client, "ERROR: Unable to send " HELLOCMD " (sent %u/%u bytes)", bytes, sizeof(HELLOCMD));
		goto leave;
	}

	if (conn_client->protoversion == 2) {
		plist_t reply = NULL;
		err = reverse_proxy_receive_plist(conn_client, &reply);
		if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(conn_client, "ERROR: Did not receive " HELLOCMD " reply, error %d", err);
			goto leave;
		}
		char* identifier = NULL;
		char* cmd = NULL;
		plist_t node = NULL;
		node = plist_dict_get_item(reply, "Command");
		if (node) {
			plist_get_string_val(node, &cmd);
		}
		node = plist_dict_get_item(reply, "Identifier");
		if (node) {
			plist_get_string_val(node, &identifier);
		}
		plist_free(reply);

		if (!cmd || (strcmp(cmd, HELLOCMD) != 0)) {
			free(cmd);
			free(identifier);
			_reverse_proxy_log(conn_client, "ERROR: Unexpected reply to " HELLOCMD " received");
			goto leave;
		}
		free(cmd);

		if (identifier) {
			_reverse_proxy_log(conn_client, "Got device identifier %s", identifier);
			free(identifier);
		}
	} else {
		char buf[16];
		memset(buf, '\0', sizeof(buf));
		bytes = 0;
		err = reverse_proxy_receive(conn_client, buf, sizeof(HELLOCMD), &bytes);
		if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(conn_client, "ERROR: Did not receive " HELLOCMD " reply, error %d", err);
			goto leave;
		}
		if (memcmp(buf, HELLOCMD, sizeof(HELLOCMD)) != 0) {
			_reverse_proxy_log(conn_client, "ERROR: Did not receive " HELLOCMD " as reply, but %.*s", (int)bytes, buf);
			goto leave;
		}
	}

	_reverse_proxy_status(conn_client, RP_STATUS_READY, "Ready");

	int running = 1;
	while (client->th_ctrl != THREAD_T_NULL && conn_client && running) {
		uint16_t cmd = 0;
		bytes = 0;
		err = reverse_proxy_receive_with_timeout(conn_client, (char*)&cmd, sizeof(cmd), &bytes, 1000);
		if (err == REVERSE_PROXY_E_TIMEOUT || (err == REVERSE_PROXY_E_SUCCESS && bytes != sizeof(cmd))) {
			continue;
		} else if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(conn_client, "Connection closed");
			break;
		}
		cmd = le16toh(cmd);
		switch (cmd) {
		case 0xBBAA:
			/* plist command */
			if (_reverse_proxy_handle_plist_cmd(conn_client) < 0) {
				running = 0;
			}
			break;
		case 0x105:
			/* proxy command */
			if (_reverse_proxy_handle_proxy_cmd(conn_client) < 0) {
				running = 0;
			}
			break;
		default:
			/* unknown */
			debug_info("ERROR: Unknown request 0x%x", cmd);
			_reverse_proxy_log(conn_client, "ERROR: Unknown request 0x%x", cmd);
			running = 0;
			break;
		}
	}

leave:
	_reverse_proxy_status(conn_client, RP_STATUS_TERMINATE, "Terminated");
	if (conn_client) {
		reverse_proxy_client_free(conn_client);
	}

	return NULL;
}

static void* _reverse_proxy_control_thread(void *cdata)
{
	reverse_proxy_client_t client = (reverse_proxy_client_t)cdata;
	THREAD_T th_conn = THREAD_T_NULL;
	int running = 1;
	_reverse_proxy_status(client, RP_STATUS_READY, "Ready");
	while (client && client->parent && running) {
		uint32_t cmd = 0;
		uint32_t bytes = 0;
		reverse_proxy_error_t err = reverse_proxy_receive_with_timeout(client, (char*)&cmd, sizeof(cmd), &bytes, 1000);
		if (err == REVERSE_PROXY_E_TIMEOUT || (err == REVERSE_PROXY_E_SUCCESS && bytes != sizeof(cmd))) {
			continue;
		} else if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(client, "Connection closed");
			break;
		}
		cmd = le32toh(cmd);
		switch (cmd) {
		case 1:
			/* connection request */
			debug_info("ReverseProxy<%p> got connect request", client);
			_reverse_proxy_status(client, RP_STATUS_CONNECT_REQ, "Connect Request");
			if (thread_new(&th_conn, _reverse_proxy_connection_thread, client) != 0) {
				debug_info("ERROR: Failed to start connection thread");
				th_conn = THREAD_T_NULL;
				running = 0;
			}
			break;
		case 2:
			/* shutdown request */
			debug_info("ReverseProxy<%p> got shutdown request", client);
			_reverse_proxy_status(client, RP_STATUS_SHUTDOWN_REQ, "Shutdown Request");
			running = 0;
			break;
		default:
			/* unknown */
			debug_info("ERROR: Unknown request 0x%x", cmd);
			_reverse_proxy_log(client, "ERROR: Unknown request 0x%x", cmd);
			running = 0;
			break;
		}
	}
	_reverse_proxy_log(client, "Terminating");

	client->th_ctrl = THREAD_T_NULL;
	if (th_conn) {
		debug_info("joining connection thread");
		thread_join(th_conn);
		thread_free(th_conn);
	}

	_reverse_proxy_status(client, RP_STATUS_TERMINATE, "Terminated");

	return NULL;
}

reverse_proxy_error_t reverse_proxy_client_start_proxy(reverse_proxy_client_t client, int control_protocol_version)
{
	char buf[16] = {0, };
	uint32_t bytes = 0;
	reverse_proxy_error_t err = REVERSE_PROXY_E_UNKNOWN_ERROR;

	if (!client) {
		return REVERSE_PROXY_E_INVALID_ARG;
	}
	if (control_protocol_version < 1 || control_protocol_version > 2) {
		debug_info("invalid protocol version %d, must be 1 or 2", control_protocol_version);
		return REVERSE_PROXY_E_INVALID_ARG;
	}

	if (control_protocol_version == 2) {
		err = reverse_proxy_send(client, CTRLCMD, sizeof(CTRLCMD), &bytes);
		if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(client, "ERROR: Failed to send " CTRLCMD " to device, error %d", err);
			return err;
		}
		plist_t dict = plist_new_dict();
		plist_dict_set_item(dict, "Command", plist_new_string(CTRLCMD));
		plist_dict_set_item(dict, "CtrlProtoVersion", plist_new_uint(client->protoversion));
		err = reverse_proxy_send_plist(client, dict);
		plist_free(dict);
		if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(client, "ERROR: Could not send " CTRLCMD " plist command, error %d", err);
			return err;
		}
		dict = NULL;
		err = reverse_proxy_receive_plist(client, &dict);
		if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(client, "ERROR: Could not receive " CTRLCMD " plist reply, error %d", err);
			return err;
		}
		plist_t node = plist_dict_get_item(dict, "ConnPort");
		if (node && plist_get_node_type(node) == PLIST_UINT) {
			uint64_t u64val = 0;
			plist_get_uint_val(node, &u64val);
			client->conn_port = (uint16_t)u64val;
		} else {
			_reverse_proxy_log(client, "ERROR: Could not get ConnPort value");
			return REVERSE_PROXY_E_UNKNOWN_ERROR;
		}
		client->protoversion = 2;
	} else {
		err = reverse_proxy_send(client, HELLOCTRLCMD, sizeof(HELLOCTRLCMD), &bytes);
		if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(client, "ERROR: Failed to send " HELLOCTRLCMD " to device, error %d", err);
			return err;
		}

		bytes = 0;
		err = reverse_proxy_receive(client, buf, sizeof(HELLOCTRLCMD)-1, &bytes);
		if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(client, "ERROR: Could not receive " HELLOCTRLCMD " reply, error %d", err);
			return err;
		}

		uint16_t cport = 0;
		bytes = 0;
		err = reverse_proxy_receive(client, (char*)&cport, 2, &bytes);
		if (err != REVERSE_PROXY_E_SUCCESS) {
			_reverse_proxy_log(client, "ERROR: Failed to receive connection port, error %d", err);
			return err;
		}
		client->conn_port = le16toh(cport);
		client->protoversion = 1;
	}

	if (thread_new(&(client->th_ctrl), _reverse_proxy_control_thread, client) != 0) {
		_reverse_proxy_log(client, "ERROR: Failed to start control thread");
		client->th_ctrl = THREAD_T_NULL; /* undefined after failure */
		err = REVERSE_PROXY_E_UNKNOWN_ERROR;
	}

	return err;
}

reverse_proxy_error_t reverse_proxy_client_create_with_service(idevice_t device, reverse_proxy_client_t* client, const char* label)
{
	reverse_proxy_error_t err = REVERSE_PROXY_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, "com.apple.PurpleReverseProxy.Ctrl", (void**)client, label, SERVICE_CONSTRUCTOR(reverse_proxy_client_new), &err);
	if (!*client) {
		return err;
	}
	(*client)->label = strdup(label);
	(*client)->type = RP_TYPE_CTRL;

	return REVERSE_PROXY_E_SUCCESS;
}

reverse_proxy_error_t reverse_proxy_client_create_with_port(idevice_t device, reverse_proxy_client_t* client, uint16_t device_port)
{
	reverse_proxy_client_t client_loc = NULL;
	reverse_proxy_error_t err;

	struct lockdownd_service_descriptor svc;
	svc.port = device_port;
	svc.ssl_enabled = 0;
	svc.identifier = NULL;

	err = reverse_proxy_client_new(device, &svc, &client_loc);
	if (err != REVERSE_PROXY_E_SUCCESS) {
		return err;
	}

	client_loc->type = RP_TYPE_CTRL;
	*client = client_loc;

	return REVERSE_PROXY_E_SUCCESS;
}

reverse_proxy_error_t reverse_proxy_client_free(reverse_proxy_client_t client)
{
	if (!client)
		return REVERSE_PROXY_E_INVALID_ARG;
	service_client_t parent = client->parent;
	client->parent = NULL;
	if (client->th_ctrl) {
		debug_info("joining control thread");
		thread_join(client->th_ctrl);
		thread_free(client->th_ctrl);
		client->th_ctrl = THREAD_T_NULL;
	}
	reverse_proxy_error_t err = reverse_proxy_error(service_client_free(parent));
	free(client->label);
	free(client);

	return err;
}

reverse_proxy_client_type_t reverse_proxy_get_type(reverse_proxy_client_t client)
{
	if (!client)
		return 0;
	return client->type;
}

void reverse_proxy_client_set_status_callback(reverse_proxy_client_t client, reverse_proxy_status_cb_t status_callback, void* user_data)
{
	if (!client) {
		return;
	}
	client->status_cb = status_callback;
	client->status_cb_user_data = user_data;
}

void reverse_proxy_client_set_log_callback(reverse_proxy_client_t client, reverse_proxy_log_cb_t log_callback, void* user_data)
{
	if (!client) {
		return;
	}
	client->log_cb = log_callback;
	client->log_cb_user_data = user_data;
}

void reverse_proxy_client_set_data_callback(reverse_proxy_client_t client, reverse_proxy_data_cb_t data_callback, void* user_data)
{
	if (!client) {
		return;
	}
	client->data_cb = data_callback;
	client->data_cb_user_data = user_data;
}

reverse_proxy_error_t reverse_proxy_send(reverse_proxy_client_t client, const char* data, uint32_t len, uint32_t* sent)
{
	reverse_proxy_error_t err = reverse_proxy_error(service_send(client->parent, data, len, sent));
	return err;
}

reverse_proxy_error_t reverse_proxy_receive_with_timeout(reverse_proxy_client_t client, char* buffer, uint32_t len, uint32_t* received, unsigned int timeout)
{
	if (!client)
		return REVERSE_PROXY_E_INVALID_ARG;
	return reverse_proxy_error(service_receive_with_timeout(client->parent, buffer, len, received, timeout));
}

reverse_proxy_error_t reverse_proxy_receive(reverse_proxy_client_t client, char* buffer, uint32_t len, uint32_t* received)
{
	return reverse_proxy_receive_with_timeout(client, buffer, len, received, 20000);
}

reverse_proxy_error_t reverse_proxy_send_plist(reverse_proxy_client_t client, plist_t plist)
{
	reverse_proxy_error_t err;
	uint32_t len = 0;
	char* buf = NULL;
	uint32_t bytes = 0;

	plist_to_bin(plist, &buf, &len);

	if (!buf) {
		return REVERSE_PROXY_E_INVALID_ARG;
	}

	debug_info("Sending %u bytes", len);

	uint32_t slen = htole32(len);
	err = reverse_proxy_send(client, (char*)&slen, sizeof(slen), &bytes);
	if (err != REVERSE_PROXY_E_SUCCESS) {
		free(buf);
		debug_info("ERROR: Unable to send data length, error %d. Sent %u/%u bytes.", err, bytes, (uint32_t)sizeof(slen));
		return err;
	}
	uint32_t done = 0;
	do {
		bytes = 0;
		err = reverse_proxy_send(client, buf+done, len-done, &bytes);
		if (err != REVERSE_PROXY_E_SUCCESS) {
			break;
		}
		done += bytes;
	} while (done < len);
	free(buf);
	if (err != REVERSE_PROXY_E_SUCCESS || done != len) {
		debug_info("ERROR: Unable to send data, error %d. Sent %u/%u bytes.", err, done, len);
		return err;
	}

	debug_info("Sent %u bytes", len);

	return REVERSE_PROXY_E_SUCCESS;
}

reverse_proxy_error_t reverse_proxy_receive_plist(reverse_proxy_client_t client, plist_t* plist)
{
	return reverse_proxy_receive_plist_with_timeout(client, plist, 20000);
}

reverse_proxy_error_t reverse_proxy_receive_plist_with_timeout(reverse_proxy_client_t client, plist_t * plist, uint32_t timeout_ms)
{
	uint32_t len;
	uint32_t bytes;
	reverse_proxy_error_t err;

	err = reverse_proxy_receive_with_timeout(client, (char*)&len, sizeof(len), &bytes, timeout_ms);
	if (err != REVERSE_PROXY_E_SUCCESS) {
		if (err != REVERSE_PROXY_E_TIMEOUT) {
			debug_info("ERROR: Unable to receive packet length, error %d\n", err);
		}
		return err;
	}

	len = le32toh(len);
	char* buf = calloc(1, len);
	if (!buf) {
		debug_info("ERROR: Out of memory");
		return REVERSE_PROXY_E_UNKNOWN_ERROR;
	}

	uint32_t done = 0;
	do {
		bytes = 0;
		err = reverse_proxy_receive_with_timeout(client, buf+done, len-done, &bytes, timeout_ms);
		if (err != REVERSE_PROXY_E_SUCCESS) {
			break;
		}
		done += bytes;
	} while (done < len);

	if (err != REVERSE_PROXY_E_SUCCESS || done != len) {
		free(buf);
		debug_info("ERROR: Unable to receive data, error %d. Received %u/%u bytes.", err, done, len);
		return err;
	}

	debug_info("Received %u bytes", len);

	plist_from_bin(buf, len, plist);
	free(buf);

	if (!(*plist)) {
		debug_info("ERROR: Failed to convert buffer to plist");
		return REVERSE_PROXY_E_PLIST_ERROR;
	}

	return REVERSE_PROXY_E_SUCCESS;
}
