/*
 * installation_proxy.c
 * com.apple.mobile.installation_proxy service implementation.
 *
 * Copyright (c) 2013 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2009 Nikias Bassen, All Rights Reserved.
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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <plist/plist.h>

#include "installation_proxy.h"
#include "property_list_service.h"
#include "common/debug.h"

struct instproxy_status_data {
	instproxy_client_t client;
	instproxy_status_cb_t cbfunc;
	char *operation;
	void *user_data;
};

/**
 * Locks an installation_proxy client, used for thread safety.
 *
 * @param client The installation_proxy client to lock
 */
static void instproxy_lock(instproxy_client_t client)
{
	debug_info("InstallationProxy: Locked");
	mutex_lock(&client->mutex);
}

/**
 * Unlocks an installation_proxy client, used for thread safety.
 * 
 * @param client The installation_proxy client to lock
 */
static void instproxy_unlock(instproxy_client_t client)
{
	debug_info("InstallationProxy: Unlocked");
	mutex_unlock(&client->mutex);
}

/**
 * Convert a property_list_service_error_t value to an instproxy_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err A property_list_service_error_t error code
 *
 * @return A matching instproxy_error_t error code,
 *     INSTPROXY_E_UNKNOWN_ERROR otherwise.
 */
static instproxy_error_t instproxy_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return INSTPROXY_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return INSTPROXY_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return INSTPROXY_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return INSTPROXY_E_CONN_FAILED;
		case PROPERTY_LIST_SERVICE_E_RECEIVE_TIMEOUT:
			return INSTPROXY_E_RECEIVE_TIMEOUT;
		default:
			break;
	}
	return INSTPROXY_E_UNKNOWN_ERROR;
}

instproxy_error_t instproxy_client_new(idevice_t device, lockdownd_service_descriptor_t service, instproxy_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	instproxy_error_t err = instproxy_error(property_list_service_client_new(device, service, &plistclient));
	if (err != INSTPROXY_E_SUCCESS) {
		return err;
	}

	instproxy_client_t client_loc = (instproxy_client_t) malloc(sizeof(struct instproxy_client_private));
	client_loc->parent = plistclient;
	mutex_init(&client_loc->mutex);
	client_loc->status_updater = (thread_t)NULL;

	*client = client_loc;
	return INSTPROXY_E_SUCCESS;
}

instproxy_error_t instproxy_client_start_service(idevice_t device, instproxy_client_t * client, const char* label)
{
	instproxy_error_t err = INSTPROXY_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, INSTPROXY_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(instproxy_client_new), &err);
	return err;
}

instproxy_error_t instproxy_client_free(instproxy_client_t client)
{
	if (!client)
		return INSTPROXY_E_INVALID_ARG;

	property_list_service_client_free(client->parent);
	client->parent = NULL;
	if (client->status_updater) {
		debug_info("joining status_updater");
		thread_join(client->status_updater);
	}
	mutex_destroy(&client->mutex);
	free(client);

	return INSTPROXY_E_SUCCESS;
}

/**
 * Send a command with specified options to the device.
 * Only used internally.
 *
 * @param client The connected installation_proxy client.
 * @param command The command to execute. Required.
 * @param client_options The client options to use, as PLIST_DICT, or NULL.
 * @param appid The ApplicationIdentifier to add or NULL if not required.
 * @param package_path The installation package path or NULL if not required.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 */
static instproxy_error_t instproxy_send_command(instproxy_client_t client, const char *command, plist_t client_options, const char *appid, const char *package_path)
{
	if (!client || !command || (client_options && (plist_get_node_type(client_options) != PLIST_DICT)))
		return INSTPROXY_E_INVALID_ARG;

	plist_t dict = plist_new_dict();
	if (appid) {
		plist_dict_set_item(dict, "ApplicationIdentifier", plist_new_string(appid));
	}
	if (client_options && (plist_dict_get_size(client_options) > 0)) {
		plist_dict_set_item(dict, "ClientOptions", plist_copy(client_options));
	}
	plist_dict_set_item(dict, "Command", plist_new_string(command));
	if (package_path) {
		plist_dict_set_item(dict, "PackagePath", plist_new_string(package_path));
	}

	instproxy_error_t err = instproxy_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	return err;
}

instproxy_error_t instproxy_browse(instproxy_client_t client, plist_t client_options, plist_t *result)
{
	if (!client || !client->parent || !result)
		return INSTPROXY_E_INVALID_ARG;

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	instproxy_lock(client);
	res = instproxy_send_command(client, "Browse", client_options, NULL, NULL);
	if (res != INSTPROXY_E_SUCCESS) {
		debug_info("could not send plist");
		goto leave_unlock;
	}

	int browsing = 0;
	plist_t apps_array = plist_new_array();
	plist_t dict = NULL;

	do {
		browsing = 0;
		dict = NULL;
		res = instproxy_error(property_list_service_receive_plist(client->parent, &dict));
		if (res != INSTPROXY_E_SUCCESS && res != INSTPROXY_E_RECEIVE_TIMEOUT) {
			break;
		}
		if (dict) {
			uint64_t i;
			uint64_t current_amount = 0;
			char *status = NULL;
			plist_t camount = plist_dict_get_item(dict, "CurrentAmount");
			plist_t pstatus = plist_dict_get_item(dict, "Status");
			if (camount) {
				plist_get_uint_val(camount, &current_amount);
			}
			if (current_amount > 0) {
				plist_t current_list = plist_dict_get_item(dict, "CurrentList");
				for (i = 0; current_list && (i < current_amount); i++) {
					plist_t item = plist_array_get_item(current_list, i);
					plist_array_append_item(apps_array, plist_copy(item));
				}
			}
			if (pstatus) {
				plist_get_string_val(pstatus, &status);
			}
			if (status) {
				if (!strcmp(status, "BrowsingApplications")) {
					browsing = 1;
				} else if (!strcmp(status, "Complete")) {
					debug_info("Browsing applications completed");
					res = INSTPROXY_E_SUCCESS;
				}
				free(status);
			}
			plist_free(dict);
		}
	} while (browsing);

	if (res == INSTPROXY_E_SUCCESS) {
		*result = apps_array;
	} else {
		plist_free(apps_array);
	}

leave_unlock:
	instproxy_unlock(client);
	return res;
}

/**
 * Internally used function that will synchronously receive messages from
 * the specified installation_proxy until it completes or an error occurs.
 *
 * If status_cb is not NULL, the callback function will be called each time
 * a status update or error message is received.
 *
 * @param client The connected installation proxy client
 * @param status_cb Pointer to a callback function or NULL
 * @param operation Operation name. Will be passed to the callback function
 *        in async mode or shown in debug messages in sync mode. 
 * @param user_data Callback data passed to status_cb.
 */
static instproxy_error_t instproxy_perform_operation(instproxy_client_t client, instproxy_status_cb_t status_cb, const char *operation, void *user_data)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;
	int ok = 1;
	plist_t dict = NULL;

	do {
		instproxy_lock(client);
		res = instproxy_error(property_list_service_receive_plist_with_timeout(client->parent, &dict, 1000));
		instproxy_unlock(client);
		if (res != INSTPROXY_E_SUCCESS && res != INSTPROXY_E_RECEIVE_TIMEOUT) {
			debug_info("could not receive plist, error %d", res);
			break;
		}
		if (dict) {
			/* invoke callback function */
			if (status_cb) {
				status_cb(operation, dict, user_data);
			}
			/* check for 'Error', so we can abort cleanly */
			plist_t err = plist_dict_get_item(dict, "Error");
			if (err) {
#ifndef STRIP_DEBUG_CODE
				char *err_msg = NULL;
				plist_get_string_val(err, &err_msg);
				if (err_msg) {
					debug_info("(%s): ERROR: %s", operation, err_msg);
					free(err_msg);
				}
#endif
				ok = 0;
				res = INSTPROXY_E_OP_FAILED;
			}
			/* get 'Status' */
			plist_t status = plist_dict_get_item(dict, "Status");
			if (status) {
				char *status_msg = NULL;
				plist_get_string_val(status, &status_msg);
				if (status_msg) {
					if (!strcmp(status_msg, "Complete")) {
						ok = 0;
						res = INSTPROXY_E_SUCCESS;
					}
#ifndef STRIP_DEBUG_CODE
					plist_t npercent = plist_dict_get_item(dict, "PercentComplete");
					if (npercent) {
						uint64_t val = 0;
						int percent;
						plist_get_uint_val(npercent, &val);
						percent = val;
						debug_info("(%s): %s (%d%%)", operation, status_msg, percent);
					} else {
						debug_info("(%s): %s", operation, status_msg);
					}
#endif
					free(status_msg);
				}
			}
			plist_free(dict);
			dict = NULL;
		}
	} while (ok && client->parent);

	return res;
}

/**
 * Internally used status updater thread function that will call the specified
 * callback function when status update messages (or error messages) are
 * received.
 *
 * @param arg Pointer to an allocated struct instproxy_status_data that holds
 *     the required data about the connected client and the callback function.
 *
 * @return Always NULL.
 */
static void* instproxy_status_updater(void* arg)
{	
	struct instproxy_status_data *data = (struct instproxy_status_data*)arg;

	/* run until the operation is complete or an error occurs */
	(void)instproxy_perform_operation(data->client, data->cbfunc, data->operation, data->user_data);

	/* cleanup */
	instproxy_lock(data->client);
	debug_info("done, cleaning up.");
	if (data->operation) {
		free(data->operation);
	}
	data->client->status_updater = (thread_t)NULL;
	instproxy_unlock(data->client);
	free(data);

	return NULL;
}

/**
 * Internally used helper function that creates a status updater thread which
 * will call the passed callback function when status updates occur.
 * If status_cb is NULL no thread will be created, but the operation will
 * run synchronously until it completes or an error occurs.
 *
 * @param client The connected installation proxy client
 * @param status_cb Pointer to a callback function or NULL
 * @param operation Operation name. Will be passed to the callback function
 *        in async mode or shown in debug messages in sync mode.
 * @param user_data Callback data passed to status_cb.
 *
 * @return INSTPROXY_E_SUCCESS when the thread was created (async mode), or
 *         when the operation completed successfully (sync).
 *         An INSTPROXY_E_* error value is returned if an error occured.
 */
static instproxy_error_t instproxy_create_status_updater(instproxy_client_t client, instproxy_status_cb_t status_cb, const char *operation, void *user_data)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;
	if (status_cb) {
		/* async mode */
		struct instproxy_status_data *data = (struct instproxy_status_data*)malloc(sizeof(struct instproxy_status_data));
		if (data) {
			data->client = client;
			data->cbfunc = status_cb;
			data->operation = strdup(operation);
			data->user_data = user_data;

			if (thread_create(&client->status_updater, instproxy_status_updater, data) == 0) {
				res = INSTPROXY_E_SUCCESS;
			}
		}
	} else {
		/* sync mode */
		res = instproxy_perform_operation(client, NULL, operation, NULL);
	}
	return res;
}


/**
 * Internal function used by instproxy_install and instproxy_upgrade.
 *
 * @param client The connected installation_proxy client
 * @param pkg_path Path of the installation package (inside the AFC jail)
 * @param client_options The client options to use, as PLIST_DICT, or NULL.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 * @param command The command to execute.
 * @param user_data Callback data passed to status_cb.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured. 
 */
static instproxy_error_t instproxy_install_or_upgrade(instproxy_client_t client, const char *pkg_path, plist_t client_options, instproxy_status_cb_t status_cb, const char *command, void *user_data)
{
	if (!client || !client->parent || !pkg_path) {
		return INSTPROXY_E_INVALID_ARG;
	}
	if (client->status_updater) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_lock(client);
	instproxy_error_t res = instproxy_send_command(client, command, client_options, NULL, pkg_path);
	instproxy_unlock(client);

	if (res != INSTPROXY_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	return instproxy_create_status_updater(client, status_cb, command, user_data);
}

instproxy_error_t instproxy_install(instproxy_client_t client, const char *pkg_path, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	return instproxy_install_or_upgrade(client, pkg_path, client_options, status_cb, "Install", user_data);
}

instproxy_error_t instproxy_upgrade(instproxy_client_t client, const char *pkg_path, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	return instproxy_install_or_upgrade(client, pkg_path, client_options, status_cb, "Upgrade", user_data);
}

instproxy_error_t instproxy_uninstall(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	if (!client || !client->parent || !appid) {
		return INSTPROXY_E_INVALID_ARG;
	}

	if (client->status_updater) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	instproxy_lock(client);
	res = instproxy_send_command(client, "Uninstall", client_options, appid, NULL);
	instproxy_unlock(client);

	if (res != INSTPROXY_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}

	return instproxy_create_status_updater(client, status_cb, "Uninstall", user_data);
}

instproxy_error_t instproxy_lookup_archives(instproxy_client_t client, plist_t client_options, plist_t *result)
{
	if (!client || !client->parent || !result)
		return INSTPROXY_E_INVALID_ARG;

	instproxy_lock(client);
	instproxy_error_t res = instproxy_send_command(client, "LookupArchives", client_options, NULL, NULL);

	if (res != INSTPROXY_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		goto leave_unlock;
	}

	res = instproxy_error(property_list_service_receive_plist(client->parent, result));
	if (res != INSTPROXY_E_SUCCESS) {
		debug_info("could not receive plist, error %d", res);
		goto leave_unlock;
	}

	res = INSTPROXY_E_SUCCESS;

leave_unlock:
	instproxy_unlock(client);
	return res;
}

instproxy_error_t instproxy_archive(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	if (!client || !client->parent || !appid)
		return INSTPROXY_E_INVALID_ARG;

	if (client->status_updater) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_lock(client);
	instproxy_error_t res = instproxy_send_command(client, "Archive", client_options, appid, NULL);
	instproxy_unlock(client);

	if (res != INSTPROXY_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}
	return instproxy_create_status_updater(client, status_cb, "Archive", user_data);
}

instproxy_error_t instproxy_restore(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	if (!client || !client->parent || !appid)
		return INSTPROXY_E_INVALID_ARG;

	if (client->status_updater) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_lock(client);
	instproxy_error_t res = instproxy_send_command(client, "Restore", client_options, appid, NULL);
	instproxy_unlock(client);

	if (res != INSTPROXY_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}
	return instproxy_create_status_updater(client, status_cb, "Restore", user_data);
}

instproxy_error_t instproxy_remove_archive(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	if (!client || !client->parent || !appid)
		return INSTPROXY_E_INVALID_ARG;

	if (client->status_updater) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_lock(client);
	instproxy_error_t res = instproxy_send_command(client, "RemoveArchive", client_options, appid, NULL);
	instproxy_unlock(client);

	if (res != INSTPROXY_E_SUCCESS) {
		debug_info("could not send plist, error %d", res);
		return res;
	}
	return instproxy_create_status_updater(client, status_cb, "RemoveArchive", user_data);
}

plist_t instproxy_client_options_new()
{
	return plist_new_dict();
}

void instproxy_client_options_add(plist_t client_options, ...)
{
	if (!client_options)
		return;
	va_list args;
	va_start(args, client_options);
	char *arg = va_arg(args, char*);
	while (arg) {
		char *key = strdup(arg);
		if (!strcmp(key, "SkipUninstall")) {
			int intval = va_arg(args, int);
			plist_dict_set_item(client_options, key, plist_new_bool(intval));
		} else if (!strcmp(key, "ApplicationSINF") || !strcmp(key, "iTunesMetadata") || !strcmp(key, "ReturnAttributes")) {
			plist_t plistval = va_arg(args, plist_t);
			if (!plistval) {
				free(key);
				break;
			}
			plist_dict_set_item(client_options, key, plist_copy(plistval));
		} else {
			char *strval = va_arg(args, char*);
			if (!strval) {
				free(key);
				break;
			}
			plist_dict_set_item(client_options, key, plist_new_string(strval));
		}
		free(key);
		arg = va_arg(args, char*);
	}
	va_end(args);
}

void instproxy_client_options_free(plist_t client_options)
{
	if (client_options) {
		plist_free(client_options);
	}
}

instproxy_error_t instproxy_client_get_path_for_bundle_identifier(instproxy_client_t client, const char* appid, char** path)
{
	if (!client || !client->parent || !appid)
		return INSTPROXY_E_INVALID_ARG;

	plist_t apps = NULL;

	// create client options for any application types
	plist_t client_opts = instproxy_client_options_new();
	instproxy_client_options_add(client_opts, "ApplicationType", "Any", NULL);

	// only return attributes we need
	plist_t return_attributes = plist_new_array();
	plist_array_append_item(return_attributes, plist_new_string("CFBundleIdentifier"));
	plist_array_append_item(return_attributes, plist_new_string("CFBundleExecutable"));
	plist_array_append_item(return_attributes, plist_new_string("Path"));
	instproxy_client_options_add(client_opts, "ReturnAttributes", return_attributes, NULL);
	plist_free(return_attributes);
	return_attributes = NULL;

	// query device for list of apps
	instproxy_error_t ierr = instproxy_browse(client, client_opts, &apps);
	instproxy_client_options_free(client_opts);
	if (ierr != INSTPROXY_E_SUCCESS) {
		return ierr;
	}

	plist_t app_found = NULL;
	uint32_t i;
	for (i = 0; i < plist_array_get_size(apps); i++) {
		char *appid_str = NULL;
		plist_t app_info = plist_array_get_item(apps, i);
		plist_t idp = plist_dict_get_item(app_info, "CFBundleIdentifier");
		if (idp) {
			plist_get_string_val(idp, &appid_str);
		}
		if (appid_str && strcmp(appid, appid_str) == 0) {
			app_found = app_info;
		}
		free(appid_str);
		if (app_found) {
			break;
		}
	}

	if (!app_found) {
		if (apps)
			plist_free(apps);
		*path = NULL;
		return INSTPROXY_E_OP_FAILED;
	}

	char* path_str = NULL;
	plist_t path_p = plist_dict_get_item(app_found, "Path");
	if (path_p) {
		plist_get_string_val(path_p, &path_str);
	}

	char* exec_str = NULL;
	plist_t exec_p = plist_dict_get_item(app_found, "CFBundleExecutable");
	if (exec_p) {
		plist_get_string_val(exec_p, &exec_str);
	}

	if (!path_str) {
		debug_info("app path not found");
		return INSTPROXY_E_OP_FAILED;
	}

	if (!exec_str) {
		debug_info("bundle executable not found");
		return INSTPROXY_E_OP_FAILED;
	}

	plist_free(apps);

	char* ret = (char*)malloc(strlen(path_str) + 1 + strlen(exec_str) + 1);
	strcpy(ret, path_str);
	strcat(ret, "/");
	strcat(ret, exec_str);

	*path = ret;

	if (path_str) {
		free(path_str);
	}

	if (exec_str) {
		free(exec_str);
	}

	return INSTPROXY_E_SUCCESS;
}
