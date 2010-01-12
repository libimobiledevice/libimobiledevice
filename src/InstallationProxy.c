/*
 * InstallationProxy.c
 * Installation Proxy implementation.
 *
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
#include <arpa/inet.h>
#include <plist/plist.h>

#include "InstallationProxy.h"
#include "property_list_service.h"
#include "debug.h"

struct instproxy_status_data {
	instproxy_client_t client;
	instproxy_status_cb_t cbfunc;
	char *operation;
};

/** Locks an installation_proxy client, done for thread safety stuff.
 *
 * @param client The installation_proxy client to lock
 */
static void instproxy_lock(instproxy_client_t client)
{
	log_debug_msg("InstallationProxy: Locked\n");
	g_mutex_lock(client->mutex);
}

/** Unlocks an installation_proxy client, done for thread safety stuff.
 * 
 * @param client The installation_proxy client to lock
 */
static void instproxy_unlock(instproxy_client_t client)
{
	log_debug_msg("InstallationProxy: Unlocked\n");
	g_mutex_unlock(client->mutex);
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
		default:
			break;
	}
	return INSTPROXY_E_UNKNOWN_ERROR;
}

/**
 * Creates a new installation_proxy client
 *
 * @param device The device to connect to
 * @param dst_port Destination port (usually given by lockdownd_start_service).
 * @param client Pointer that will be set to a newly allocated
 *     instproxy_client_t upon successful return.
 *
 * @return INSTPROXY_E_SUCCESS on success, or an INSTPROXY_E_* error value
 *     when an error occured.
 */
instproxy_error_t instproxy_client_new(iphone_device_t device, int dst_port, instproxy_client_t *client)
{
	/* makes sure thread environment is available */
	if (!g_thread_supported())
		g_thread_init(NULL);

	if (!device)
		return INSTPROXY_E_INVALID_ARG;

	property_list_service_client_t plistclient = NULL;
	if (property_list_service_client_new(device, dst_port, &plistclient) != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		return INSTPROXY_E_CONN_FAILED;
	}

	instproxy_client_t client_loc = (instproxy_client_t) malloc(sizeof(struct instproxy_client_int));
	client_loc->parent = plistclient;
	client_loc->mutex = g_mutex_new();
	client_loc->status_updater = NULL;

	*client = client_loc;
	return INSTPROXY_E_SUCCESS;
}

/**
 * Frees an installation_proxy client.
 *
 * @param client The installation_proxy client to free.
 *
 * @return INSTPROXY_E_SUCCESS on success
 *      or INSTPROXY_E_INVALID_ARG if client is NULL.
 */
instproxy_error_t instproxy_client_free(instproxy_client_t client)
{
	if (!client)
		return INSTPROXY_E_INVALID_ARG;

	property_list_service_client_free(client->parent);
	client->parent = NULL;
	if (client->status_updater) {
		log_dbg_msg(DBGMASK_INSTPROXY, "joining status_updater");
		g_thread_join(client->status_updater);
	}
	if (client->mutex) {
		g_mutex_free(client->mutex);
	}
	free(client);

	return INSTPROXY_E_SUCCESS;
}

/**
 * List installed applications. This function runs synchronously.
 *
 * @param client The connected installation_proxy client
 * @param apptype The type of applications to list.
 * @param result Pointer that will be set to a plist that will hold an array
 *        of PLIST_DICT holding information about the applications found.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 */
instproxy_error_t instproxy_browse(instproxy_client_t client, instproxy_apptype_t apptype, plist_t *result)
{
	if (!client || !client->parent || !result)
		return INSTPROXY_E_INVALID_ARG;

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;
	int browsing = 0;
	plist_t apps_array = NULL;

	plist_t dict = plist_new_dict();
	if (apptype != INSTPROXY_APPTYPE_ALL) {
		plist_t client_opts = plist_new_dict();
		plist_t p_apptype = NULL;
		switch (apptype) {
			case INSTPROXY_APPTYPE_SYSTEM:
				p_apptype = plist_new_string("System");
				break;
			case INSTPROXY_APPTYPE_USER:
				p_apptype = plist_new_string("User");
				break;
			default:
				log_dbg_msg(DBGMASK_INSTPROXY, "%s: unknown apptype %d given, using INSTPROXY_APPTYPE_USER instead\n", __func__, apptype);
				p_apptype = plist_new_string("User");
				break;
		}
		plist_dict_insert_item(client_opts, "ApplicationType", p_apptype);
		plist_dict_insert_item(dict, "ClientOptions", client_opts);
	}
	plist_dict_insert_item(dict, "Command", plist_new_string("Browse"));

	instproxy_lock(client);
	res = instproxy_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	if (res != INSTPROXY_E_SUCCESS) {
		log_dbg_msg(DBGMASK_INSTPROXY, "%s: could not send plist\n", __func__);
		goto leave_unlock;
	}

	apps_array = plist_new_array();

	do {
		browsing = 0;
		dict = NULL;
		res = instproxy_error(property_list_service_receive_plist(client->parent, &dict));
		if (res != INSTPROXY_E_SUCCESS) {
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
					log_dbg_msg(DBGMASK_INSTPROXY, "%s: Browsing applications completed\n");
					res = INSTPROXY_E_SUCCESS;
				}
				free(status);
			}
			plist_free(dict);
		}
	} while (browsing);

	if (res == INSTPROXY_E_SUCCESS) {
		*result = apps_array;
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
 */
static instproxy_error_t instproxy_perform_operation(instproxy_client_t client, instproxy_status_cb_t status_cb, const char *operation)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;
	int ok = 1;
	plist_t dict = NULL;

	do {
		instproxy_lock(client);
		res = instproxy_error(property_list_service_receive_plist_with_timeout(client->parent, &dict, 30000));
		instproxy_unlock(client);
		if (res != INSTPROXY_E_SUCCESS) {
			log_dbg_msg(DBGMASK_INSTPROXY, "%s: could not receive plist, error %d\n", __func__, res);
			break;
		}
		if (dict) {
			/* invoke callback function */
			if (status_cb) {
				status_cb(operation, dict);
			}
			/* check for 'Error', so we can abort cleanly */
			plist_t err = plist_dict_get_item(dict, "Error");
			if (err) {
#ifndef STRIP_DEBUG_CODE
				char *err_msg = NULL;
				plist_get_string_val(err, &err_msg);
				if (err_msg) {
					log_dbg_msg(DBGMASK_INSTPROXY, "%s(%s): ERROR: %s\n", __func__, operation, err_msg);
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
						log_dbg_msg(DBGMASK_INSTPROXY, "%s(%s): %s (%d%%)\n", __func__, operation, status_msg, percent);
					} else {
						log_dbg_msg(DBGMASK_INSTPROXY, "%s(%s): %s\n", __func__, operation, status_msg);
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
static gpointer instproxy_status_updater(gpointer arg)
{	
	struct instproxy_status_data *data = (struct instproxy_status_data*)arg;

	/* run until the operation is complete or an error occurs */
	(void)instproxy_perform_operation(data->client, data->cbfunc, data->operation);

	/* cleanup */
	instproxy_lock(data->client);
	log_dbg_msg(DBGMASK_INSTPROXY, "%s: done, cleaning up.\n", __func__);
	if (data->operation) {
	    free(data->operation);
	}
	data->client->status_updater = NULL;
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
 *
 * @return INSTPROXY_E_SUCCESS when the thread was created (async mode), or
 *         when the operation completed successfully (sync).
 *         An INSTPROXY_E_* error value is returned if an error occured.
 */
static instproxy_error_t instproxy_create_status_updater(instproxy_client_t client, instproxy_status_cb_t status_cb, const char *operation)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;
	if (status_cb) {
		/* async mode */
		struct instproxy_status_data *data = (struct instproxy_status_data*)malloc(sizeof(struct instproxy_status_data));
		if (data) {
			data->client = client;
			data->cbfunc = status_cb;
			data->operation = strdup(operation);

			client->status_updater = g_thread_create(instproxy_status_updater, data, TRUE, NULL);
			if (client->status_updater) {
				res = INSTPROXY_E_SUCCESS;
			}
		}
	} else {
		/* sync mode */
		res = instproxy_perform_operation(client, NULL, operation);
	}
	return res;
}


/**
 * Internal function used by instproxy_install and instproxy_upgrade.
 *
 * @param client The connected installation_proxy client
 * @param pkg_path Path of the installation package (inside the AFC jail)
 * @param sinf PLIST_DATA node holding the package's SINF data or NULL.
 * @param metadata PLIST_DATA node holding the packages's Metadata or NULL.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 * @param command The command to execute.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured. 
 */
static instproxy_error_t instproxy_install_or_upgrade(instproxy_client_t client, const char *pkg_path, plist_t sinf, plist_t metadata, instproxy_status_cb_t status_cb, const char *command)
{
	if (!client || !client->parent || !pkg_path) {
		return INSTPROXY_E_INVALID_ARG;
	}
	if (sinf && (plist_get_node_type(sinf) != PLIST_DATA)) {
		log_dbg_msg(DBGMASK_INSTPROXY, "%s(%s): ERROR: sinf data is not a PLIST_DATA node!\n", __func__, command);
		return INSTPROXY_E_INVALID_ARG;
	}
	if (metadata && (plist_get_node_type(metadata) != PLIST_DATA)) {
		log_dbg_msg(DBGMASK_INSTPROXY, "%s(%s): ERROR: metadata is not a PLIST_DATA node!\n", __func__, command);
		return INSTPROXY_E_INVALID_ARG;
	}

	if (client->status_updater) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	if (sinf && metadata) {
		plist_t client_opts = plist_new_dict();
		plist_dict_insert_item(client_opts, "ApplicationSINF", plist_copy(sinf));
		plist_dict_insert_item(client_opts, "iTunesMetadata", plist_copy(metadata));
		plist_dict_insert_item(dict, "ClientOptions", client_opts);
	}
	plist_dict_insert_item(dict, "Command", plist_new_string(command));
	plist_dict_insert_item(dict, "PackagePath", plist_new_string(pkg_path));

	instproxy_lock(client);
	res = instproxy_error(property_list_service_send_xml_plist(client->parent, dict));
	instproxy_unlock(client);

	plist_free(dict);

	if (res != INSTPROXY_E_SUCCESS) {
		log_dbg_msg(DBGMASK_INSTPROXY, "%s: could not send plist, error %d\n", __func__, res);
		return res;
	}

	return instproxy_create_status_updater(client, status_cb, command);
}

/**
 * Install an application on the device.
 *
 * @param client The connected installation_proxy client
 * @param pkg_path Path of the installation package (inside the AFC jail)
 * @param sinf PLIST_DATA node holding the package's SINF data or NULL.
 * @param metadata PLIST_DATA node holding the packages's Metadata or NULL.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_install(instproxy_client_t client, const char *pkg_path, plist_t sinf, plist_t metadata, instproxy_status_cb_t status_cb)
{
	return instproxy_install_or_upgrade(client, pkg_path, sinf, metadata, status_cb, "Install");
}

/**
 * Upgrade an application on the device. This function is nearly the same as
 * instproxy_install; the difference is that the installation progress on the
 * device is faster if the application is already installed.
 *
 * @param client The connected installation_proxy client
 * @param pkg_path Path of the installation package (inside the AFC jail)
 * @param sinf PLIST_DATA node holding the package's SINF data or NULL.
 * @param metadata PLIST_DATA node holding the packages's Metadata or NULL.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_upgrade(instproxy_client_t client, const char *pkg_path, plist_t sinf, plist_t metadata, instproxy_status_cb_t status_cb)
{
	return instproxy_install_or_upgrade(client, pkg_path, sinf, metadata, status_cb, "Upgrade");
}

/**
 * Uninstall an application from the device.
 *
 * @param client The connected installation proxy client
 * @param appid ApplicationIdentifier of the app to uninstall
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_uninstall(instproxy_client_t client, const char *appid, instproxy_status_cb_t status_cb)
{
	if (!client || !client->parent || !appid) {
		return INSTPROXY_E_INVALID_ARG;
	}

	if (client->status_updater) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;
	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "ApplicationIdentifier", plist_new_string(appid));
	plist_dict_insert_item(dict, "Command", plist_new_string("Uninstall"));

	instproxy_lock(client);
	res = instproxy_error(property_list_service_send_xml_plist(client->parent, dict));
	instproxy_unlock(client);

	plist_free(dict);

	if (res != INSTPROXY_E_SUCCESS) {
		log_dbg_msg(DBGMASK_INSTPROXY, "%s: could not send plist, error %d\n", __func__, res);
		return res;
	}

	return instproxy_create_status_updater(client, status_cb, "Uninstall");
}

/**
 * List archived applications. This function runs synchronously.
 *
 * @see instproxy_archive
 *
 * @param client The connected installation_proxy client
 * @param result Pointer that will be set to a plist containing a PLIST_DICT
 *        holding information about the archived applications found.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 */
instproxy_error_t instproxy_lookup_archives(instproxy_client_t client, plist_t *result)
{
	if (!client || !client->parent || !result)
		return INSTPROXY_E_INVALID_ARG;

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "Command", plist_new_string("LookupArchives"));

	instproxy_lock(client);

	res = instproxy_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != INSTPROXY_E_SUCCESS) {
		log_dbg_msg(DBGMASK_INSTPROXY, "%s: could not send plist, error %d\n", __func__, res);
		goto leave_unlock;
	}

	res = instproxy_error(property_list_service_receive_plist(client->parent, result));
	if (res != INSTPROXY_E_SUCCESS) {
		log_dbg_msg(DBGMASK_INSTPROXY, "%s: could not receive plist, error %d\n", __func__, res);
		goto leave_unlock;
	}

	res = INSTPROXY_E_SUCCESS;

leave_unlock:
	instproxy_unlock(client);
	return res;
}

/**
 * Archive an application on the device.
 * This function tells the device to make an archive of the specified
 * application. This results in the device creating a ZIP archive in the
 * 'ApplicationArchives' directory and uninstalling the application.
 *
 * @param client The connected installation proxy client
 * @param appid ApplicationIdentifier of the app to archive.
 * @param options This is either 0 for default behaviour (make an archive
 *        including app/user settings etc. AND uninstall the application),
 *        or one or a combination of the following options:
 *        INSTPROXY_ARCHIVE_APP_ONLY (1)
 *        INSTPROXY_ARCHIVE_SKIP_UNINSTALL (2)
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_archive(instproxy_client_t client, const char *appid, uint32_t options, instproxy_status_cb_t status_cb)
{
	if (!client || !client->parent || !appid)
		return INSTPROXY_E_INVALID_ARG;

	if (client->status_updater) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "ApplicationIdentifier", plist_new_string(appid));
	if (options > 0) {
		plist_t client_opts = plist_new_dict();
		if (options & INSTPROXY_ARCHIVE_APP_ONLY) {
			plist_dict_insert_item(client_opts, "ArchiveType", plist_new_string("ApplicationOnly"));
		}
		if (options & INSTPROXY_ARCHIVE_SKIP_UNINSTALL) {
			plist_dict_insert_item(client_opts, "SkipUninstall", plist_new_bool(1));
		}
		plist_dict_insert_item(dict, "ClientOptions", client_opts);
	}
	plist_dict_insert_item(dict, "Command", plist_new_string("Archive"));

	instproxy_lock(client);
	res = instproxy_error(property_list_service_send_xml_plist(client->parent, dict));
	instproxy_unlock(client);

	plist_free(dict);

	if (res != INSTPROXY_E_SUCCESS) {
		log_dbg_msg(DBGMASK_INSTPROXY, "%s: could not send plist, error %d\n", __func__, res);
		return res;
	}
	return instproxy_create_status_updater(client, status_cb, "Archive");
}

/**
 * Restore a previously archived application on the device.
 * This function is the counterpart to instproxy_archive.
 * @see instproxy_archive
 *
 * @param client The connected installation proxy client
 * @param appid ApplicationIdentifier of the app to restore.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_restore(instproxy_client_t client, const char *appid, instproxy_status_cb_t status_cb)
{
	if (!client || !client->parent || !appid)
		return INSTPROXY_E_INVALID_ARG;

	if (client->status_updater) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "ApplicationIdentifier", plist_new_string(appid));
	plist_dict_insert_item(dict, "Command", plist_new_string("Restore"));

	instproxy_lock(client);
	res = instproxy_error(property_list_service_send_xml_plist(client->parent, dict));
	instproxy_unlock(client);

	plist_free(dict);

	if (res != INSTPROXY_E_SUCCESS) {
		log_dbg_msg(DBGMASK_INSTPROXY, "%s: could not send plist, error %d\n", __func__, res);
		return res;
	}
	return instproxy_create_status_updater(client, status_cb, "Restore");
}

/**
 * Removes a previously archived application from the device.
 * This function removes the ZIP archive from the 'ApplicationArchives'
 * directory.
 *
 * @param client The connected installation proxy client
 * @param appid ApplicationIdentifier of the archived app to remove.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_remove_archive(instproxy_client_t client, const char *appid, instproxy_status_cb_t status_cb)
{
	if (!client || !client->parent || !appid)
		return INSTPROXY_E_INVALID_ARG;

	if (client->status_updater) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "ApplicationIdentifier", plist_new_string(appid));
	plist_dict_insert_item(dict, "Command", plist_new_string("RemoveArchive"));

	instproxy_lock(client);
	res = instproxy_error(property_list_service_send_xml_plist(client->parent, dict));
	instproxy_unlock(client);

	plist_free(dict);

	if (res != INSTPROXY_E_SUCCESS) {
		log_dbg_msg(DBGMASK_INSTPROXY, "%s: could not send plist, error %d\n", __func__, res);
		return res;
	}
	return instproxy_create_status_updater(client, status_cb, "RemoveArchive");
}

