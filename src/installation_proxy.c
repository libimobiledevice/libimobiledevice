/*
 * installation_proxy.c
 * com.apple.mobile.installation_proxy service implementation.
 *
 * Copyright (c) 2010-2015 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2010-2013 Nikias Bassen, All Rights Reserved.
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
#include <inttypes.h>
#include <unistd.h>
#include <plist/plist.h>

#include "installation_proxy.h"
#include "property_list_service.h"
#include "common/debug.h"

typedef enum {
	INSTPROXY_COMMAND_TYPE_ASYNC,
	INSTPROXY_COMMAND_TYPE_SYNC
} instproxy_command_type_t;

struct instproxy_status_data {
	instproxy_client_t client;
	plist_t command;
	instproxy_status_cb_t cbfunc;
	void *user_data;
};

/**
 * Converts an error string identifier to a instproxy_error_t value.
 * Used internally to get correct error codes from a response.
 *
 * @param name The error name to convert.
 * @param error_detail Pointer to store error detail text if available. The
 *   caller is reponsible for freeing the allocated buffer after use. If NULL
 *   is passed no error detail will be returned.
 *
 * @return A matching instproxy_error_t error code or
 *   INSTPROXY_E_UNKNOWN_ERROR otherwise.
 */
static instproxy_error_t instproxy_strtoerr(const char* name)
{
	instproxy_error_t err = INSTPROXY_E_UNKNOWN_ERROR;

	if (strcmp(name, "AlreadyArchived") == 0) {
		err = INSTPROXY_E_ALREADY_ARCHIVED;
	} else if (strcmp(name, "APIInternalError") == 0) {
		err = INSTPROXY_E_API_INTERNAL_ERROR;
	} else if (strcmp(name, "ApplicationAlreadyInstalled") == 0) {
		err = INSTPROXY_E_APPLICATION_ALREADY_INSTALLED;
	} else if (strcmp(name, "ApplicationMoveFailed") == 0) {
		err = INSTPROXY_E_APPLICATION_MOVE_FAILED;
	} else if (strcmp(name, "ApplicationSINFCaptureFailed") == 0) {
		err = INSTPROXY_E_APPLICATION_SINF_CAPTURE_FAILED;
	} else if (strcmp(name, "ApplicationSandboxFailed") == 0) {
		err = INSTPROXY_E_APPLICATION_SANDBOX_FAILED;
	} else if (strcmp(name, "ApplicationVerificationFailed") == 0) {
		err = INSTPROXY_E_APPLICATION_VERIFICATION_FAILED;
	} else if (strcmp(name, "ArchiveDestructionFailed") == 0) {
		err = INSTPROXY_E_ARCHIVE_DESTRUCTION_FAILED;
	} else if (strcmp(name, "BundleVerificationFailed") == 0) {
		err = INSTPROXY_E_BUNDLE_VERIFICATION_FAILED;
	} else if (strcmp(name, "CarrierBundleCopyFailed") == 0) {
		err = INSTPROXY_E_CARRIER_BUNDLE_COPY_FAILED;
	} else if (strcmp(name, "CarrierBundleDirectoryCreationFailed") == 0) {
		err = INSTPROXY_E_CARRIER_BUNDLE_DIRECTORY_CREATION_FAILED;
	} else if (strcmp(name, "CarrierBundleMissingSupportedSIMs") == 0) {
		err = INSTPROXY_E_CARRIER_BUNDLE_MISSING_SUPPORTED_SIMS;
	} else if (strcmp(name, "CommCenterNotificationFailed") == 0) {
		err = INSTPROXY_E_COMM_CENTER_NOTIFICATION_FAILED;
	} else if (strcmp(name, "ContainerCreationFailed") == 0) {
		err = INSTPROXY_E_CONTAINER_CREATION_FAILED;
	} else if (strcmp(name, "ContainerP0wnFailed") == 0) {
		err = INSTPROXY_E_CONTAINER_P0WN_FAILED;
	} else if (strcmp(name, "ContainerRemovalFailed") == 0) {
		err = INSTPROXY_E_CONTAINER_REMOVAL_FAILED;
	} else if (strcmp(name, "EmbeddedProfileInstallFailed") == 0) {
		err = INSTPROXY_E_EMBEDDED_PROFILE_INSTALL_FAILED;
	} else if (strcmp(name, "ExecutableTwiddleFailed") == 0) {
		err = INSTPROXY_E_EXECUTABLE_TWIDDLE_FAILED;
	} else if (strcmp(name, "ExistenceCheckFailed") == 0) {
		err = INSTPROXY_E_EXISTENCE_CHECK_FAILED;
	} else if (strcmp(name, "InstallMapUpdateFailed") == 0) {
		err = INSTPROXY_E_INSTALL_MAP_UPDATE_FAILED;
	} else if (strcmp(name, "ManifestCaptureFailed") == 0) {
		err = INSTPROXY_E_MANIFEST_CAPTURE_FAILED;
	} else if (strcmp(name, "MapGenerationFailed") == 0) {
		err = INSTPROXY_E_MAP_GENERATION_FAILED;
	} else if (strcmp(name, "MissingBundleExecutable") == 0) {
		err = INSTPROXY_E_MISSING_BUNDLE_EXECUTABLE;
	} else if (strcmp(name, "MissingBundleIdentifier") == 0) {
		err = INSTPROXY_E_MISSING_BUNDLE_IDENTIFIER;
	} else if (strcmp(name, "MissingBundlePath") == 0) {
		err = INSTPROXY_E_MISSING_BUNDLE_PATH;
	} else if (strcmp(name, "MissingContainer") == 0) {
		err = INSTPROXY_E_MISSING_CONTAINER;
	} else if (strcmp(name, "NotificationFailed") == 0) {
		err = INSTPROXY_E_NOTIFICATION_FAILED;
	} else if (strcmp(name, "PackageExtractionFailed") == 0) {
		err = INSTPROXY_E_PACKAGE_EXTRACTION_FAILED;
	} else if (strcmp(name, "PackageInspectionFailed") == 0) {
		err = INSTPROXY_E_PACKAGE_INSPECTION_FAILED;
	} else if (strcmp(name, "PackageMoveFailed") == 0) {
		err = INSTPROXY_E_PACKAGE_MOVE_FAILED;
	} else if (strcmp(name, "PathConversionFailed") == 0) {
		err = INSTPROXY_E_PATH_CONVERSION_FAILED;
	} else if (strcmp(name, "RestoreContainerFailed") == 0) {
		err = INSTPROXY_E_RESTORE_CONTAINER_FAILED;
	} else if (strcmp(name, "SeatbeltProfileRemovalFailed") == 0) {
		err = INSTPROXY_E_SEATBELT_PROFILE_REMOVAL_FAILED;
	} else if (strcmp(name, "StageCreationFailed") == 0) {
		err = INSTPROXY_E_STAGE_CREATION_FAILED;
	} else if (strcmp(name, "SymlinkFailed") == 0) {
		err = INSTPROXY_E_SYMLINK_FAILED;
	} else if (strcmp(name, "UnknownCommand") == 0) {
		err = INSTPROXY_E_UNKNOWN_COMMAND;
	} else if (strcmp(name, "iTunesArtworkCaptureFailed") == 0) {
		err = INSTPROXY_E_ITUNES_ARTWORK_CAPTURE_FAILED;
	} else if (strcmp(name, "iTunesMetadataCaptureFailed") == 0) {
		err = INSTPROXY_E_ITUNES_METADATA_CAPTURE_FAILED;
	} else if (strcmp(name, "DeviceOSVersionTooLow") == 0) {
		err = INSTPROXY_E_DEVICE_OS_VERSION_TOO_LOW;
	} else if (strcmp(name, "DeviceFamilyNotSupported") == 0) {
		err = INSTPROXY_E_DEVICE_FAMILY_NOT_SUPPORTED;
	} else if (strcmp(name, "PackagePatchFailed") == 0) {
		err = INSTPROXY_E_PACKAGE_PATCH_FAILED;
	} else if (strcmp(name, "IncorrectArchitecture") == 0) {
		err = INSTPROXY_E_INCORRECT_ARCHITECTURE;
	} else if (strcmp(name, "PluginCopyFailed") == 0) {
		err = INSTPROXY_E_PLUGIN_COPY_FAILED;
	} else if (strcmp(name, "BreadcrumbFailed") == 0) {
		err = INSTPROXY_E_BREADCRUMB_FAILED;
	} else if (strcmp(name, "BreadcrumbUnlockFailed") == 0) {
		err = INSTPROXY_E_BREADCRUMB_UNLOCK_FAILED;
	} else if (strcmp(name, "GeoJSONCaptureFailed") == 0) {
		err = INSTPROXY_E_GEOJSON_CAPTURE_FAILED;
	} else if (strcmp(name, "NewsstandArtworkCaptureFailed") == 0) {
		err = INSTPROXY_E_NEWSSTAND_ARTWORK_CAPTURE_FAILED;
	} else if (strcmp(name, "MissingCommand") == 0) {
		err = INSTPROXY_E_MISSING_COMMAND;
	} else if (strcmp(name, "NotEntitled") == 0) {
		err = INSTPROXY_E_NOT_ENTITLED;
	} else if (strcmp(name, "MissingPackagePath") == 0) {
		err = INSTPROXY_E_MISSING_PACKAGE_PATH;
	} else if (strcmp(name, "MissingContainerPath") == 0) {
		err = INSTPROXY_E_MISSING_CONTAINER_PATH;
	} else if (strcmp(name, "MissingApplicationIdentifier") == 0) {
		err = INSTPROXY_E_MISSING_APPLICATION_IDENTIFIER;
	} else if (strcmp(name, "MissingAttributeValue") == 0) {
		err = INSTPROXY_E_MISSING_ATTRIBUTE_VALUE;
	} else if (strcmp(name, "LookupFailed") == 0) {
		err = INSTPROXY_E_LOOKUP_FAILED;
	} else if (strcmp(name, "DictCreationFailed") == 0) {
		err = INSTPROXY_E_DICT_CREATION_FAILED;
	} else if (strcmp(name, "InstallProhibited") == 0) {
		err = INSTPROXY_E_INSTALL_PROHIBITED;
	} else if (strcmp(name, "UninstallProhibited") == 0) {
		err = INSTPROXY_E_UNINSTALL_PROHIBITED;
	} else if (strcmp(name, "MissingBundleVersion") == 0) {
		err = INSTPROXY_E_MISSING_BUNDLE_VERSION;
	}

	return err;
}

/**
 * Locks an installation_proxy client, used for thread safety.
 *
 * @param client The installation_proxy client to lock
 */
static void instproxy_lock(instproxy_client_t client)
{
	debug_info("Locked");
	mutex_lock(&client->mutex);
}

/**
 * Unlocks an installation_proxy client, used for thread safety.
 *
 * @param client The installation_proxy client to lock
 */
static void instproxy_unlock(instproxy_client_t client)
{
	debug_info("Unlocked");
	mutex_unlock(&client->mutex);
}

/**
 * Converts a property_list_service_error_t value to an instproxy_error_t value.
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

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_client_new(idevice_t device, lockdownd_service_descriptor_t service, instproxy_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	instproxy_error_t err = instproxy_error(property_list_service_client_new(device, service, &plistclient));
	if (err != INSTPROXY_E_SUCCESS) {
		return err;
	}

	instproxy_client_t client_loc = (instproxy_client_t) malloc(sizeof(struct instproxy_client_private));
	client_loc->parent = plistclient;
	mutex_init(&client_loc->mutex);
	client_loc->receive_status_thread = (thread_t)NULL;

	*client = client_loc;
	return INSTPROXY_E_SUCCESS;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_client_start_service(idevice_t device, instproxy_client_t * client, const char* label)
{
	instproxy_error_t err = INSTPROXY_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, INSTPROXY_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(instproxy_client_new), &err);
	return err;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_client_free(instproxy_client_t client)
{
	if (!client)
		return INSTPROXY_E_INVALID_ARG;

	property_list_service_client_free(client->parent);
	client->parent = NULL;
	if (client->receive_status_thread) {
		debug_info("joining receive_status_thread");
		thread_join(client->receive_status_thread);
		thread_free(client->receive_status_thread);
		client->receive_status_thread = (thread_t)NULL;
	}
	mutex_destroy(&client->mutex);
	free(client);

	return INSTPROXY_E_SUCCESS;
}

/**
 * Sends a command to the device.
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
static instproxy_error_t instproxy_send_command(instproxy_client_t client, plist_t command)
{
	if (!client || !command)
		return INSTPROXY_E_INVALID_ARG;

	instproxy_error_t res = instproxy_error(property_list_service_send_xml_plist(client->parent, command));

	if (res != INSTPROXY_E_SUCCESS) {
		debug_info("could not send command plist, error %d", res);
		return res;
	}

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
 * @param command Operation specificiation in plist. Will be passed to the
 *        status_cb callback.
 * @param user_data Callback data passed to status_cb.
 */
static instproxy_error_t instproxy_receive_status_loop(instproxy_client_t client, plist_t command, instproxy_status_cb_t status_cb, void *user_data)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;
	int complete = 0;
	plist_t node = NULL;
	char* command_name = NULL;
	char* status_name = NULL;
	char* error_name = NULL;
	char* error_description = NULL;
	uint64_t error_code = 0;
#ifndef STRIP_DEBUG_CODE
	int percent_complete = 0;
#endif

	instproxy_command_get_name(command, &command_name);

	do {
		/* receive status response */
		instproxy_lock(client);
		res = instproxy_error(property_list_service_receive_plist_with_timeout(client->parent, &node, 1000));
		instproxy_unlock(client);

		/* break out if we have a communication problem */
		if (res != INSTPROXY_E_SUCCESS && res != INSTPROXY_E_RECEIVE_TIMEOUT) {
			debug_info("could not receive plist, error %d", res);
			break;
		}

		/* parse status response */
		if (node) {
			/* check status for possible error to allow reporting it and aborting it gracefully */
			res = instproxy_status_get_error(node, &error_name, &error_description, &error_code);
			if (res != INSTPROXY_E_SUCCESS) {
				debug_info("command: %s, error %d, code 0x%08"PRIx64", name: %s, description: \"%s\"", command_name, res, error_code, error_name, error_description ? error_description: "N/A");
				complete = 1;
			}

			if (error_name) {
				free(error_name);
				error_name = NULL;
			}

			if (error_description) {
				free(error_description);
				error_description = NULL;
			}

			/* check status from response */
			instproxy_status_get_name(node, &status_name);
			if (!status_name) {
				debug_info("failed to retrieve name from status response with error %d.", res);
				complete = 1;
			}

			if (status_name) {
				if (!strcmp(status_name, "Complete")) {
					complete = 1;
				} else {
					res = INSTPROXY_E_OP_IN_PROGRESS;
				}

#ifndef STRIP_DEBUG_CODE
				percent_complete = -1;
				instproxy_status_get_percent_complete(node, &percent_complete);
				if (percent_complete >= 0) {
					debug_info("command: %s, status: %s, percent (%d%%)", command_name, status_name, percent_complete);
				} else {
					debug_info("command: %s, status: %s", command_name, status_name);
				}
#endif
				free(status_name);
				status_name = NULL;
			}

			/* invoke status callback function */
			if (status_cb) {
				status_cb(command, node, user_data);
			}

			plist_free(node);
			node = NULL;
		}
	} while (!complete && client->parent);

	if (command_name)
		free(command_name);

	return res;
}

/**
 * Internally used "receive status" thread function that will call the specified
 * callback function when status update messages (or error messages) are
 * received.
 *
 * @param arg Pointer to an allocated struct instproxy_status_data that holds
 *     the required data about the connected client and the callback function.
 *
 * @return Always NULL.
 */
static void* instproxy_receive_status_loop_thread(void* arg)
{
	struct instproxy_status_data *data = (struct instproxy_status_data*)arg;

	/* run until the command is complete or an error occurs */
	(void)instproxy_receive_status_loop(data->client, data->command, data->cbfunc, data->user_data);

	/* cleanup */
	instproxy_lock(data->client);

	debug_info("done, cleaning up.");

	if (data->command) {
		plist_free(data->command);
	}

	if (data->client->receive_status_thread) {
		thread_free(data->client->receive_status_thread);
		data->client->receive_status_thread = (thread_t)NULL;
	}

	instproxy_unlock(data->client);
	free(data);

	return NULL;
}

/**
 * Internally used helper function that creates a "receive status" thread which
 * will call the passed callback function when a status is received.
 *
 * If async is 0 no thread will be created and the command will run
 * synchronously until it completes or an error occurs.
 *
 * @param client The connected installation proxy client
 * @param command Operation name. Will be passed to the callback function
 *        in async mode or shown in debug messages in sync mode.
 * @param async A boolean indicating if receive loop should be run
 *        asynchronously or block.
 * @param status_cb Pointer to a callback function or NULL.
 * @param user_data Callback data passed to status_cb.
 *
 * @return INSTPROXY_E_SUCCESS when the thread was created (async mode), or
 *         when the command completed successfully (sync).
 *         An INSTPROXY_E_* error value is returned if an error occured.
 */
static instproxy_error_t instproxy_receive_status_loop_with_callback(instproxy_client_t client, plist_t command, instproxy_command_type_t async, instproxy_status_cb_t status_cb, void *user_data)
{
	if (!client || !client->parent || !command) {
		return INSTPROXY_E_INVALID_ARG;
	}

	if (client->receive_status_thread) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;
	if (async == INSTPROXY_COMMAND_TYPE_ASYNC) {
		/* async mode */
		struct instproxy_status_data *data = (struct instproxy_status_data*)malloc(sizeof(struct instproxy_status_data));
		if (data) {
			data->client = client;
			data->command = plist_copy(command);
			data->cbfunc = status_cb;
			data->user_data = user_data;

			if (thread_new(&client->receive_status_thread, instproxy_receive_status_loop_thread, data) == 0) {
				res = INSTPROXY_E_SUCCESS;
			}
		}
	} else {
		/* sync mode as a fallback */
		res = instproxy_receive_status_loop(client, command, status_cb, user_data);
	}

	return res;
}

/**
 * Internal core function to send a command and process the response.
 *
 * @param client The connected installation_proxy client
 * @param command The command specification dictionary.
 * @param async A boolean indicating whether the receive loop should be run
 *        asynchronously or block until completing the command.
 * @param status_cb Callback function to call if a command status is received.
 * @param user_data Callback data passed to status_cb.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 */
static instproxy_error_t instproxy_perform_command(instproxy_client_t client, plist_t command, instproxy_command_type_t async, instproxy_status_cb_t status_cb, void *user_data)
{
	if (!client || !client->parent || !command) {
		return INSTPROXY_E_INVALID_ARG;
	}

	if (client->receive_status_thread) {
		return INSTPROXY_E_OP_IN_PROGRESS;
	}

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	/* send command */
	instproxy_lock(client);
	res = instproxy_send_command(client, command);
	instproxy_unlock(client);

	/* loop until status or error is received */
	res = instproxy_receive_status_loop_with_callback(client, command, async, status_cb, user_data);

	return res;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_browse_with_callback(instproxy_client_t client, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	if (!client || !client->parent || !status_cb)
		return INSTPROXY_E_INVALID_ARG;

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("Browse"));
	if (client_options)
		plist_dict_set_item(command, "ClientOptions", plist_copy(client_options));

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_ASYNC, status_cb, (void*)user_data);

	plist_free(command);

	return res;
}

static void instproxy_append_current_list_to_result_cb(plist_t command, plist_t status, void *user_data)
{
	plist_t *result_array = (plist_t*)user_data;
	uint64_t current_amount = 0;
	plist_t current_list = NULL;
	uint64_t i;

	instproxy_status_get_current_list(status, NULL, NULL, &current_amount, &current_list);

	debug_info("current_amount: %d", current_amount);

	if (current_amount > 0) {
		for (i = 0; current_list && (i < current_amount); i++) {
			plist_t item = plist_array_get_item(current_list, i);
			plist_array_append_item(*result_array, plist_copy(item));
		}
	}

	if (current_list)
		plist_free(current_list);
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_browse(instproxy_client_t client, plist_t client_options, plist_t *result)
{
	if (!client || !client->parent || !result)
		return INSTPROXY_E_INVALID_ARG;

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t result_array = plist_new_array();

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("Browse"));
	if (client_options)
		plist_dict_set_item(command, "ClientOptions", plist_copy(client_options));

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_SYNC, instproxy_append_current_list_to_result_cb, (void*)&result_array);

	if (res == INSTPROXY_E_SUCCESS) {
		*result = result_array;
	} else {
		plist_free(result_array);
	}

	plist_free(command);

	return res;
}

static void instproxy_copy_lookup_result_cb(plist_t command, plist_t status, void *user_data)
{
	plist_t* result = (plist_t*)user_data;

	plist_t node = plist_dict_get_item(status, "LookupResult");
	if (node) {
		*result = plist_copy(node);
	}
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_lookup(instproxy_client_t client, const char** appids, plist_t client_options, plist_t *result)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;
	int i = 0;
	plist_t lookup_result = NULL;
	plist_t command = NULL;
	plist_t appid_array = NULL;
	plist_t node = NULL;

	if (!client || !client->parent || !result)
		return INSTPROXY_E_INVALID_ARG;

	command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("Lookup"));
	if (client_options) {
		node = plist_copy(client_options);
	} else if (appids) {
		node = plist_new_dict();
	}

	/* add bundle identifiers to client options */
	if (appids) {
		appid_array = plist_new_array();
		while (appids[i]) {
			plist_array_append_item(appid_array, plist_new_string(appids[i]));
			i++;
		}
		plist_dict_set_item(node, "BundleIDs", appid_array);
	}

	if (node) {
		plist_dict_set_item(command, "ClientOptions", node);
	}

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_SYNC, instproxy_copy_lookup_result_cb, (void*)&lookup_result);

	if (res == INSTPROXY_E_SUCCESS) {
		*result = lookup_result;
	} else {
		plist_free(lookup_result);
	}

	plist_free(command);

	return res;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_install(instproxy_client_t client, const char *pkg_path, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("Install"));
	if (client_options)
		plist_dict_set_item(command, "ClientOptions", plist_copy(client_options));
	plist_dict_set_item(command, "PackagePath", plist_new_string(pkg_path));

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_ASYNC, status_cb, user_data);

	plist_free(command);

	return res;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_upgrade(instproxy_client_t client, const char *pkg_path, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("Upgrade"));
	if (client_options)
		plist_dict_set_item(command, "ClientOptions", plist_copy(client_options));
	plist_dict_set_item(command, "PackagePath", plist_new_string(pkg_path));

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_ASYNC, status_cb, user_data);

	plist_free(command);

	return res;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_uninstall(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("Uninstall"));
	if (client_options)
		plist_dict_set_item(command, "ClientOptions", plist_copy(client_options));
	plist_dict_set_item(command, "ApplicationIdentifier", plist_new_string(appid));

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_ASYNC, status_cb, user_data);

	plist_free(command);

	return res;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_lookup_archives(instproxy_client_t client, plist_t client_options, plist_t *result)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("LookupArchives"));
	if (client_options)
		plist_dict_set_item(command, "ClientOptions", plist_copy(client_options));

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_SYNC, instproxy_copy_lookup_result_cb, (void*)result);

	plist_free(command);

	return res;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_archive(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("Archive"));
	if (client_options)
		plist_dict_set_item(command, "ClientOptions", plist_copy(client_options));
	plist_dict_set_item(command, "ApplicationIdentifier", plist_new_string(appid));

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_ASYNC, status_cb, user_data);

	plist_free(command);

	return res;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_restore(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("Restore"));
	if (client_options)
		plist_dict_set_item(command, "ClientOptions", plist_copy(client_options));
	plist_dict_set_item(command, "ApplicationIdentifier", plist_new_string(appid));

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_ASYNC, status_cb, user_data);

	plist_free(command);

	return res;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_remove_archive(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("RemoveArchive"));
	if (client_options)
		plist_dict_set_item(command, "ClientOptions", plist_copy(client_options));
	plist_dict_set_item(command, "ApplicationIdentifier", plist_new_string(appid));

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_ASYNC, status_cb, user_data);

	plist_free(command);

	return res;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_check_capabilities_match(instproxy_client_t client, const char** capabilities, plist_t client_options, plist_t *result)
{
	if (!capabilities || (plist_get_node_type(capabilities) != PLIST_ARRAY && plist_get_node_type(capabilities) != PLIST_DICT))
		return INSTPROXY_E_INVALID_ARG;

	plist_t lookup_result = NULL;

	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	plist_t command = plist_new_dict();
	plist_dict_set_item(command, "Command", plist_new_string("CheckCapabilitiesMatch"));
	if (client_options)
		plist_dict_set_item(command, "ClientOptions", plist_copy(client_options));

	if (capabilities) {
		int i = 0;
		plist_t capabilities_array = plist_new_array();
		while (capabilities[i]) {
			plist_array_append_item(capabilities_array, plist_new_string(capabilities[i]));
			i++;
		}
		plist_dict_set_item(command, "Capabilities", capabilities_array);
	}

	res = instproxy_perform_command(client, command, INSTPROXY_COMMAND_TYPE_SYNC, instproxy_copy_lookup_result_cb, (void*)&lookup_result);

	if (res == INSTPROXY_E_SUCCESS) {
		*result = lookup_result;
	} else {
		plist_free(lookup_result);
	}

	plist_free(command);

	return res;
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_status_get_error(plist_t status, char **name, char** description, uint64_t* code)
{
	instproxy_error_t res = INSTPROXY_E_UNKNOWN_ERROR;

	if (!status || !name)
		return INSTPROXY_E_INVALID_ARG;

	plist_t node = plist_dict_get_item(status, "Error");
	if (node) {
		plist_get_string_val(node, name);
	} else {
		/* no error here */
		res = INSTPROXY_E_SUCCESS;
	}

	if (code != NULL) {
		*code = 0;
		node = plist_dict_get_item(status, "ErrorDetail");
		if (node) {
			plist_get_uint_val(node, code);
			*code &= 0xffffffff;
		}
	}

	if (description != NULL) {
		node = plist_dict_get_item(status, "ErrorDescription");
		if (node) {
			plist_get_string_val(node, description);
		}
	}

	if (*name) {
		res = instproxy_strtoerr(*name);
	}

	return res;
}

LIBIMOBILEDEVICE_API void instproxy_status_get_name(plist_t status, char **name)
{
	*name = NULL;
	if (name) {
		plist_t node = plist_dict_get_item(status, "Status");
		if (node) {
			plist_get_string_val(node, name);
		}
	}
}

LIBIMOBILEDEVICE_API void instproxy_status_get_percent_complete(plist_t status, int *percent)
{
	uint64_t val = 0;
	if (percent) {
		plist_t node = plist_dict_get_item(status, "PercentComplete");
		if (node) {
			plist_get_uint_val(node, &val);
			*percent = val;
		}
	}
}

LIBIMOBILEDEVICE_API void instproxy_status_get_current_list(plist_t status, uint64_t* total, uint64_t* current_index, uint64_t* current_amount, plist_t* list)
{
	plist_t node = NULL;

	if (status && plist_get_node_type(status) == PLIST_DICT) {
		/* command specific logic: parse browsed list */
		if (list != NULL) {
			node = plist_dict_get_item(status, "CurrentList");
			if (node) {
				*current_amount = plist_array_get_size(node);
				*list = plist_copy(node);
			}
		}

		if (total != NULL) {
			node = plist_dict_get_item(status, "Total");
			if (node) {
				plist_get_uint_val(node, total);
			}
		}

		if (current_amount != NULL) {
			node = plist_dict_get_item(status, "CurrentAmount");
			if (node) {
				plist_get_uint_val(node, current_amount);
			}
		}

		if (current_index != NULL) {
			node = plist_dict_get_item(status, "CurrentIndex");
			if (node) {
				plist_get_uint_val(node, current_index);
			}
		}
	}
}

LIBIMOBILEDEVICE_API void instproxy_command_get_name(plist_t command, char** name)
{
	*name = NULL;
	plist_t node = plist_dict_get_item(command, "Command");
	if (node) {
		plist_get_string_val(node, name);
	}
}

LIBIMOBILEDEVICE_API plist_t instproxy_client_options_new()
{
	return plist_new_dict();
}

LIBIMOBILEDEVICE_API void instproxy_client_options_add(plist_t client_options, ...)
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

LIBIMOBILEDEVICE_API void instproxy_client_options_set_return_attributes(plist_t client_options, ...)
{
	if (!client_options)
		return;

	plist_t return_attributes = plist_new_array();

	va_list args;
	va_start(args, client_options);
	char *arg = va_arg(args, char*);
	while (arg) {
		char *attribute = strdup(arg);
		plist_array_append_item(return_attributes, plist_new_string(attribute));
		free(attribute);
		arg = va_arg(args, char*);
	}
	va_end(args);

	plist_dict_set_item(client_options, "ReturnAttributes", return_attributes);
}

LIBIMOBILEDEVICE_API void instproxy_client_options_free(plist_t client_options)
{
	if (client_options) {
		plist_free(client_options);
	}
}

LIBIMOBILEDEVICE_API instproxy_error_t instproxy_client_get_path_for_bundle_identifier(instproxy_client_t client, const char* appid, char** path)
{
	if (!client || !client->parent || !appid)
		return INSTPROXY_E_INVALID_ARG;

	plist_t apps = NULL;

	// create client options for any application types
	plist_t client_opts = instproxy_client_options_new();
	instproxy_client_options_add(client_opts, "ApplicationType", "Any", NULL);

	// only return attributes we need
	instproxy_client_options_set_return_attributes(client_opts, "CFBundleIdentifier", "CFBundleExecutable", "Path", NULL);

	// only query for specific appid
	const char* appids[] = {appid, NULL};

	// query device for list of apps
	instproxy_error_t ierr = instproxy_lookup(client, appids, client_opts, &apps);

	instproxy_client_options_free(client_opts);

	if (ierr != INSTPROXY_E_SUCCESS) {
		return ierr;
	}

	plist_t app_found = plist_access_path(apps, 1, appid);
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
