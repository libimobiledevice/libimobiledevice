/**
 * @file libimobiledevice/installation_proxy.h
 * @brief Manage applications on a device.
 * \internal
 *
 * Copyright (c) 2009 Nikias Bassen All Rights Reserved.
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

#ifndef IINSTALLATION_PROXY_H
#define IINSTALLATION_PROXY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define INSTPROXY_SERVICE_NAME "com.apple.mobile.installation_proxy"

/** @name Error Codes */
/*@{*/
#define INSTPROXY_E_SUCCESS                0
#define INSTPROXY_E_INVALID_ARG           -1
#define INSTPROXY_E_PLIST_ERROR           -2
#define INSTPROXY_E_CONN_FAILED           -3
#define INSTPROXY_E_OP_IN_PROGRESS        -4
#define INSTPROXY_E_OP_FAILED             -5
#define INSTPROXY_E_RECEIVE_TIMEOUT       -6

#define INSTPROXY_E_UNKNOWN_ERROR       -256
/*@}*/

/** Represents an error code. */
typedef int16_t instproxy_error_t;

typedef struct instproxy_client_private instproxy_client_private;
typedef instproxy_client_private *instproxy_client_t; /**< The client handle. */

/** Reports the status of the given operation */
typedef void (*instproxy_status_cb_t) (const char *operation, plist_t status, void *user_data);

/* Interface */

/**
 * Connects to the installation_proxy service on the specified device.
 *
 * @param device The device to connect to
 * @param service The service descriptor returned by lockdownd_start_service.
 * @param client Pointer that will be set to a newly allocated
 *     instproxy_client_t upon successful return.
 *
 * @return INSTPROXY_E_SUCCESS on success, or an INSTPROXY_E_* error value
 *     when an error occured.
 */
instproxy_error_t instproxy_client_new(idevice_t device, lockdownd_service_descriptor_t service, instproxy_client_t *client);

/**
 * Starts a new installation_proxy service on the specified device and connects to it.
 *
 * @param device The device to connect to.
 * @param client Pointer that will point to a newly allocated
 *     instproxy_client_t upon successful return. Must be freed using
 *     instproxy_client_free() after use.
 * @param label The label to use for communication. Usually the program name.
 *  Pass NULL to disable sending the label in requests to lockdownd.
 *
 * @return INSTPROXY_E_SUCCESS on success, or an INSTPROXY_E_* error
 *     code otherwise.
 */
instproxy_error_t instproxy_client_start_service(idevice_t device, instproxy_client_t * client, const char* label);

/**
 * Disconnects an installation_proxy client from the device and frees up the
 * installation_proxy client data.
 *
 * @param client The installation_proxy client to disconnect and free.
 *
 * @return INSTPROXY_E_SUCCESS on success
 *      or INSTPROXY_E_INVALID_ARG if client is NULL.
 */
instproxy_error_t instproxy_client_free(instproxy_client_t client);


/**
 * List installed applications. This function runs synchronously.
 *
 * @param client The connected installation_proxy client
 * @param client_options The client options to use, as PLIST_DICT, or NULL.
 *        Valid client options include:
 *          "ApplicationType" -> "User"
 *          "ApplicationType" -> "System"
 * @param result Pointer that will be set to a plist that will hold an array
 *        of PLIST_DICT holding information about the applications found.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 */
instproxy_error_t instproxy_browse(instproxy_client_t client, plist_t client_options, plist_t *result);

/**
 * Install an application on the device.
 *
 * @param client The connected installation_proxy client
 * @param pkg_path Path of the installation package (inside the AFC jail)
 * @param client_options The client options to use, as PLIST_DICT, or NULL.
 *        Valid options include:
 *          "iTunesMetadata" -> PLIST_DATA
 *          "ApplicationSINF" -> PLIST_DATA
 *          "PackageType" -> "Developer"
 *        If PackageType -> Developer is specified, then pkg_path points to
 *        an .app directory instead of an install package.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 * @param user_data Callback data passed to status_cb.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_install(instproxy_client_t client, const char *pkg_path, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data);

/**
 * Upgrade an application on the device. This function is nearly the same as
 * instproxy_install; the difference is that the installation progress on the
 * device is faster if the application is already installed.
 *
 * @param client The connected installation_proxy client
 * @param pkg_path Path of the installation package (inside the AFC jail)
 * @param client_options The client options to use, as PLIST_DICT, or NULL.
 *        Valid options include:
 *          "iTunesMetadata" -> PLIST_DATA
 *          "ApplicationSINF" -> PLIST_DATA
 *          "PackageType" -> "Developer"
 *        If PackageType -> Developer is specified, then pkg_path points to
 *        an .app directory instead of an install package.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 * @param user_data Callback data passed to status_cb.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_upgrade(instproxy_client_t client, const char *pkg_path, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data);

/**
 * Uninstall an application from the device.
 *
 * @param client The connected installation proxy client
 * @param appid ApplicationIdentifier of the app to uninstall
 * @param client_options The client options to use, as PLIST_DICT, or NULL.
 *        Currently there are no known client options, so pass NULL here.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 * @param user_data Callback data passed to status_cb.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_uninstall(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data);


/**
 * List archived applications. This function runs synchronously.
 *
 * @see instproxy_archive
 *
 * @param client The connected installation_proxy client
 * @param client_options The client options to use, as PLIST_DICT, or NULL.
 *        Currently there are no known client options, so pass NULL here.
 * @param result Pointer that will be set to a plist containing a PLIST_DICT
 *        holding information about the archived applications found.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 */
instproxy_error_t instproxy_lookup_archives(instproxy_client_t client, plist_t client_options, plist_t *result);

/**
 * Archive an application on the device.
 * This function tells the device to make an archive of the specified
 * application. This results in the device creating a ZIP archive in the
 * 'ApplicationArchives' directory and uninstalling the application.
 *
 * @param client The connected installation proxy client
 * @param appid ApplicationIdentifier of the app to archive.
 * @param client_options The client options to use, as PLIST_DICT, or NULL.
 *        Valid options include:
 *          "SkipUninstall" -> Boolean
 *          "ArchiveType" -> "ApplicationOnly"
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 * @param user_data Callback data passed to status_cb.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_archive(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data);

/**
 * Restore a previously archived application on the device.
 * This function is the counterpart to instproxy_archive.
 * @see instproxy_archive
 *
 * @param client The connected installation proxy client
 * @param appid ApplicationIdentifier of the app to restore.
 * @param client_options The client options to use, as PLIST_DICT, or NULL.
 *        Currently there are no known client options, so pass NULL here.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 * @param user_data Callback data passed to status_cb.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_restore(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data);

/**
 * Removes a previously archived application from the device.
 * This function removes the ZIP archive from the 'ApplicationArchives'
 * directory.
 *
 * @param client The connected installation proxy client
 * @param appid ApplicationIdentifier of the archived app to remove.
 * @param client_options The client options to use, as PLIST_DICT, or NULL.
 *        Currently there are no known client options, so passing NULL is fine.
 * @param status_cb Callback function for progress and status information. If
 *        NULL is passed, this function will run synchronously.
 * @param user_data Callback data passed to status_cb.
 *
 * @return INSTPROXY_E_SUCCESS on success or an INSTPROXY_E_* error value if
 *     an error occured.
 *
 * @note If a callback function is given (async mode), this function returns
 *     INSTPROXY_E_SUCCESS immediately if the status updater thread has been
 *     created successfully; any error occuring during the operation has to be
 *     handled inside the specified callback function.
 */
instproxy_error_t instproxy_remove_archive(instproxy_client_t client, const char *appid, plist_t client_options, instproxy_status_cb_t status_cb, void *user_data);

/* Helper */

/**
 * Create a new client_options plist.
 *
 * @return A new plist_t of type PLIST_DICT.
 */
plist_t instproxy_client_options_new();

/**
 * Add one or more new key:value pairs to the given client_options.
 *
 * @param client_options The client options to modify.
 * @param ... KEY, VALUE, [KEY, VALUE], NULL
 *
 * @note The keys and values passed are expected to be strings, except for the
 *       keys "ApplicationSINF", "iTunesMetadata", "ReturnAttributes" which are
 *       expecting a plist_t node as value and "SkipUninstall" expects int.
 */
void instproxy_client_options_add(plist_t client_options, ...);

/**
 * Free client_options plist.
 *
 * @param client_options The client options plist to free. Does nothing if NULL
 *        is passed.
 */
void instproxy_client_options_free(plist_t client_options);

/**
 * Query the device for the path of an application.
 *
 * @param client The connected installation proxy client.
 * @param appid ApplicationIdentifier of app to retrieve the path for.
 * @param path Pointer to store the device path for the application
 *        which is set to NULL if it could not be determined.
 *
 * @return INSTPROXY_E_SUCCESS on success, INSTPROXY_E_OP_FAILED if
 *         the path could not be determined or an INSTPROXY_E_* error
 *         value if an error occured.
 *
 * @note This implementation browses all applications and matches the
 *       right entry by the application identifier.
 */
instproxy_error_t instproxy_client_get_path_for_bundle_identifier(instproxy_client_t client, const char* bundle_id, char** path);

#ifdef __cplusplus
}
#endif

#endif
