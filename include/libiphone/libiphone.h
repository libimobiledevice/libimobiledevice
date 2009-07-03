/*
 * libiphone.h
 * Main include of libiphone
 *
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

#ifndef LIBIPHONE_H
#define LIBIPHONE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <plist/plist.h>
#include <usbmuxd.h>

//general errors
#define IPHONE_E_SUCCESS                0
#define IPHONE_E_INVALID_ARG           -1
#define IPHONE_E_UNKNOWN_ERROR         -2
#define IPHONE_E_NO_DEVICE             -3
#define IPHONE_E_TIMEOUT               -4
#define IPHONE_E_NOT_ENOUGH_DATA       -5
#define IPHONE_E_BAD_HEADER            -6

//lockdownd specific error
#define IPHONE_E_INVALID_CONF          -7
#define IPHONE_E_PAIRING_FAILED        -8
#define IPHONE_E_SSL_ERROR             -9
#define IPHONE_E_PLIST_ERROR          -10
#define IPHONE_E_DICT_ERROR           -11
#define IPHONE_E_START_SERVICE_FAILED -12

//afc specific error
#define IPHONE_E_AFC_ERROR            -13

typedef int16_t iphone_error_t;

typedef enum {
	AFC_FOPEN_RDONLY   = 0x00000001, // r   O_RDONLY
	AFC_FOPEN_RW       = 0x00000002, // r+  O_RDWR   | O_CREAT
	AFC_FOPEN_WRONLY   = 0x00000003, // w   O_WRONLY | O_CREAT  | O_TRUNC
	AFC_FOPEN_WR       = 0x00000004, // w+  O_RDWR   | O_CREAT  | O_TRUNC
	AFC_FOPEN_APPEND   = 0x00000005, // a   O_WRONLY | O_APPEND | O_CREAT
	AFC_FOPEN_RDAPPEND = 0x00000006  // a+  O_RDWR   | O_APPEND | O_CREAT
} iphone_afc_file_mode_t;

struct iphone_device_int;
typedef struct iphone_device_int *iphone_device_t;

struct iphone_lckd_client_int;
typedef struct iphone_lckd_client_int *iphone_lckd_client_t;

struct iphone_afc_client_int;
typedef struct iphone_afc_client_int *iphone_afc_client_t;

struct iphone_msync_client_int;
typedef struct iphone_msync_client_int *iphone_msync_client_t;

struct iphone_np_client_int;
typedef struct iphone_np_client_int *iphone_np_client_t;

//debug related functions
#define DBGMASK_ALL        0xFFFF
#define DBGMASK_NONE       0x0000
#define DBGMASK_USBMUX     (1 << 1)
#define DBGMASK_LOCKDOWND  (1 << 2)
#define DBGMASK_MOBILESYNC (1 << 3)

void iphone_set_debug_mask(uint16_t mask);
void iphone_set_debug(int level);

//device related functions
iphone_error_t iphone_get_device ( iphone_device_t *device );
iphone_error_t iphone_get_device_by_uuid ( iphone_device_t *device, const char *uuid );
iphone_error_t iphone_free_device ( iphone_device_t device );

uint32_t iphone_get_device_handle ( iphone_device_t device );

//lockdownd related functions
iphone_error_t lockdownd_get_device_uid(iphone_lckd_client_t control, char **uid);
iphone_error_t lockdownd_get_device_name ( iphone_lckd_client_t client, char **device_name );
iphone_error_t iphone_lckd_new_client ( iphone_device_t device, iphone_lckd_client_t *client );
iphone_error_t iphone_lckd_free_client( iphone_lckd_client_t client );

iphone_error_t iphone_lckd_start_service ( iphone_lckd_client_t client, const char *service, int *port );
iphone_error_t iphone_lckd_recv ( iphone_lckd_client_t client, plist_t* plist);
iphone_error_t iphone_lckd_send ( iphone_lckd_client_t client, plist_t plist);


//afc related functions
iphone_error_t iphone_afc_new_client ( iphone_device_t device, int dst_port, iphone_afc_client_t *client );
iphone_error_t iphone_afc_free_client ( iphone_afc_client_t client );
int iphone_afc_get_afcerror ( iphone_afc_client_t client );
int iphone_afc_get_errno ( iphone_afc_client_t client );

iphone_error_t iphone_afc_get_devinfo ( iphone_afc_client_t client, char ***infos );
iphone_error_t iphone_afc_get_dir_list ( iphone_afc_client_t client, const char *dir, char ***list);

iphone_error_t iphone_afc_get_file_info ( iphone_afc_client_t client, const char *filename, char ***infolist );
iphone_error_t iphone_afc_open_file ( iphone_afc_client_t client, const char *filename, iphone_afc_file_mode_t file_mode, uint64_t *handle );
iphone_error_t iphone_afc_close_file ( iphone_afc_client_t client, uint64_t handle);
iphone_error_t iphone_afc_lock_file ( iphone_afc_client_t client, uint64_t handle, int operation);
iphone_error_t iphone_afc_read_file ( iphone_afc_client_t client, uint64_t handle, char *data, int length, uint32_t *bytes);
iphone_error_t iphone_afc_write_file ( iphone_afc_client_t client, uint64_t handle, const char *data, int length, uint32_t *bytes);
iphone_error_t iphone_afc_seek_file ( iphone_afc_client_t client, uint64_t handle, int64_t offset, int whence);
iphone_error_t iphone_afc_truncate_file ( iphone_afc_client_t client, uint64_t handle, uint64_t newsize);
iphone_error_t iphone_afc_delete_file ( iphone_afc_client_t client, const char *path);
iphone_error_t iphone_afc_rename_file ( iphone_afc_client_t client, const char *from, const char *to);
iphone_error_t iphone_afc_mkdir ( iphone_afc_client_t client, const char *dir);
iphone_error_t iphone_afc_truncate(iphone_afc_client_t client, const char *path, off_t newsize);



iphone_error_t iphone_msync_new_client(iphone_device_t device, int dst_port,
									   iphone_msync_client_t * client);
iphone_error_t iphone_msync_free_client(iphone_msync_client_t client);

iphone_error_t iphone_msync_recv(iphone_msync_client_t client, plist_t * plist);
iphone_error_t iphone_msync_send(iphone_msync_client_t client, plist_t plist);

// NotificationProxy related
// notifications for use with post_notification (client --> device)
#define NP_SYNC_WILL_START      "com.apple.itunes-mobdev.syncWillStart"
#define NP_SYNC_DID_START       "com.apple.itunes-mobdev.syncDidStart"
#define NP_SYNC_DID_FINISH      "com.apple.itunes-mobdev.syncDidFinish"

// notifications for use with observe_notification (device --> client)
#define NP_SYNC_CANCEL_REQUEST  "com.apple.itunes-client.syncCancelRequest"
#define NP_SYNC_SUSPEND_REQUEST "com.apple.itunes-client.syncSuspendRequest"
#define NP_SYNC_RESUME_REQUEST  "com.apple.itunes-client.syncResumeRequest"
#define NP_PHONE_NUMBER_CHANGED "com.apple.mobile.lockdown.phone_number_changed"
#define NP_DEVICE_NAME_CHANGED  "com.apple.mobile.lockdown.device_name_changed"
#define NP_ATTEMPTACTIVATION    "com.apple.springboard.attemptactivation"
#define NP_DS_DOMAIN_CHANGED    "com.apple.mobile.data_sync.domain_changed"
#define NP_APP_INSTALLED        "com.apple.mobile.application_installed"
#define NP_APP_UNINSTALLED      "com.apple.mobile.application_uninstalled"

iphone_error_t iphone_np_new_client ( iphone_device_t device, int dst_port, iphone_np_client_t *client );
iphone_error_t iphone_np_free_client ( iphone_np_client_t client );

iphone_error_t iphone_np_post_notification ( iphone_np_client_t client, const char *notification );

iphone_error_t iphone_np_observe_notification ( iphone_np_client_t client, const char *notification );
iphone_error_t iphone_np_observe_notifications ( iphone_np_client_t client, const char **notification_spec );
iphone_error_t iphone_np_get_notification ( iphone_np_client_t client, char **notification );

typedef void (*iphone_np_notify_cb_t) ( const char *notification );

iphone_error_t iphone_np_set_notify_callback ( iphone_np_client_t client, iphone_np_notify_cb_t notify_cb );

#ifdef __cplusplus
}
#endif

#endif

