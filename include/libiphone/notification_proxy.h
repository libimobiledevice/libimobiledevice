#ifndef NOTIFICATION_PROXY_H
#define NOTIFICATION_PROXY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libiphone/libiphone.h>

struct np_client_int;
typedef struct np_client_int *np_client_t;

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

iphone_error_t np_new_client ( iphone_device_t device, int dst_port, np_client_t *client );
iphone_error_t np_free_client ( np_client_t client );

iphone_error_t np_post_notification ( np_client_t client, const char *notification );

iphone_error_t np_observe_notification ( np_client_t client, const char *notification );
iphone_error_t np_observe_notifications ( np_client_t client, const char **notification_spec );

typedef void (*np_notify_cb_t) ( const char *notification );

iphone_error_t np_set_notify_callback ( np_client_t client, np_notify_cb_t notify_cb );

#ifdef __cplusplus
}
#endif

#endif
