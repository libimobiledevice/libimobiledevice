cdef extern from "libimobiledevice/notification_proxy.h":
    cdef struct np_client_private:
        pass
    ctypedef np_client_private *np_client_t
    ctypedef enum np_error_t:
        NP_E_SUCCESS = 0
        NP_E_INVALID_ARG = -1
        NP_E_PLIST_ERROR = -2
        NP_E_CONN_FAILED = -3
        NP_E_UNKNOWN_ERROR = -256
    ctypedef void (*np_notify_cb_t) (const_char_ptr notification, void *userdata)
    np_error_t np_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, np_client_t *client)
    np_error_t np_client_free(np_client_t client)
    np_error_t np_post_notification(np_client_t client, char *notification)
    np_error_t np_observe_notification(np_client_t client, char *notification)
    np_error_t np_observe_notifications(np_client_t client, char **notification_spec)
    np_error_t np_set_notify_callback(np_client_t client, np_notify_cb_t notify_cb, void *userdata)

    cdef char* C_NP_SYNC_WILL_START "NP_SYNC_WILL_START"
    cdef char* C_NP_SYNC_DID_START "NP_SYNC_DID_START"
    cdef char* C_NP_SYNC_DID_FINISH "NP_SYNC_DID_FINISH"
    cdef char* C_NP_SYNC_LOCK_REQUEST "NP_SYNC_LOCK_REQUEST"

    cdef char* C_NP_SYNC_CANCEL_REQUEST "NP_SYNC_CANCEL_REQUEST"
    cdef char* C_NP_SYNC_SUSPEND_REQUEST "NP_SYNC_SUSPEND_REQUEST"
    cdef char* C_NP_SYNC_RESUME_REQUEST "NP_SYNC_RESUME_REQUEST"
    cdef char* C_NP_PHONE_NUMBER_CHANGED "NP_PHONE_NUMBER_CHANGED"
    cdef char* C_NP_DEVICE_NAME_CHANGED "NP_DEVICE_NAME_CHANGED"
    cdef char* C_NP_TIMEZONE_CHANGED "NP_TIMEZONE_CHANGED"
    cdef char* C_NP_TRUSTED_HOST_ATTACHED "NP_TRUSTED_HOST_ATTACHED"
    cdef char* C_NP_HOST_DETACHED "NP_HOST_DETACHED"
    cdef char* C_NP_HOST_ATTACHED "NP_HOST_ATTACHED"
    cdef char* C_NP_REGISTRATION_FAILED "NP_REGISTRATION_FAILED"
    cdef char* C_NP_ACTIVATION_STATE "NP_ACTIVATION_STATE"
    cdef char* C_NP_BRICK_STATE "NP_BRICK_STATE"
    cdef char* C_NP_DS_DOMAIN_CHANGED "NP_DS_DOMAIN_CHANGED"
    cdef char* C_NP_BACKUP_DOMAIN_CHANGED "NP_BACKUP_DOMAIN_CHANGED"
    cdef char* C_NP_APP_INSTALLED "NP_APP_INSTALLED"
    cdef char* C_NP_APP_UNINSTALLED "NP_APP_UNINSTALLED"
    cdef char* C_NP_DEV_IMAGE_MOUNTED "NP_DEV_IMAGE_MOUNTED"
    cdef char* C_NP_ATTEMPTACTIVATION "NP_ATTEMPTACTIVATION"
    cdef char* C_NP_ITDBPREP_DID_END "NP_ITDBPREP_DID_END"
    cdef char* C_NP_LANGUAGE_CHANGED "NP_LANGUAGE_CHANGED"
    cdef char* C_NP_ADDRESS_BOOK_PREF_CHANGED "NP_ADDRESS_BOOK_PREF_CHANGED"

NP_SYNC_WILL_START = C_NP_SYNC_WILL_START
NP_SYNC_DID_START = C_NP_SYNC_DID_START
NP_SYNC_DID_FINISH = C_NP_SYNC_DID_FINISH
NP_SYNC_LOCK_REQUEST = C_NP_SYNC_LOCK_REQUEST

NP_SYNC_CANCEL_REQUEST = C_NP_SYNC_CANCEL_REQUEST
NP_SYNC_SUSPEND_REQUEST = C_NP_SYNC_SUSPEND_REQUEST
NP_SYNC_RESUME_REQUEST = C_NP_SYNC_RESUME_REQUEST
NP_PHONE_NUMBER_CHANGED = C_NP_PHONE_NUMBER_CHANGED
NP_DEVICE_NAME_CHANGED = C_NP_DEVICE_NAME_CHANGED
NP_TIMEZONE_CHANGED = C_NP_TIMEZONE_CHANGED
NP_TRUSTED_HOST_ATTACHED = C_NP_TRUSTED_HOST_ATTACHED
NP_HOST_DETACHED = C_NP_HOST_DETACHED
NP_HOST_ATTACHED = C_NP_HOST_ATTACHED
NP_REGISTRATION_FAILED = C_NP_REGISTRATION_FAILED
NP_ACTIVATION_STATE = C_NP_ACTIVATION_STATE
NP_BRICK_STATE = C_NP_BRICK_STATE
NP_DS_DOMAIN_CHANGED = C_NP_DS_DOMAIN_CHANGED
NP_BACKUP_DOMAIN_CHANGED = C_NP_BACKUP_DOMAIN_CHANGED
NP_APP_INSTALLED = C_NP_APP_INSTALLED
NP_APP_UNINSTALLED = C_NP_APP_UNINSTALLED
NP_DEV_IMAGE_MOUNTED = C_NP_DEV_IMAGE_MOUNTED
NP_ATTEMPTACTIVATION = C_NP_ATTEMPTACTIVATION
NP_ITDBPREP_DID_END = C_NP_ITDBPREP_DID_END
NP_LANGUAGE_CHANGED = C_NP_LANGUAGE_CHANGED
NP_ADDRESS_BOOK_PREF_CHANGED = C_NP_ADDRESS_BOOK_PREF_CHANGED

cdef void np_notify_cb(const_char_ptr notification, void *py_callback):
    (<object>py_callback)(notification)

cdef class NotificationProxyError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            NP_E_SUCCESS: "Success",
            NP_E_INVALID_ARG: "Invalid argument",
            NP_E_PLIST_ERROR: "Property list error",
            NP_E_CONN_FAILED: "Connection failed",
            NP_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class NotificationProxyClient(PropertyListService):
    __service_name__ = "com.apple.mobile.notification_proxy"
    cdef np_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(np_client_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))

    def __dealloc__(self):
        cdef np_error_t err
        if self._c_client is not NULL:
            err = np_client_free(self._c_client)
            self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return NotificationProxyError(ret)

    cpdef set_notify_callback(self, object callback):
        self.handle_error(np_set_notify_callback(self._c_client, np_notify_cb, <void*>callback))

    cpdef observe_notification(self, bytes notification):
        self.handle_error(np_observe_notification(self._c_client, notification))

    cpdef post_notification(self, bytes notification):
        self.handle_error(np_post_notification(self._c_client, notification))
