cdef extern from *:
    ctypedef char* const_char_ptr "const char*"

cdef extern from "libimobiledevice/notification_proxy.h":
    cdef struct np_client_int:
        pass
    ctypedef np_client_int *np_client_t
    ctypedef enum np_error_t:
        NP_E_SUCCESS = 0
        NP_E_INVALID_ARG = -1
        NP_E_PLIST_ERROR = -2
        NP_E_CONN_FAILED = -3
        NP_E_UNKNOWN_ERROR = -256
    ctypedef void (*np_notify_cb_t) (const_char_ptr notification, void *userdata)
    np_error_t np_client_new(idevice_t device, uint16_t port, np_client_t *client)
    np_error_t np_client_free(np_client_t client)
    np_error_t np_post_notification(np_client_t client, char *notification)
    np_error_t np_observe_notification(np_client_t client, char *notification)
    np_error_t np_observe_notifications(np_client_t client, char **notification_spec)
    np_error_t np_set_notify_callback(np_client_t client, np_notify_cb_t notify_cb, void *userdata)

cdef void np_notify_cb(const_char_ptr notification, void *py_callback):
    (<object>py_callback)(notification)

cdef class NotificationProxyError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            NP_E_SUCCESS: "Success",
            NP_E_INVALID_ARG: "Invalid argument",
            NP_E_PLIST_ERROR: "PList Error",
            NP_E_CONN_FAILED: "Connection Failed",
            NP_E_UNKNOWN_ERROR: "Unknown Error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class NotificationProxy(Base):
    cdef np_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownClient lockdown=None, *args, **kwargs):
        cdef:
            iDevice dev = device
            LockdownClient lckd
            np_error_t err
        if lockdown is None:
            lckd = LockdownClient(dev)
        else:
            lckd = lockdown
        port = lckd.start_service("com.apple.mobile.notification_proxy")
        err = np_client_new(dev._c_dev, port, &self._c_client)
        self.handle_error(err)

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
