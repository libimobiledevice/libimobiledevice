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
            NP_E_PLIST_ERROR: "Property list error",
            NP_E_CONN_FAILED: "Connection failed",
            NP_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class NotificationProxy(Base):
    __service_name__ = "com.apple.mobile.notification_proxy"
    cdef np_client_t _c_client

    def __cinit__(self, iDevice device not None, int port, *args, **kwargs):
        cdef:
            iDevice dev = device
            np_error_t err
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
