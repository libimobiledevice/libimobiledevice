cdef extern from *:
    ctypedef char* const_char_ptr "const char*"

cdef extern from "libimobiledevice/notification_proxy.h":
    cdef struct np_client_int:
        pass
    ctypedef np_client_int *np_client_t
    ctypedef int16_t np_error_t
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
    pass

cdef class NotificationProxy:
    cdef np_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownClient lockdown=None, *args, **kwargs):
        cdef iDevice dev = device
        cdef LockdownClient lckd
        if lockdown is None:
            lckd = LockdownClient(dev)
        else:
            lckd = lockdown
        port = lckd.start_service("com.apple.mobile.notification_proxy")
        err = NotificationProxyError(np_client_new(dev._c_dev, port, &(self._c_client)))
        if err: raise err

    def __dealloc__(self):
        if self._c_client is not NULL:
            err = NotificationProxyError(np_client_free(self._c_client))
            if err: raise err
    
    cpdef set_notify_callback(self, object callback):
        err = NotificationProxyError(np_set_notify_callback(self._c_client, np_notify_cb, <void*>callback))
        if err: raise err
    
    cpdef observe_notification(self, bytes notification):
        err = NotificationProxyError(np_observe_notification(self._c_client, notification))
        if err: raise err

    cpdef post_notification(self, bytes notification):
        err = NotificationProxyError(np_post_notification(self._c_client, notification))
        if err: raise err
