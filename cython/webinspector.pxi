cdef extern from "libimobiledevice/webinspector.h":
    cdef struct webinspector_client_private:
        pass
    ctypedef webinspector_client_private *webinspector_client_t

    ctypedef enum webinspector_error_t:
        WEBINSPECTOR_E_SUCCESS = 0
        WEBINSPECTOR_E_INVALID_ARG = -1
        WEBINSPECTOR_E_PLIST_ERROR = -2
        WEBINSPECTOR_E_MUX_ERROR = -3
        WEBINSPECTOR_E_SSL_ERROR = -4
        WEBINSPECTOR_E_UNKNOWN_ERROR = -256

    webinspector_error_t webinspector_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, webinspector_client_t * client)
    webinspector_error_t webinspector_client_free(webinspector_client_t client)

    webinspector_error_t webinspector_send(webinspector_client_t client, plist.plist_t plist)
    webinspector_error_t webinspector_receive(webinspector_client_t client, plist.plist_t * plist)
    webinspector_error_t webinspector_receive_with_timeout(webinspector_client_t client, plist.plist_t * plist, uint32_t timeout_ms)

cdef class WebinspectorError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            WEBINSPECTOR_E_SUCCESS: "Success",
            WEBINSPECTOR_E_INVALID_ARG: "Invalid argument",
            WEBINSPECTOR_E_PLIST_ERROR: "Property list error",
            WEBINSPECTOR_E_MUX_ERROR: "MUX error",
            WEBINSPECTOR_E_SSL_ERROR: "SSL Error",
            WEBINSPECTOR_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class WebinspectorClient(PropertyListService):
    __service_name__ = "com.apple.webinspector"
    cdef webinspector_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(webinspector_client_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))

    def __dealloc__(self):
        cdef webinspector_error_t err
        if self._c_client is not NULL:
            err = webinspector_client_free(self._c_client)
            self.handle_error(err)

    cdef inline int16_t _send(self, plist.plist_t node):
        return webinspector_send(self._c_client, node)

    cdef inline int16_t _receive(self, plist.plist_t* node):
        return webinspector_receive(self._c_client, node)

    cdef inline int16_t _receive_with_timeout(self, plist.plist_t* node, int timeout_ms):
        return webinspector_receive_with_timeout(self._c_client, node, timeout_ms)

    cdef inline BaseError _error(self, int16_t ret):
        return WebinspectorError(ret)
