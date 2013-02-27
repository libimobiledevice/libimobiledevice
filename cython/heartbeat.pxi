cdef extern from "libimobiledevice/heartbeat.h":
    cdef struct heartbeat_client_private:
        pass
    ctypedef heartbeat_client_private *heartbeat_client_t

    ctypedef enum heartbeat_error_t:
        HEARTBEAT_E_SUCCESS = 0
        HEARTBEAT_E_INVALID_ARG = -1
        HEARTBEAT_E_PLIST_ERROR = -2
        HEARTBEAT_E_MUX_ERROR = -3
        HEARTBEAT_E_SSL_ERROR = -4
        HEARTBEAT_E_UNKNOWN_ERROR = -256

    heartbeat_error_t heartbeat_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, heartbeat_client_t * client)
    heartbeat_error_t heartbeat_client_free(heartbeat_client_t client)

    heartbeat_error_t heartbeat_send(heartbeat_client_t client, plist.plist_t plist)
    heartbeat_error_t heartbeat_receive(heartbeat_client_t client, plist.plist_t * plist)
    heartbeat_error_t heartbeat_receive_with_timeout(heartbeat_client_t client, plist.plist_t * plist, uint32_t timeout_ms)

cdef class HeartbeatError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            HEARTBEAT_E_SUCCESS: "Success",
            HEARTBEAT_E_INVALID_ARG: "Invalid argument",
            HEARTBEAT_E_PLIST_ERROR: "Property list error",
            HEARTBEAT_E_MUX_ERROR: "MUX error",
            HEARTBEAT_E_SSL_ERROR: "SSL Error",
            HEARTBEAT_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class HeartbeatClient(PropertyListService):
    __service_name__ = "com.apple.heartbeat"
    cdef heartbeat_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(heartbeat_client_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))

    def __dealloc__(self):
        cdef heartbeat_error_t err
        if self._c_client is not NULL:
            err = heartbeat_client_free(self._c_client)
            self.handle_error(err)

    cdef inline int16_t _send(self, plist.plist_t node):
        return heartbeat_send(self._c_client, node)

    cdef inline int16_t _receive(self, plist.plist_t* node):
        return heartbeat_receive(self._c_client, node)

    cdef inline int16_t _receive_with_timeout(self, plist.plist_t* node, int timeout_ms):
        return heartbeat_receive_with_timeout(self._c_client, node, timeout_ms)

    cdef inline BaseError _error(self, int16_t ret):
        return HeartbeatError(ret)
