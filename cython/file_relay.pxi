cdef extern from "libimobiledevice/file_relay.h":
    cdef struct file_relay_client_private:
        pass
    ctypedef file_relay_client_private *file_relay_client_t
    ctypedef char** const_sources_t "const char**"

    ctypedef enum file_relay_error_t:
        FILE_RELAY_E_SUCCESS = 0
        FILE_RELAY_E_INVALID_ARG = -1
        FILE_RELAY_E_PLIST_ERROR = -2
        FILE_RELAY_E_MUX_ERROR = -3
        FILE_RELAY_E_INVALID_SOURCE = -4
        FILE_RELAY_E_STAGING_EMPTY = -5
        FILE_RELAY_E_UNKNOWN_ERROR = -256

    file_relay_error_t file_relay_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, file_relay_client_t *client)
    file_relay_error_t file_relay_client_free(file_relay_client_t client)

    file_relay_error_t file_relay_request_sources(file_relay_client_t client, const_sources_t sources, idevice_connection_t *connection)

cdef class FileRelayError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            FILE_RELAY_E_SUCCESS: "Success",
            FILE_RELAY_E_INVALID_ARG: "Invalid argument",
            FILE_RELAY_E_PLIST_ERROR: "Property list error",
            FILE_RELAY_E_MUX_ERROR: "MUX error",
            FILE_RELAY_E_INVALID_SOURCE: "Invalid source",
            FILE_RELAY_E_STAGING_EMPTY: "Staging empty",
            FILE_RELAY_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

from libc.stdlib cimport *

cdef class FileRelayClient(PropertyListService):
    __service_name__ = "com.apple.mobile.file_relay"
    cdef file_relay_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(file_relay_client_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))

    def __dealloc__(self):
        cdef file_relay_error_t err
        if self._c_client is not NULL:
            err = file_relay_client_free(self._c_client)
            self.handle_error(err)

    cpdef iDeviceConnection request_sources(self, list sources):
        cdef:
            file_relay_error_t err
            Py_ssize_t count = len(sources)
            char** c_sources = <char**>malloc(sizeof(char*) * (count + 1))
            iDeviceConnection conn = iDeviceConnection.__new__(iDeviceConnection)

        for i, value in enumerate(sources):
            c_sources[i] = value
        c_sources[count] = NULL

        err = file_relay_request_sources(self._c_client, <const_sources_t>c_sources, &conn._c_connection)
        free(c_sources)
        self.handle_error(err)
        return conn

    cdef inline BaseError _error(self, int16_t ret):
        return FileRelayError(ret)
