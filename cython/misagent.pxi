cdef extern from "libimobiledevice/misagent.h":
    cdef struct misagent_client_private:
        pass
    ctypedef misagent_client_private *misagent_client_t

    ctypedef enum misagent_error_t:
        MISAGENT_E_SUCCESS = 0
        MISAGENT_E_INVALID_ARG = -1
        MISAGENT_E_PLIST_ERROR = -2
        MISAGENT_E_CONN_FAILED = -3
        MISAGENT_E_REQUEST_FAILED = -4
        MISAGENT_E_UNKNOWN_ERROR = -256

    misagent_error_t misagent_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, misagent_client_t * client)
    misagent_error_t misagent_client_free(misagent_client_t client)

    misagent_error_t misagent_install(misagent_client_t client, plist.plist_t profile)
    misagent_error_t misagent_copy(misagent_client_t client, plist.plist_t* profiles)
    misagent_error_t misagent_remove(misagent_client_t client, char* profileID)
    int misagent_get_status_code(misagent_client_t client)

cdef class MisagentError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            MISAGENT_E_SUCCESS: "Success",
            MISAGENT_E_INVALID_ARG: "Invalid argument",
            MISAGENT_E_PLIST_ERROR: "Property list error",
            MISAGENT_E_CONN_FAILED: "Connection failed",
            MISAGENT_E_REQUEST_FAILED: "Request failed",
            MISAGENT_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class MisagentClient(PropertyListService):
    __service_name__ = "com.apple.misagent"
    cdef misagent_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(misagent_client_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))

    def __dealloc__(self):
        cdef misagent_error_t err
        if self._c_client is not NULL:
            err = misagent_client_free(self._c_client)
            self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return MisagentError(ret)

    cpdef install(self, plist.Node profile):
        cdef misagent_error_t err
        err = misagent_install(self._c_client, profile._c_node)
        self.handle_error(err)

    cpdef plist.Node copy(self):
        cdef:
            plist.plist_t c_node = NULL
            misagent_error_t err
        err = misagent_copy(self._c_client, &c_node)
        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cpdef remove(self, bytes profile_id):
        cdef misagent_error_t err
        err = misagent_remove(self._c_client, profile_id)
        self.handle_error(err)

    cpdef int get_status_code(self):
        return misagent_get_status_code(self._c_client)
