REQUEST_TYPE_ALL = "All"
REQUEST_TYPE_WIFI = "WiFi"
REQUEST_TYPE_GAS_GAUGE = "GasGauge"
REQUEST_TYPE_NAND = "NAND"

cdef extern from "libimobiledevice/diagnostics_relay.h":
    cdef struct diagnostics_relay_client_private:
        pass
    ctypedef diagnostics_relay_client_private *diagnostics_relay_client_t

    ctypedef enum diagnostics_relay_error_t:
        DIAGNOSTICS_RELAY_E_SUCCESS = 0
        DIAGNOSTICS_RELAY_E_INVALID_ARG = -1
        DIAGNOSTICS_RELAY_E_PLIST_ERROR = -2
        DIAGNOSTICS_RELAY_E_MUX_ERROR = -3
        DIAGNOSTICS_RELAY_E_UNKNOWN_REQUEST = -4
        DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR = -256
    cdef enum:
        DIAGNOSTICS_RELAY_ACTION_FLAG_WAIT_FOR_DISCONNECT = (1 << 1)
        DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_PASS = (1 << 2)
        DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_FAIL = (1 << 3)

    diagnostics_relay_error_t diagnostics_relay_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, diagnostics_relay_client_t * client)
    diagnostics_relay_error_t diagnostics_relay_client_free(diagnostics_relay_client_t client)

    diagnostics_relay_error_t diagnostics_relay_goodbye(diagnostics_relay_client_t client)
    diagnostics_relay_error_t diagnostics_relay_sleep(diagnostics_relay_client_t client)
    diagnostics_relay_error_t diagnostics_relay_restart(diagnostics_relay_client_t client, int flags)
    diagnostics_relay_error_t diagnostics_relay_shutdown(diagnostics_relay_client_t client, int flags)
    diagnostics_relay_error_t diagnostics_relay_request_diagnostics(diagnostics_relay_client_t client, char* type, plist.plist_t* diagnostics)
    diagnostics_relay_error_t diagnostics_relay_query_mobilegestalt(diagnostics_relay_client_t client, plist.plist_t keys, plist.plist_t* result)
    diagnostics_relay_error_t diagnostics_relay_query_ioregistry_entry(diagnostics_relay_client_t client, char* name, char* class_name, plist.plist_t* result)
    diagnostics_relay_error_t diagnostics_relay_query_ioregistry_plane(diagnostics_relay_client_t client, char* plane, plist.plist_t* result)

cdef class DiagnosticsRelayError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            DIAGNOSTICS_RELAY_E_SUCCESS: "Success",
            DIAGNOSTICS_RELAY_E_INVALID_ARG: "Invalid argument",
            DIAGNOSTICS_RELAY_E_PLIST_ERROR: "Property list error",
            DIAGNOSTICS_RELAY_E_MUX_ERROR: "MUX error",
            DIAGNOSTICS_RELAY_E_UNKNOWN_REQUEST: "Unknown request",
            DIAGNOSTICS_RELAY_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class DiagnosticsRelayClient(PropertyListService):
    __service_name__ = "com.apple.mobile.diagnostics_relay"
    cdef diagnostics_relay_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(diagnostics_relay_client_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))

    def __dealloc__(self):
        cdef diagnostics_relay_error_t err
        if self._c_client is not NULL:
            err = diagnostics_relay_client_free(self._c_client)
            self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return DiagnosticsRelayError(ret)

    cpdef goodbye(self):
        self.handle_error(diagnostics_relay_goodbye(self._c_client))

    cpdef sleep(self):
        self.handle_error(diagnostics_relay_sleep(self._c_client))

    cpdef restart(self, int flags):
        self.handle_error(diagnostics_relay_restart(self._c_client, flags))

    cpdef shutdown(self, int flags):
        self.handle_error(diagnostics_relay_shutdown(self._c_client, flags))

    cpdef plist.Node request_diagnostics(self, bytes type):
        cdef:
            plist.plist_t c_node = NULL
            diagnostics_relay_error_t err
        err = diagnostics_relay_request_diagnostics(self._c_client, type, &c_node)
        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cpdef plist.Node query_mobilegestalt(self, plist.Node keys = None):
        cdef:
            plist.plist_t c_node = NULL
            diagnostics_relay_error_t err
            plist.plist_t keys_c_node = NULL
        if keys is not None:
            keys_c_node = keys._c_node
        err = diagnostics_relay_query_mobilegestalt(self._c_client, keys_c_node, &c_node)
        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cpdef plist.Node query_ioregistry_entry(self, bytes name, bytes class_name):
        cdef:
            plist.plist_t c_node = NULL
            diagnostics_relay_error_t err
        err = diagnostics_relay_query_ioregistry_entry(self._c_client, name, class_name, &c_node)
        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cpdef plist.Node query_ioregistry_plane(self, bytes plane = None):
        cdef:
            plist.plist_t c_node = NULL
            diagnostics_relay_error_t err
        err = diagnostics_relay_query_ioregistry_plane(self._c_client, plane, &c_node)
        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise
