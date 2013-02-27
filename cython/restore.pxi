cdef extern from "libimobiledevice/restore.h":
    cdef struct restored_client_private:
        pass
    ctypedef restored_client_private *restored_client_t

    ctypedef enum restored_error_t:
        RESTORE_E_SUCCESS = 0
        RESTORE_E_INVALID_ARG = -1
        RESTORE_E_INVALID_CONF = -2
        RESTORE_E_PLIST_ERROR = -3
        RESTORE_E_DICT_ERROR = -4
        RESTORE_E_NOT_ENOUGH_DATA = -5
        RESTORE_E_MUX_ERROR = -6
        RESTORE_E_START_RESTORE_FAILED = -7
        RESTORE_E_UNKNOWN_ERROR = -256

    restored_error_t restored_client_new(idevice_t device, restored_client_t *client, char *label)
    restored_error_t restored_client_free(restored_client_t client)

    restored_error_t restored_query_type(restored_client_t client, char **tp, uint64_t *version)
    restored_error_t restored_query_value(restored_client_t client, char *key, plist.plist_t *value)
    restored_error_t restored_get_value(restored_client_t client, char *key, plist.plist_t *value)
    restored_error_t restored_send(restored_client_t client, plist.plist_t plist)
    restored_error_t restored_receive(restored_client_t client, plist.plist_t *plist)
    restored_error_t restored_goodbye(restored_client_t client)

    restored_error_t restored_start_restore(restored_client_t client, plist.plist_t options, uint64_t version)
    restored_error_t restored_reboot(restored_client_t client)

    void restored_client_set_label(restored_client_t client, char *label)

cdef class RestoreError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            RESTORE_E_SUCCESS: "Success",
            RESTORE_E_INVALID_ARG: "Invalid argument",
            RESTORE_E_INVALID_CONF: "Invalid configuration",
            RESTORE_E_PLIST_ERROR: "Property list error",
            RESTORE_E_DICT_ERROR: "Dict error",
            RESTORE_E_NOT_ENOUGH_DATA: "Not enough data",
            RESTORE_E_MUX_ERROR: "MUX Error",
            RESTORE_E_START_RESTORE_FAILED: "Starting restore failed",
            RESTORE_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class RestoreClient(PropertyListService):
    cdef restored_client_t _c_client

    def __cinit__(self, iDevice device not None, bytes label=b'', *args, **kwargs):
        cdef:
            restored_error_t err
            char* c_label = NULL
        if label:
            c_label = label
        err = restored_client_new(device._c_dev, &self._c_client, c_label)
        self.handle_error(err)

        self.device = device

    def __dealloc__(self):
        cdef restored_error_t err
        if self._c_client is not NULL:
            err = restored_client_free(self._c_client)
            self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return RestoreError(ret)

    cdef inline int16_t _send(self, plist.plist_t node):
        return restored_send(self._c_client, node)

    cdef inline int16_t _receive(self, plist.plist_t* node):
        return restored_receive(self._c_client, node)

    cpdef tuple query_type(self):
        cdef:
            restored_error_t err
            char* c_type = NULL
            uint64_t c_version = 0
            tuple result
        err = restored_query_type(self._c_client, &c_type, &c_version)
        try:
            self.handle_error(err)
            result = (c_type, c_version)
            return result
        except BaseError, e:
            raise
        finally:
            if c_type != NULL:
                free(c_type)

    cpdef plist.Node query_value(self, bytes key=None):
        cdef:
            restored_error_t err
            plist.plist_t c_node = NULL
            char* c_key = NULL
        if key is not None:
            c_key = key
        err = restored_query_value(self._c_client, c_key, &c_node)
        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cpdef plist.Node get_value(self, bytes key=None):
        cdef:
            restored_error_t err
            plist.plist_t c_node = NULL
            char* c_key = NULL
        if key is not None:
            c_key = key
        err = restored_get_value(self._c_client, c_key, &c_node)
        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cpdef goodbye(self):
        self.handle_error(restored_goodbye(self._c_client))

    cpdef start_restore(self, plist.Node options, uint64_t version):
        self.handle_error(restored_start_restore(self._c_client, options._c_node, version))

    cpdef reboot(self):
        self.handle_error(restored_reboot(self._c_client))

    cpdef set_label(self, bytes label):
        restored_client_set_label(self._c_client, label)
