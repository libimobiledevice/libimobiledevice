cdef extern from "libimobiledevice/mobilebackup2.h":
    cdef struct mobilebackup2_client_private:
        pass
    ctypedef mobilebackup2_client_private *mobilebackup2_client_t

    ctypedef enum mobilebackup2_error_t:
        MOBILEBACKUP2_E_SUCCESS = 0
        MOBILEBACKUP2_E_INVALID_ARG = -1
        MOBILEBACKUP2_E_PLIST_ERROR = -2
        MOBILEBACKUP2_E_MUX_ERROR = -3
        MOBILEBACKUP2_E_BAD_VERSION = -4
        MOBILEBACKUP2_E_REPLY_NOT_OK = -5
        MOBILEBACKUP2_E_NO_COMMON_VERSION = -6
        MOBILEBACKUP2_E_UNKNOWN_ERROR = -256

    mobilebackup2_error_t mobilebackup2_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, mobilebackup2_client_t * client)
    mobilebackup2_error_t mobilebackup2_client_free(mobilebackup2_client_t client)

    mobilebackup2_error_t mobilebackup2_send_message(mobilebackup2_client_t client, char *message, plist.plist_t options)
    mobilebackup2_error_t mobilebackup2_receive_message(mobilebackup2_client_t client, plist.plist_t *msg_plist, char **dlmessage)
    mobilebackup2_error_t mobilebackup2_send_raw(mobilebackup2_client_t client, char *data, uint32_t length, uint32_t *bytes)
    mobilebackup2_error_t mobilebackup2_receive_raw(mobilebackup2_client_t client, char *data, uint32_t length, uint32_t *bytes)
    mobilebackup2_error_t mobilebackup2_version_exchange(mobilebackup2_client_t client, double local_versions[], char count, double *remote_version)
    mobilebackup2_error_t mobilebackup2_send_request(mobilebackup2_client_t client, char *request, char *target_identifier, char *source_identifier, plist.plist_t options)
    mobilebackup2_error_t mobilebackup2_send_status_response(mobilebackup2_client_t client, int status_code, char *status1, plist.plist_t status2)

cdef class MobileBackup2Error(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            MOBILEBACKUP2_E_SUCCESS: "Success",
            MOBILEBACKUP2_E_INVALID_ARG: "Invalid argument",
            MOBILEBACKUP2_E_PLIST_ERROR: "Property list error",
            MOBILEBACKUP2_E_MUX_ERROR: "MUX error",
            MOBILEBACKUP2_E_BAD_VERSION: "Bad version",
            MOBILEBACKUP2_E_REPLY_NOT_OK: "Reply not OK",
            MOBILEBACKUP2_E_NO_COMMON_VERSION: "No common version",
            MOBILEBACKUP2_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class MobileBackup2Client(PropertyListService):
    __service_name__ = "com.apple.mobilebackup2"
    cdef mobilebackup2_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(mobilebackup2_client_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))

    def __dealloc__(self):
        cdef mobilebackup2_error_t err
        if self._c_client is not NULL:
            err = mobilebackup2_client_free(self._c_client)
            self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return MobileBackup2Error(ret)

    cdef send_message(self, bytes message, plist.Node options):
        self.handle_error(mobilebackup2_send_message(self._c_client, message, options._c_node))

    cdef tuple receive_message(self):
        cdef:
            char* dlmessage = NULL
            plist.plist_t c_node = NULL
            mobilebackup2_error_t err
        err = mobilebackup2_receive_message(self._c_client, &c_node, &dlmessage)
        try:
            self.handle_error(err)
            return (plist.plist_t_to_node(c_node), <bytes>dlmessage)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            if dlmessage != NULL:
                free(dlmessage)
            raise

    cdef int send_raw(self, bytes data, int length):
        cdef:
            uint32_t bytes = 0
            mobilebackup2_error_t err
        err = mobilebackup2_send_raw(self._c_client, data, length, &bytes)
        try:
            self.handle_error(err)
            return <bint>bytes
        except BaseError, e:
            raise

    cdef int receive_raw(self, bytes data, int length):
        cdef:
            uint32_t bytes = 0
            mobilebackup2_error_t err
        err = mobilebackup2_receive_raw(self._c_client, data, length, &bytes)
        try:
            self.handle_error(err)
            return <bint>bytes
        except BaseError, e:
            raise

    cdef float version_exchange(self, double[::1] local_versions):
        cdef:
            double[::1] temp = None
            double remote_version = 0.0
            mobilebackup2_error_t err
        err = mobilebackup2_version_exchange(self._c_client, &local_versions[0], len(local_versions), &remote_version)
        try:
            self.handle_error(err)
            return <float>remote_version
        except BaseError, e:
            raise

    cdef send_request(self, bytes request, bytes target_identifier, bytes source_identifier, plist.Node options):
        self.handle_error(mobilebackup2_send_request(self._c_client, request, target_identifier, source_identifier, options._c_node))

    cdef send_status_response(self, int status_code, bytes status1, plist.Node status2):
        self.handle_error(mobilebackup2_send_status_response(self._c_client, status_code, status1, status2._c_node))
