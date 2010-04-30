cdef extern from "libimobiledevice/mobilebackup.h":
    cdef struct mobilebackup_client_private:
        pass
    ctypedef mobilebackup_client_private *mobilebackup_client_t

    ctypedef enum mobilebackup_error_t:
        MOBILEBACKUP_E_SUCCESS = 0
        MOBILEBACKUP_E_INVALID_ARG = -1
        MOBILEBACKUP_E_PLIST_ERROR = -2
        MOBILEBACKUP_E_MUX_ERROR = -3
        MOBILEBACKUP_E_BAD_VERSION = -4
        MOBILEBACKUP_E_UNKNOWN_ERROR = -256

    mobilebackup_error_t mobilebackup_client_new(idevice_t device, uint16_t port, mobilebackup_client_t * client)
    mobilebackup_error_t mobilebackup_client_free(mobilebackup_client_t client)
    mobilebackup_error_t mobilebackup_receive(mobilebackup_client_t client, plist.plist_t *plist)
    mobilebackup_error_t mobilebackup_send(mobilebackup_client_t client, plist.plist_t plist)

cdef class MobileBackupError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            MOBILEBACKUP_E_SUCCESS: "Success",
            MOBILEBACKUP_E_INVALID_ARG: "Invalid argument",
            MOBILEBACKUP_E_PLIST_ERROR: "Property list error",
            MOBILEBACKUP_E_MUX_ERROR: "MUX error",
            MOBILEBACKUP_E_BAD_VERSION: "Bad version",
            MOBILEBACKUP_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class MobileBackupClient(PropertyListService):
    __service_name__ = "com.apple.mobilebackup"
    cdef mobilebackup_client_t _c_client

    def __cinit__(self, iDevice device not None, int port, *args, **kwargs):
        self.handle_error(mobilebackup_client_new(device._c_dev, port, &self._c_client))

    def __dealloc__(self):
        cdef mobilebackup_error_t err
        if self._c_client is not NULL:
            err = mobilebackup_client_free(self._c_client)
            self.handle_error(err)

    cdef inline int16_t _send(self, plist.plist_t node):
        return mobilebackup_send(self._c_client, node)

    cdef inline int16_t _receive(self, plist.plist_t* node):
        return mobilebackup_receive(self._c_client, node)

    cdef inline BaseError _error(self, int16_t ret):
        return MobileBackupError(ret)
