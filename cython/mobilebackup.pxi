cdef extern from "libimobiledevice/mobilebackup.h":
    cdef struct mobilebackup_client_int:
        pass
    ctypedef mobilebackup_client_int *mobilebackup_client_t

    ctypedef int16_t mobilebackup_error_t
    int16_t MOBILEBACKUP_E_SUCCESS
    int16_t MOBILEBACKUP_E_INVALID_ARG
    int16_t MOBILEBACKUP_E_PLIST_ERROR
    int16_t MOBILEBACKUP_E_MUX_ERROR
    int16_t MOBILEBACKUP_E_BAD_VERSION
    int16_t MOBILEBACKUP_E_UNKNOWN_ERROR

    mobilebackup_error_t mobilebackup_client_new(idevice_t device, uint16_t port, mobilebackup_client_t * client)
    mobilebackup_error_t mobilebackup_client_free(mobilebackup_client_t client)
    mobilebackup_error_t mobilebackup_receive(mobilebackup_client_t client, plist.plist_t *plist)
    mobilebackup_error_t mobilebackup_send(mobilebackup_client_t client, plist.plist_t plist)

cdef class MobileBackupError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            MOBILEBACKUP_E_SUCCESS: "Success",
            MOBILEBACKUP_E_INVALID_ARG: "Invalid argument",
            MOBILEBACKUP_E_PLIST_ERROR: "PList Error",
            MOBILEBACKUP_E_MUX_ERROR: "MUX Error",
            MOBILEBACKUP_E_BAD_VERSION: "Bad Version",
            MOBILEBACKUP_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class MobileBackupClient(PropertyListClient):
    cdef mobilebackup_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownClient lockdown=None, *args, **kwargs):
        cdef:
            iDevice dev = device
            LockdownClient lckd
            mobilebackup_error_t err
        if lockdown is None:
            lckd = LockdownClient(dev)
        else:
            lckd = lockdown
        port = lckd.start_service("com.apple.mobilebackup")
        err = mobilebackup_client_new(dev._c_dev, port, &self._c_client)
        self.handle_error(err)

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
