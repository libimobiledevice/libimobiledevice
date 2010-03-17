cdef extern from "libimobiledevice/mobilesync.h":
    cdef struct mobilesync_client_int:
        pass
    ctypedef mobilesync_client_int *mobilesync_client_t

    ctypedef int16_t mobilesync_error_t
    int16_t MOBILESYNC_E_SUCCESS
    int16_t MOBILESYNC_E_INVALID_ARG
    int16_t MOBILESYNC_E_PLIST_ERROR
    int16_t MOBILESYNC_E_MUX_ERROR
    int16_t MOBILESYNC_E_BAD_VERSION
    int16_t MOBILESYNC_E_UNKNOWN_ERROR

    mobilesync_error_t mobilesync_client_new(idevice_t device, uint16_t port, mobilesync_client_t * client)
    mobilesync_error_t mobilesync_client_free(mobilesync_client_t client)
    mobilesync_error_t mobilesync_receive(mobilesync_client_t client, plist.plist_t *plist)
    mobilesync_error_t mobilesync_send(mobilesync_client_t client, plist.plist_t plist)

cdef class MobileSyncError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            MOBILESYNC_E_SUCCESS: "Success",
            MOBILESYNC_E_INVALID_ARG: "Invalid argument",
            MOBILESYNC_E_PLIST_ERROR: "PList Error",
            MOBILESYNC_E_MUX_ERROR: "MUX Error",
            MOBILESYNC_E_BAD_VERSION: "Bad Version",
            MOBILESYNC_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class MobileSyncClient(PropertyListService):
    cdef mobilesync_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownClient lockdown=None, *args, **kwargs):
        cdef iDevice dev = device
        cdef LockdownClient lckd
        if lockdown is None:
            lckd = LockdownClient(dev)
        else:
            lckd = lockdown
        port = lckd.start_service("com.apple.mobilesync")
        err = MobileSyncError(mobilesync_client_new(dev._c_dev, port, &(self._c_client)))
        if err: raise err
    
    def __dealloc__(self):
        if self._c_client is not NULL:
            err = MobileSyncError(mobilesync_client_free(self._c_client))
            if err: raise err
    
    cdef _send(self, plist.plist_t node):
        return MobileSyncError(mobilesync_send(self._c_client, node))

    cdef _receive(self, plist.plist_t* node):
        return MobileSyncError(mobilesync_receive(self._c_client, node))
