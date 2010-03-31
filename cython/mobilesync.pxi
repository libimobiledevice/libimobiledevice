cdef extern from "libimobiledevice/mobilesync.h":
    cdef struct mobilesync_client_private:
        pass
    ctypedef mobilesync_client_private *mobilesync_client_t

    ctypedef enum mobilesync_error_t:
        MOBILESYNC_E_SUCCESS = 0
        MOBILESYNC_E_INVALID_ARG = -1
        MOBILESYNC_E_PLIST_ERROR = -2
        MOBILESYNC_E_MUX_ERROR = -3
        MOBILESYNC_E_BAD_VERSION = -4
        MOBILESYNC_E_UNKNOWN_ERROR = -256

    mobilesync_error_t mobilesync_client_new(idevice_t device, uint16_t port, mobilesync_client_t * client)
    mobilesync_error_t mobilesync_client_free(mobilesync_client_t client)
    mobilesync_error_t mobilesync_receive(mobilesync_client_t client, plist.plist_t *plist)
    mobilesync_error_t mobilesync_send(mobilesync_client_t client, plist.plist_t plist)

cdef class MobileSyncError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            MOBILESYNC_E_SUCCESS: "Success",
            MOBILESYNC_E_INVALID_ARG: "Invalid argument",
            MOBILESYNC_E_PLIST_ERROR: "Property list error",
            MOBILESYNC_E_MUX_ERROR: "MUX error",
            MOBILESYNC_E_BAD_VERSION: "Bad version",
            MOBILESYNC_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class MobileSyncClient(PropertyListClient):
    cdef mobilesync_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownClient lockdown=None, *args, **kwargs):
        cdef:
            iDevice dev = device
            LockdownClient lckd
            mobilesync_error_t err
        if lockdown is None:
            lckd = LockdownClient(dev)
        else:
            lckd = lockdown
        port = lckd.start_service("com.apple.mobilesync")
        err = mobilesync_client_new(dev._c_dev, port, &(self._c_client))
        self.handle_error(err)
    
    def __dealloc__(self):
        cdef mobilesync_error_t err
        if self._c_client is not NULL:
            err = mobilesync_client_free(self._c_client)
            self.handle_error(err)
    
    cdef inline int16_t _send(self, plist.plist_t node):
        return mobilesync_send(self._c_client, node)

    cdef inline int16_t _receive(self, plist.plist_t* node):
        return mobilesync_receive(self._c_client, node)

    cdef inline BaseError _error(self, int16_t ret):
        return MobileSyncError(ret)
