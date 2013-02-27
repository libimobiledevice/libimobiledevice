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
        MOBILEBACKUP_E_REPLY_NOT_OK = -5
        MOBILEBACKUP_E_UNKNOWN_ERROR = -256

    ctypedef enum mobilebackup_flags_t:
        MB_RESTORE_NOTIFY_SPRINGBOARD = (1 << 0)
        MB_RESTORE_PRESERVE_SETTINGS = (1 << 1)
        MB_RESTORE_PRESERVE_CAMERA_ROLL = (1 << 2)

    mobilebackup_error_t mobilebackup_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, mobilebackup_client_t * client)
    mobilebackup_error_t mobilebackup_client_free(mobilebackup_client_t client)
    mobilebackup_error_t mobilebackup_receive(mobilebackup_client_t client, plist.plist_t *plist)
    mobilebackup_error_t mobilebackup_send(mobilebackup_client_t client, plist.plist_t plist)
    mobilebackup_error_t mobilebackup_request_backup(mobilebackup_client_t client, plist.plist_t backup_manifest, char *base_path, char *proto_version)
    mobilebackup_error_t mobilebackup_send_backup_file_received(mobilebackup_client_t client)
    mobilebackup_error_t mobilebackup_request_restore(mobilebackup_client_t client, plist.plist_t backup_manifest, mobilebackup_flags_t flags, char *proto_version)
    mobilebackup_error_t mobilebackup_receive_restore_file_received(mobilebackup_client_t client, plist.plist_t *result)
    mobilebackup_error_t mobilebackup_receive_restore_application_received(mobilebackup_client_t client, plist.plist_t *result)
    mobilebackup_error_t mobilebackup_send_restore_complete(mobilebackup_client_t client)
    mobilebackup_error_t mobilebackup_send_error(mobilebackup_client_t client, char *reason)

cdef class MobileBackupError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            MOBILEBACKUP_E_SUCCESS: "Success",
            MOBILEBACKUP_E_INVALID_ARG: "Invalid argument",
            MOBILEBACKUP_E_PLIST_ERROR: "Property list error",
            MOBILEBACKUP_E_MUX_ERROR: "MUX error",
            MOBILEBACKUP_E_BAD_VERSION: "Bad version",
            MOBILEBACKUP_E_REPLY_NOT_OK: "Reply not OK",
            MOBILEBACKUP_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class MobileBackupClient(PropertyListService):
    __service_name__ = "com.apple.mobilebackup"
    cdef mobilebackup_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(mobilebackup_client_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))

    def __dealloc__(self):
        cdef mobilebackup_error_t err
        if self._c_client is not NULL:
            err = mobilebackup_client_free(self._c_client)
            self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return MobileBackupError(ret)

    cdef inline int16_t _send(self, plist.plist_t node):
        return mobilebackup_send(self._c_client, node)

    cdef inline int16_t _receive(self, plist.plist_t* node):
        return mobilebackup_receive(self._c_client, node)

    cdef request_backup(self, plist.Node backup_manifest, bytes base_path, bytes proto_version):
        self.handle_error(mobilebackup_request_backup(self._c_client, backup_manifest._c_node, base_path, proto_version))

    cdef send_backup_file_received(self):
        self.handle_error(mobilebackup_send_backup_file_received(self._c_client))

    cdef request_restore(self, plist.Node backup_manifest, int flags, proto_version):
        self.handle_error(mobilebackup_request_restore(self._c_client, backup_manifest._c_node, <mobilebackup_flags_t>flags, proto_version))

    cpdef plist.Node receive_restore_file_received(self):
        cdef:
            plist.plist_t c_node = NULL
            mobilebackup_error_t err
        err = mobilebackup_receive_restore_file_received(self._c_client, &c_node)
        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cpdef plist.Node receive_restore_application_received(self):
        cdef:
            plist.plist_t c_node = NULL
            mobilebackup_error_t err
        err = mobilebackup_receive_restore_application_received(self._c_client, &c_node)
        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cdef send_restore_complete(self):
        self.handle_error(mobilebackup_send_restore_complete(self._c_client))

    cdef send_error(self, bytes reason):
        self.handle_error(mobilebackup_send_error(self._c_client, reason))
