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
        MOBILESYNC_E_SYNC_REFUSED = -5
        MOBILESYNC_E_CANCELLED = -6
        MOBILESYNC_E_WRONG_DIRECTION = -7
        MOBILESYNC_E_NOT_READY = -8
        MOBILESYNC_E_UNKNOWN_ERROR = -256

    ctypedef enum mobilesync_sync_type_t:
        MOBILESYNC_SYNC_TYPE_FAST
        MOBILESYNC_SYNC_TYPE_SLOW
        MOBILESYNC_SYNC_TYPE_RESET

    ctypedef struct mobilesync_anchors:
        char *device_anchor
        char *host_anchor
    ctypedef mobilesync_anchors *mobilesync_anchors_t

    mobilesync_error_t mobilesync_client_new(idevice_t device, lockdownd_service_descriptor_t service, mobilesync_client_t * client)
    mobilesync_error_t mobilesync_client_free(mobilesync_client_t client)
    mobilesync_error_t mobilesync_receive(mobilesync_client_t client, plist.plist_t *plist)
    mobilesync_error_t mobilesync_send(mobilesync_client_t client, plist.plist_t plist)

    mobilesync_error_t mobilesync_start(mobilesync_client_t client, char *data_class, mobilesync_anchors_t anchors, uint64_t computer_data_class_version, mobilesync_sync_type_t *sync_type, uint64_t *device_data_class_version, char** error_description)
    mobilesync_error_t mobilesync_cancel(mobilesync_client_t client, char* reason)
    mobilesync_error_t mobilesync_finish(mobilesync_client_t client)

    mobilesync_error_t mobilesync_get_all_records_from_device(mobilesync_client_t client)
    mobilesync_error_t mobilesync_get_changes_from_device(mobilesync_client_t client)
    mobilesync_error_t mobilesync_receive_changes(mobilesync_client_t client, plist.plist_t *entities, uint8_t *is_last_record, plist.plist_t *actions)
    mobilesync_error_t mobilesync_acknowledge_changes_from_device(mobilesync_client_t client)

    mobilesync_error_t mobilesync_ready_to_send_changes_from_computer(mobilesync_client_t client)
    mobilesync_error_t mobilesync_send_changes(mobilesync_client_t client, plist.plist_t changes, uint8_t is_last_record, plist.plist_t actions)
    mobilesync_error_t mobilesync_remap_identifiers(mobilesync_client_t client, plist.plist_t *mapping)

    mobilesync_anchors_t mobilesync_anchors_new(char *device_anchor, char *computer_anchor)
    void mobilesync_anchors_free(mobilesync_anchors_t anchors)

    plist.plist_t mobilesync_actions_new()
    void mobilesync_actions_add(plist.plist_t actions, ...)
    void mobilesync_actions_free(plist.plist_t actions)

SYNC_TYPE_FAST = MOBILESYNC_SYNC_TYPE_FAST
SYNC_TYPE_SLOW = MOBILESYNC_SYNC_TYPE_SLOW
SYNC_TYPE_RESET = MOBILESYNC_SYNC_TYPE_RESET

cdef class MobileSyncError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            MOBILESYNC_E_SUCCESS: "Success",
            MOBILESYNC_E_INVALID_ARG: "Invalid argument",
            MOBILESYNC_E_PLIST_ERROR: "Property list error",
            MOBILESYNC_E_MUX_ERROR: "MUX error",
            MOBILESYNC_E_BAD_VERSION: "Bad version",
            MOBILESYNC_E_SYNC_REFUSED: "Sync refused",
            MOBILESYNC_E_CANCELLED: "Sync cancelled",
            MOBILESYNC_E_WRONG_DIRECTION: "Wrong sync direction",
            MOBILESYNC_E_NOT_READY: "Not ready to receive changes",
            MOBILESYNC_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class MobileSyncClient(DeviceLinkService):
    __service_name__ = "com.apple.mobilesync"
    cdef mobilesync_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(mobilesync_client_new(device._c_dev, descriptor._c_service_descriptor, &(self._c_client)))
    
    def __dealloc__(self):
        cdef mobilesync_error_t err
        if self._c_client is not NULL:
            err = mobilesync_client_free(self._c_client)
            self.handle_error(err)

    cpdef tuple start(self, bytes data_class, bytes device_anchor, bytes host_anchor):
        cdef:
            mobilesync_anchors_t anchors = NULL
            mobilesync_sync_type_t sync_type
            uint64_t computer_data_class_version = 1
            uint64_t device_data_class_version
            char* error_description = NULL

        if device_anchor is None:
            anchors = mobilesync_anchors_new(NULL, host_anchor)
        else:
            anchors = mobilesync_anchors_new(device_anchor, host_anchor)

        try:
            self.handle_error(mobilesync_start(self._c_client, data_class, anchors, computer_data_class_version, &sync_type, &device_data_class_version, &error_description))
            return (sync_type, <bint>computer_data_class_version, <bint>device_data_class_version, <bytes>error_description)
        except Exception, e:
            raise
        finally:
            mobilesync_anchors_free(anchors)

    cpdef finish(self):
        self.handle_error(mobilesync_finish(self._c_client))

    cpdef cancel(self, bytes reason):
        self.handle_error(mobilesync_cancel(self._c_client, reason))

    cpdef get_all_records_from_device(self):
        self.handle_error(mobilesync_get_all_records_from_device(self._c_client))

    cpdef get_changes_from_device(self):
        self.handle_error(mobilesync_get_changes_from_device(self._c_client))

    cpdef tuple receive_changes(self):
        cdef:
            plist.plist_t entities = NULL
            uint8_t is_last_record = 0
            plist.plist_t actions = NULL
        try:
            self.handle_error(mobilesync_receive_changes(self._c_client, &entities, &is_last_record, &actions))
            return (plist.plist_t_to_node(entities), <bint>is_last_record, plist.plist_t_to_node(actions))
        except Exception, e:
            if entities != NULL:
                plist.plist_free(entities)
            if actions != NULL:
                plist.plist_free(actions)
            raise

    cpdef acknowledge_changes_from_device(self):
        self.handle_error(mobilesync_acknowledge_changes_from_device(self._c_client))

    cpdef ready_to_send_changes_from_computer(self):
        self.handle_error(mobilesync_ready_to_send_changes_from_computer(self._c_client))

    cpdef send_changes(self, plist.Node changes, bint is_last_record, plist.Node actions):
        self.handle_error(mobilesync_send_changes(self._c_client, changes._c_node, is_last_record, actions._c_node))

    cpdef remap_identifiers(self):
        cdef plist.plist_t remapping = NULL

        try:
            self.handle_error(mobilesync_remap_identifiers(self._c_client, &remapping))
            return plist.plist_t_to_node(remapping)
        except Exception, e:
            if remapping != NULL:
                plist.plist_free(remapping)
            raise
    
    cdef int16_t _send(self, plist.plist_t node):
        return mobilesync_send(self._c_client, node)

    cdef int16_t _receive(self, plist.plist_t* node):
        return mobilesync_receive(self._c_client, node)

    cdef inline BaseError _error(self, int16_t ret):
        return MobileSyncError(ret)
