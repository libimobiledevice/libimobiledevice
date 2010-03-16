cdef extern from *:
    ctypedef unsigned char uint8_t
    ctypedef short int int16_t
    ctypedef unsigned short int uint16_t
    ctypedef unsigned int uint32_t
    ctypedef int int32_t
IF UNAME_MACHINE == 'x86_64':
    ctypedef unsigned long int uint64_t
ELSE:
    ctypedef unsigned long long int uint64_t

cimport plist

cdef extern from "pyerrors.h":
    ctypedef class __builtin__.Exception [object PyBaseExceptionObject]:
        pass

cdef class BaseError(Exception):
    cdef dict _lookup_table
    cdef int16_t _c_errcode
    cpdef get_message(self)

    def __cinit__(self, int16_t errcode):
        self._c_errcode = errcode
        Exception.__init__(self, errcode)
    
    def __nonzero__(self):
        return self._c_errcode != 0

    cpdef get_message(self):
        return '%s (%s)' % (self._lookup_table[self._c_errcode], self._c_errcode)

    def __str__(self):
        return self.get_message()

    def __repr__(self):
        return self.__str__()

cdef extern from "libimobiledevice/libimobiledevice.h":
    cdef struct idevice_int:
        pass
    ctypedef idevice_int* idevice_t
    ctypedef int16_t idevice_error_t
    int16_t IDEVICE_E_SUCCESS
    int16_t IDEVICE_E_INVALID_ARG
    int16_t IDEVICE_E_UNKNOWN_ERROR
    int16_t IDEVICE_E_NO_DEVICE
    int16_t IDEVICE_E_NOT_ENOUGH_DATA
    int16_t IDEVICE_E_BAD_HEADER
    int16_t IDEVICE_E_SSL_ERROR
    cdef enum idevice_event_type:
        IDEVICE_DEVICE_ADD = 1,
        IDEVICE_DEVICE_REMOVE
    ctypedef struct idevice_event_t:
        idevice_event_type event
        char *uuid
        int conn_type
    ctypedef void (*idevice_event_cb_t) (idevice_event_t *event, void *user_data)
    cdef extern idevice_error_t c_idevice_event_subscribe "idevice_event_subscribe" (idevice_event_cb_t callback, void *user_data)
    cdef extern idevice_error_t c_idevice_event_unsubscribe "idevice_event_unsubscribe" ()
    void idevice_set_debug_level(int level)
    idevice_error_t idevice_new(idevice_t *device, char *uuid)
    idevice_error_t idevice_free(idevice_t device)
    idevice_error_t idevice_get_uuid(idevice_t device, char** uuid)
    idevice_error_t idevice_get_handle(idevice_t device, uint32_t *handle)

def set_debug_level(level):
    idevice_set_debug_level(level)

#cdef void idevice_event_cb(idevice_event_t *c_event, void *user_data):
    #event = iDeviceEvent()
    #event._c_event = c_event
    #(<object>user_data)(event)

#def idevice_event_subscribe(callback):
    #c_idevice_event_subscribe(idevice_event_cb, <void*>callback)

cdef class iDeviceError(BaseError):
    def __cinit__(self, *args, **kwargs):
        self._lookup_table = {
            IDEVICE_E_SUCCESS: 'Success',
            IDEVICE_E_INVALID_ARG: 'Invalid argument',
            IDEVICE_E_UNKNOWN_ERROR: 'Unknown error',
            IDEVICE_E_NO_DEVICE: 'No device',
            IDEVICE_E_NOT_ENOUGH_DATA: 'Not enough data',
            IDEVICE_E_BAD_HEADER: 'Bad header',
            IDEVICE_E_SSL_ERROR: 'SSL Error'
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class iDeviceEvent:
    cdef idevice_event_t* _c_event

cdef class iDevice:
    cdef idevice_t _c_dev

    def __cinit__(self, uuid=None, *args, **kwargs):
        cdef char* c_uuid = NULL
        if uuid is not None:
            c_uuid = uuid
        err = iDeviceError(idevice_new(&(self._c_dev), c_uuid))
        if err: raise err

    def __dealloc__(self):
        if self._c_dev is not NULL:
            err = iDeviceError(idevice_free(self._c_dev))
            if err: raise err

    property uuid:
        def __get__(self):
            cdef char* uuid
            err = iDeviceError(idevice_get_uuid(self._c_dev, &uuid))
            if err: raise err
            return uuid
    property handle:
        def __get__(self):
            cdef uint32_t handle
            err = iDeviceError(idevice_get_handle(self._c_dev, &handle))
            if err: raise err
            return handle

cdef extern from "libimobiledevice/lockdown.h":
    cdef struct lockdownd_client_int:
        pass
    ctypedef lockdownd_client_int *lockdownd_client_t
    ctypedef int16_t lockdownd_error_t
    int16_t LOCKDOWN_E_SUCCESS
    int16_t LOCKDOWN_E_INVALID_ARG
    int16_t LOCKDOWN_E_INVALID_CONF
    int16_t LOCKDOWN_E_PLIST_ERROR
    int16_t LOCKDOWN_E_PAIRING_FAILED
    int16_t LOCKDOWN_E_SSL_ERROR
    int16_t LOCKDOWN_E_DICT_ERROR
    int16_t LOCKDOWN_E_START_SERVICE_FAILED
    int16_t LOCKDOWN_E_NOT_ENOUGH_DATA
    int16_t LOCKDOWN_E_SET_VALUE_PROHIBITED
    int16_t LOCKDOWN_E_GET_VALUE_PROHIBITED
    int16_t LOCKDOWN_E_REMOVE_VALUE_PROHIBITED
    int16_t LOCKDOWN_E_MUX_ERROR
    int16_t LOCKDOWN_E_ACTIVATION_FAILED
    int16_t LOCKDOWN_E_PASSWORD_PROTECTED
    int16_t LOCKDOWN_E_NO_RUNNING_SESSION
    int16_t LOCKDOWN_E_INVALID_HOST_ID
    int16_t LOCKDOWN_E_INVALID_SERVICE
    int16_t LOCKDOWN_E_INVALID_ACTIVATION_RECORD
    int16_t LOCKDOWN_E_UNKNOWN_ERROR

    lockdownd_error_t lockdownd_client_new_with_handshake(idevice_t device, lockdownd_client_t *client, char *label)
    lockdownd_error_t lockdownd_client_free(lockdownd_client_t client)
    lockdownd_error_t lockdownd_start_service(lockdownd_client_t client, char *service, uint16_t *port)

cdef class LockdownError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            LOCKDOWN_E_SUCCESS: "Success",
            LOCKDOWN_E_INVALID_ARG: "Invalid argument",
            LOCKDOWN_E_INVALID_CONF: "Invalid configuration",
            LOCKDOWN_E_PLIST_ERROR: "PList error",
            LOCKDOWN_E_PAIRING_FAILED: "Pairing failed",
            LOCKDOWN_E_SSL_ERROR: "SSL error",
            LOCKDOWN_E_DICT_ERROR: "Dict error",
            LOCKDOWN_E_START_SERVICE_FAILED: "Start service failed",
            LOCKDOWN_E_NOT_ENOUGH_DATA: "Not enough data",
            LOCKDOWN_E_SET_VALUE_PROHIBITED: "Set value prohibited",
            LOCKDOWN_E_GET_VALUE_PROHIBITED: "Get value prohibited",
            LOCKDOWN_E_REMOVE_VALUE_PROHIBITED: "Remove value prohibited",
            LOCKDOWN_E_MUX_ERROR: "MUX Error",
            LOCKDOWN_E_ACTIVATION_FAILED: "Activation failed",
            LOCKDOWN_E_PASSWORD_PROTECTED: "Password protected",
            LOCKDOWN_E_NO_RUNNING_SESSION: "No running session",
            LOCKDOWN_E_INVALID_HOST_ID: "Invalid host ID",
            LOCKDOWN_E_INVALID_SERVICE: "Invalid service",
            LOCKDOWN_E_INVALID_ACTIVATION_RECORD: "Invalid activation record",
            LOCKDOWN_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class LockdownClient:
    cdef lockdownd_client_t _c_client

    def __cinit__(self, iDevice device not None, char *label=NULL, *args, **kwargs):
        cdef iDevice dev = device
        err = LockdownError(lockdownd_client_new_with_handshake(dev._c_dev, &(self._c_client), label))
        if err: raise err
    
    def __dealloc__(self):
        if self._c_client is not NULL:
            err = LockdownError(lockdownd_client_free(self._c_client))
            if err: raise err
    
    cpdef start_service(self, service):
        cdef uint16_t port
        err = LockdownError(lockdownd_start_service(self._c_client, service, &port))
        if err: raise err
        return port
    
    def goodbye(self):
        pass
        

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

cdef class MobileSyncClient:
    cdef mobilesync_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownClient lockdown not None, *args, **kwargs):
        cdef iDevice dev = device
        cdef LockdownClient lckd = lockdown
        port = lckd.start_service("com.apple.mobilesync")
        err = MobileSyncError(mobilesync_client_new(dev._c_dev, port, &(self._c_client)))
        if err: raise err
    
    def __dealloc__(self):
        if self._c_client is not NULL:
            err = MobileSyncError(mobilesync_client_free(self._c_client))
            if err: raise err
    
    cpdef send(self, object obj):
        cdef plist.Node node
        cdef plist.plist_t c_node
        if isinstance(obj, plist.Node):
            node = obj
            c_node = node._c_node
        else:
            c_node = plist.native_to_plist_t(obj)
        err = MobileSyncError(mobilesync_send(self._c_client, c_node))
        if err: raise err

    cpdef receive(self):
        cdef plist.plist_t c_node = NULL
        err = MobileSyncError(mobilesync_receive(self._c_client, &(c_node)))
        if err: raise err

        return plist.plist_t_to_node(c_node)

cdef extern from *:
    ctypedef char* const_char_ptr "const char*"

cdef extern from "libimobiledevice/notification_proxy.h":
    cdef struct np_client_int:
        pass
    ctypedef np_client_int *np_client_t
    ctypedef int16_t np_error_t
    ctypedef void (*np_notify_cb_t) (const_char_ptr notification, void *userdata)
    np_error_t np_client_new(idevice_t device, uint16_t port, np_client_t *client)
    np_error_t np_client_free(np_client_t client)
    np_error_t np_post_notification(np_client_t client, char *notification)
    np_error_t np_observe_notification(np_client_t client, char *notification)
    np_error_t np_observe_notifications(np_client_t client, char **notification_spec)
    np_error_t np_set_notify_callback(np_client_t client, np_notify_cb_t notify_cb, void *userdata)

cdef void np_notify_cb(const_char_ptr notification, void *py_callback):
    (<object>py_callback)(notification)

cdef class NotificationProxyError(BaseError):
    pass

cdef class NotificationProxy:
    cdef np_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownClient lockdown not None, *args, **kwargs):
        cdef iDevice dev = device
        cdef LockdownClient lckd = lockdown
        port = lckd.start_service("com.apple.mobile.notification_proxy")
        err = NotificationProxyError(np_client_new(dev._c_dev, port, &(self._c_client)))
        if err: raise err

    def __dealloc__(self):
        if self._c_client is not NULL:
            err = NotificationProxyError(np_client_free(self._c_client))
            if err: raise err
    
    def set_notify_callback(self, callback):
        err = NotificationProxyError(np_set_notify_callback(self._c_client, np_notify_cb, <void*>callback))
        if err: raise err
    
    def observe_notification(self, notification):
        err = NotificationProxyError(np_observe_notification(self._c_client, notification))
        if err: raise err

cdef extern from "libimobiledevice/sbservices.h":
    cdef struct sbservices_client_int:
        pass
    ctypedef sbservices_client_int *sbservices_client_t
    ctypedef int16_t sbservices_error_t
    sbservices_error_t sbservices_client_new(idevice_t device, uint16_t port, sbservices_client_t *client)
    sbservices_error_t sbservices_client_free(sbservices_client_t client)
    sbservices_error_t sbservices_get_icon_state(sbservices_client_t client, plist.plist_t *state)
    sbservices_error_t sbservices_set_icon_state(sbservices_client_t client, plist.plist_t newstate)
    sbservices_error_t sbservices_get_icon_pngdata(sbservices_client_t client, char *bundleId, char **pngdata, uint64_t *pngsize)

cdef class SpringboardServicesError(BaseError):
    pass

cdef class SpringboardServices:
    cdef sbservices_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownClient lockdown not None, *args, **kwargs):
        cdef iDevice dev = device
        cdef LockdownClient lckd = lockdown
        port = lockdown.start_service("com.apple.springboardservices")
        err = SpringboardServicesError(sbservices_client_new(dev._c_dev, port, &(self._c_client)))
        if err: raise err
    
    def __dealloc__(self):
        if self._c_client is not NULL:
            err = SpringboardServicesError(sbservices_client_free(self._c_client))
            if err: raise err
