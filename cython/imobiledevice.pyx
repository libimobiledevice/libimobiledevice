cdef class BaseError(Exception):
    def __cinit__(self, int16_t errcode):
        self._c_errcode = errcode

    def __nonzero__(self):
        return self._c_errcode != 0

    property message:
        def __get__(self):
            if self._c_errcode in self._lookup_table:
                return self._lookup_table[self._c_errcode]
            else:
                return "Unknown error ({0})".format(self._c_errcode)

    property code:
        def __get__(self):
            return self._c_errcode

    def __str__(self):
        return '%s (%s)' % (self.message, self.code)

    def __repr__(self):
        return self.__str__()

cdef class Base:
    cdef inline int handle_error(self, int16_t ret) except -1:
        if ret == 0:
            return 0
        cdef BaseError err = self._error(ret)
        raise err

    cdef BaseError _error(self, int16_t ret): pass

cdef extern from "libimobiledevice/libimobiledevice.h":
    ctypedef enum idevice_error_t:
        IDEVICE_E_SUCCESS = 0
        IDEVICE_E_INVALID_ARG = -1
        IDEVICE_E_UNKNOWN_ERROR = -2
        IDEVICE_E_NO_DEVICE = -3
        IDEVICE_E_NOT_ENOUGH_DATA = -4
        IDEVICE_E_BAD_HEADER = -5
        IDEVICE_E_SSL_ERROR = -6
    ctypedef void (*idevice_event_cb_t) (const_idevice_event_t event, void *user_data)
    cdef extern idevice_error_t idevice_event_subscribe(idevice_event_cb_t callback, void *user_data)
    cdef extern idevice_error_t idevice_event_unsubscribe()
    idevice_error_t idevice_get_device_list(char ***devices, int *count)
    idevice_error_t idevice_device_list_free(char **devices)
    void idevice_set_debug_level(int level)
    idevice_error_t idevice_new(idevice_t *device, char *udid)
    idevice_error_t idevice_free(idevice_t device)
    idevice_error_t idevice_get_udid(idevice_t device, char** udid)
    idevice_error_t idevice_get_handle(idevice_t device, uint32_t *handle)
    idevice_error_t idevice_connect(idevice_t device, uint16_t port, idevice_connection_t *connection)
    idevice_error_t idevice_disconnect(idevice_connection_t connection)
    idevice_error_t idevice_connection_send(idevice_connection_t connection, char *data, uint32_t len, uint32_t *sent_bytes)
    idevice_error_t idevice_connection_receive_timeout(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout)
    idevice_error_t idevice_connection_receive(idevice_connection_t connection, char *data, uint32_t len, uint32_t *recv_bytes)

cdef class iDeviceError(BaseError):
    def __init__(self, *args, **kwargs):
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

def set_debug_level(int level):
    idevice_set_debug_level(level)

cdef class iDeviceEvent:
    def __init__(self, *args, **kwargs):
        raise TypeError("iDeviceEvent cannot be instantiated")

    def __str__(self):
        return 'iDeviceEvent: %s (%s)' % (self.event == IDEVICE_DEVICE_ADD and 'Add' or 'Remove', self.udid)

    property event:
        def __get__(self):
            return self._c_event.event
    property udid:
        def __get__(self):
            return self._c_event.udid
    property conn_type:
        def __get__(self):
            return self._c_event.conn_type

cdef void idevice_event_cb(const_idevice_event_t c_event, void *user_data) with gil:
    cdef iDeviceEvent event = iDeviceEvent.__new__(iDeviceEvent)
    event._c_event = c_event
    (<object>user_data)(event)

def event_subscribe(object callback):
    cdef iDeviceError err = iDeviceError(idevice_event_subscribe(idevice_event_cb, <void*>callback))
    if err: raise err

def event_unsubscribe():
    cdef iDeviceError err = iDeviceError(idevice_event_unsubscribe())
    if err: raise err

def get_device_list():
    cdef:
        char** devices = NULL
        int count
        list result
        bytes device
        iDeviceError err = iDeviceError(idevice_get_device_list(&devices, &count))

    if err:
        if devices != NULL:
            idevice_device_list_free(devices)
        raise err

    result = []
    for i from 0 <= i < count:
        device = devices[i]
        result.append(device)

    err = iDeviceError(idevice_device_list_free(devices))
    if err: raise err
    return result

cdef class iDeviceConnection(Base):
    def __init__(self, *args, **kwargs):
        raise TypeError("iDeviceConnection cannot be instantiated.  Please use iDevice.connect()")

    cpdef bytes receive_timeout(self, uint32_t max_len, unsigned int timeout):
        cdef:
            uint32_t bytes_received
            char* c_data = <char *>malloc(max_len)
            bytes result

        try:
            self.handle_error(idevice_connection_receive_timeout(self._c_connection, c_data, max_len, &bytes_received, timeout))
            result = c_data[:bytes_received]
            return result
        except BaseError, e:
            raise
        finally:
            free(c_data)

    cpdef bytes receive(self, max_len):
        cdef:
            uint32_t bytes_received
            char* c_data = <char *>malloc(max_len)
            bytes result

        try:
            self.handle_error(idevice_connection_receive(self._c_connection, c_data, max_len, &bytes_received))
            result = c_data[:bytes_received]
            return result
        except BaseError, e:
            raise
        finally:
            free(c_data)

    cpdef disconnect(self):
        cdef idevice_error_t err
        err = idevice_disconnect(self._c_connection)
        self.handle_error(err)

    cdef BaseError _error(self, int16_t ret):
        return iDeviceError(ret)

from libc.stdlib cimport *

cdef class iDevice(Base):
    def __cinit__(self, object udid=None, *args, **kwargs):
        cdef char* c_udid = NULL
        if isinstance(udid, basestring):
            c_udid = <bytes>udid
        elif udid is not None:
            raise TypeError("iDevice's constructor takes a string or None as the udid argument")
        self.handle_error(idevice_new(&self._c_dev, c_udid))

    def __dealloc__(self):
        if self._c_dev is not NULL:
            self.handle_error(idevice_free(self._c_dev))

    cdef BaseError _error(self, int16_t ret):
        return iDeviceError(ret)

    cpdef iDeviceConnection connect(self, uint16_t port):
        cdef:
            idevice_error_t err
            idevice_connection_t c_conn = NULL
            iDeviceConnection conn
        err = idevice_connect(self._c_dev, port, &c_conn)
        try:
            self.handle_error(err)

            conn = iDeviceConnection.__new__(iDeviceConnection)
            conn._c_connection = c_conn

            return conn
        except Exception, e:
            if c_conn != NULL:
                idevice_disconnect(c_conn)

    property udid:
        def __get__(self):
            cdef:
                char* udid
                idevice_error_t err
            err = idevice_get_udid(self._c_dev, &udid)
            try:
                self.handle_error(err)
                return udid
            except Exception, e:
                if udid != NULL:
                    free(udid)
    property handle:
        def __get__(self):
            cdef uint32_t handle
            self.handle_error(idevice_get_handle(self._c_dev, &handle))
            return handle

cdef extern from *:
    ctypedef char* const_char_ptr "const char*"

cdef class BaseService(Base):
    __service_name__ = None

cdef class PropertyListService(BaseService):
    cpdef send(self, plist.Node node):
        self.handle_error(self._send(node._c_node))

    cpdef object receive(self):
        cdef:
            plist.plist_t c_node = NULL
            int16_t err
        err = self._receive(&c_node)
        try:
            self.handle_error(err)

            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cpdef object receive_with_timeout(self, int timeout_ms):
        cdef:
            plist.plist_t c_node = NULL
            int16_t err
        err = self._receive_with_timeout(&c_node, timeout_ms)
        try:
            self.handle_error(err)

            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cdef int16_t _send(self, plist.plist_t node):
        raise NotImplementedError("send is not implemented")

    cdef int16_t _receive(self, plist.plist_t* c_node):
        raise NotImplementedError("receive is not implemented")

    cdef int16_t _receive_with_timeout(self, plist.plist_t* c_node, int timeout_ms):
        raise NotImplementedError("receive_with_timeout is not implemented")

cdef class DeviceLinkService(PropertyListService):
    pass

include "lockdown.pxi"
include "mobilesync.pxi"
include "notification_proxy.pxi"
include "sbservices.pxi"
include "mobilebackup.pxi"
include "mobilebackup2.pxi"
include "afc.pxi"
include "file_relay.pxi"
include "screenshotr.pxi"
include "installation_proxy.pxi"
include "mobile_image_mounter.pxi"
include "webinspector.pxi"
include "heartbeat.pxi"
include "diagnostics_relay.pxi"
include "misagent.pxi"
include "house_arrest.pxi"
include "restore.pxi"
include "debugserver.pxi"
