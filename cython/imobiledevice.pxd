cimport plist

from libc.stdint cimport *

cdef extern from "pyerrors.h":
    ctypedef class __builtin__.Exception [object PyBaseExceptionObject]:
        pass

cdef class BaseError(Exception):
    cdef dict _lookup_table
    cdef int16_t _c_errcode

cdef class Base:
    cdef inline int handle_error(self, int16_t ret) except -1
    cdef BaseError _error(self, int16_t ret)

cdef class iDeviceError(BaseError): pass

cdef extern from "libimobiledevice/libimobiledevice.h":
    cdef struct idevice_private:
        pass
    ctypedef idevice_private* idevice_t
    cdef struct idevice_connection_private:
        pass
    ctypedef idevice_connection_private* idevice_connection_t
    cdef enum idevice_event_type:
        IDEVICE_DEVICE_ADD = 1,
        IDEVICE_DEVICE_REMOVE
    ctypedef struct idevice_event_t:
        idevice_event_type event
        char *udid
        int conn_type
    ctypedef idevice_event_t* const_idevice_event_t "const idevice_event_t*"

cdef class iDeviceEvent:
    cdef const_idevice_event_t _c_event

cdef class iDeviceConnection(Base):
    cdef idevice_connection_t _c_connection

    cpdef bytes receive_timeout(self, uint32_t max_len, unsigned int timeout)
    cpdef bytes receive(self, max_len)
    cpdef disconnect(self)

cdef class iDevice(Base):
    cdef idevice_t _c_dev

    cpdef iDeviceConnection connect(self, uint16_t port)

cdef class BaseService(Base):
    pass

cdef class PropertyListService(BaseService):
    cpdef send(self, plist.Node node)
    cpdef object receive(self)
    cpdef object receive_with_timeout(self, int timeout_ms)
    cdef int16_t _send(self, plist.plist_t node)
    cdef int16_t _receive(self, plist.plist_t* c_node)
    cdef int16_t _receive_with_timeout(self, plist.plist_t* c_node, int timeout_ms)

cdef extern from "libimobiledevice/lockdown.h":
    cdef struct lockdownd_client_private:
        pass
    ctypedef lockdownd_client_private *lockdownd_client_t
    cdef struct lockdownd_pair_record:
        char *device_certificate
        char *host_certificate
        char *host_id
        char *root_certificate
    ctypedef lockdownd_pair_record *lockdownd_pair_record_t
    cdef struct lockdownd_service_descriptor:
        uint16_t port
        uint8_t ssl_enabled
    ctypedef lockdownd_service_descriptor *lockdownd_service_descriptor_t

cdef class LockdownError(BaseError): pass

cdef class LockdownPairRecord:
    cdef lockdownd_pair_record_t _c_record

cdef class LockdownServiceDescriptor(Base):
    cdef lockdownd_service_descriptor_t _c_service_descriptor

cdef class LockdownClient(PropertyListService):
    cdef lockdownd_client_t _c_client
    cdef readonly iDevice device

    cpdef bytes query_type(self)
    cpdef plist.Node get_value(self, bytes domain=*, bytes key=*)
    cpdef set_value(self, bytes domain, bytes key, object value)
    cpdef remove_value(self, bytes domain, bytes key)
    cpdef object start_service(self, object service)
    cpdef object get_service_client(self, object service_class)
    cpdef tuple start_session(self, bytes host_id)
    cpdef stop_session(self, bytes session_id)
    cpdef pair(self, object pair_record=*)
    cpdef validate_pair(self, object pair_record=*)
    cpdef unpair(self, object pair_record=*)
    cpdef activate(self, plist.Node activation_record)
    cpdef deactivate(self)
    cpdef enter_recovery(self)
    cpdef goodbye(self)
    cpdef list get_sync_data_classes(self)
