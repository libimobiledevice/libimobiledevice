cimport plist

include "stdint.pxi"

cdef extern from "pyerrors.h":
    ctypedef class __builtin__.Exception [object PyBaseExceptionObject]:
        pass

cdef class BaseError(Exception):
    cdef dict _lookup_table
    cdef int16_t _c_errcode

cdef class Base:
    cdef inline int handle_error(self, int16_t ret) except -1
    cdef inline BaseError _error(self, int16_t ret)

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
        char *uuid
        int conn_type
    ctypedef idevice_event_t* const_idevice_event_t "const idevice_event_t*"

cdef class iDeviceEvent:
    cdef const_idevice_event_t _c_event

cdef class iDeviceConnection(Base):
    cdef idevice_connection_t _c_connection

    cpdef disconnect(self)

cdef class iDevice(Base):
    cdef idevice_t _c_dev

    cpdef iDeviceConnection connect(self, uint16_t port)

cdef class LockdownError(BaseError): pass

cdef extern from "libimobiledevice/lockdown.h":
    cdef struct lockdownd_client_private:
        pass
    ctypedef lockdownd_client_private *lockdownd_client_t

cdef class LockdownClient(Base):
    cdef lockdownd_client_t _c_client
    cpdef int start_service(self, service)
    cpdef goodbye(self)

cpdef set_debug_level(int level)
cpdef event_subscribe(object callback)
cpdef event_unsubscribe()
cpdef get_device_list()
