cimport plist

include "stdint.pxi"

cdef extern from "pyerrors.h":
    ctypedef class __builtin__.Exception [object PyBaseExceptionObject]:
        pass

cdef class BaseError(Exception):
    cdef dict _lookup_table
    cdef int16_t _c_errcode

cdef class iDeviceError(BaseError): pass

cdef extern from "libimobiledevice/libimobiledevice.h":
    cdef struct idevice_int:
        pass
    ctypedef idevice_int* idevice_t
    ctypedef int16_t idevice_error_t
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

cdef class iDevice:
    cdef idevice_t _c_dev

cdef class LockdownError(BaseError): pass

cdef extern from "libimobiledevice/lockdown.h":
    cdef struct lockdownd_client_int:
        pass
    ctypedef lockdownd_client_int *lockdownd_client_t

cdef class LockdownClient:
    cdef lockdownd_client_t _c_client
    cpdef int start_service(self, service)
    cpdef goodbye(self)

cpdef set_debug_level(int level)
cpdef event_subscribe(object callback)
cpdef event_unsubscribe()
cpdef get_device_list()
