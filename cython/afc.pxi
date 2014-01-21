cdef extern from "libimobiledevice/afc.h":
    cdef struct afc_client_private:
        pass
    ctypedef afc_client_private *afc_client_t
    ctypedef enum afc_error_t:
        AFC_E_SUCCESS = 0
        AFC_E_UNKNOWN_ERROR = 1
        AFC_E_OP_HEADER_INVALID = 2
        AFC_E_NO_RESOURCES = 3
        AFC_E_READ_ERROR = 4
        AFC_E_WRITE_ERROR = 5
        AFC_E_UNKNOWN_PACKET_TYPE = 6
        AFC_E_INVALID_ARG = 7
        AFC_E_OBJECT_NOT_FOUND = 8
        AFC_E_OBJECT_IS_DIR = 9
        AFC_E_PERM_DENIED = 10
        AFC_E_SERVICE_NOT_CONNECTED = 11
        AFC_E_OP_TIMEOUT = 12
        AFC_E_TOO_MUCH_DATA = 13
        AFC_E_END_OF_DATA = 14
        AFC_E_OP_NOT_SUPPORTED = 15
        AFC_E_OBJECT_EXISTS = 16
        AFC_E_OBJECT_BUSY = 17
        AFC_E_NO_SPACE_LEFT = 18
        AFC_E_OP_WOULD_BLOCK = 19
        AFC_E_IO_ERROR = 20
        AFC_E_OP_INTERRUPTED = 21
        AFC_E_OP_IN_PROGRESS = 22
        AFC_E_INTERNAL_ERROR = 23
        AFC_E_MUX_ERROR = 30
        AFC_E_NO_MEM = 31
        AFC_E_NOT_ENOUGH_DATA = 32
        AFC_E_DIR_NOT_EMPTY = 33
    ctypedef enum afc_file_mode_t:
        AFC_FOPEN_RDONLY   = 0x00000001
        AFC_FOPEN_RW       = 0x00000002
        AFC_FOPEN_WRONLY   = 0x00000003
        AFC_FOPEN_WR       = 0x00000004
        AFC_FOPEN_APPEND   = 0x00000005
        AFC_FOPEN_RDAPPEND = 0x00000006
    ctypedef enum afc_link_type_t:
        AFC_HARDLINK = 1
        AFC_SYMLINK = 2
    ctypedef enum afc_lock_op_t:
        AFC_LOCK_SH = 1 | 4
        AFC_LOCK_EX = 2 | 4
        AFC_LOCK_UN = 8 | 4

    afc_error_t afc_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, afc_client_t *client)
    afc_error_t afc_client_free(afc_client_t client)
    afc_error_t afc_get_device_info(afc_client_t client, char ***infos)
    afc_error_t afc_read_directory(afc_client_t client, char *dir, char ***list)
    afc_error_t afc_get_file_info(afc_client_t client, char *filename, char ***infolist)
    afc_error_t afc_remove_path(afc_client_t client, char *path)
    afc_error_t afc_rename_path(afc_client_t client, char *f, char *to)
    afc_error_t afc_make_directory(afc_client_t client, char *dir)
    afc_error_t afc_truncate(afc_client_t client, char *path, uint64_t newsize)
    afc_error_t afc_make_link(afc_client_t client, afc_link_type_t linktype, char *target, char *linkname)
    afc_error_t afc_set_file_time(afc_client_t client, char *path, uint64_t mtime)

    afc_error_t afc_file_open(afc_client_t client, char *filename, afc_file_mode_t file_mode, uint64_t *handle)
    afc_error_t afc_file_close(afc_client_t client, uint64_t handle)
    afc_error_t afc_file_lock(afc_client_t client, uint64_t handle, afc_lock_op_t operation)
    afc_error_t afc_file_read(afc_client_t client, uint64_t handle, char *data, uint32_t length, uint32_t *bytes_read)
    afc_error_t afc_file_write(afc_client_t client, uint64_t handle, char *data, uint32_t length, uint32_t *bytes_written)
    afc_error_t afc_file_seek(afc_client_t client, uint64_t handle, int64_t offset, int whence)
    afc_error_t afc_file_tell(afc_client_t client, uint64_t handle, uint64_t *position)
    afc_error_t afc_file_truncate(afc_client_t client, uint64_t handle, uint64_t newsize)

LOCK_SH = AFC_LOCK_SH
LOCK_EX = AFC_LOCK_EX
LOCK_UN = AFC_LOCK_UN

cdef class AfcError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            AFC_E_SUCCESS: "Success",
            AFC_E_UNKNOWN_ERROR: "Unknown error",
            AFC_E_OP_HEADER_INVALID: "OP header invalid",
            AFC_E_NO_RESOURCES: "No resources",
            AFC_E_READ_ERROR: "Read error",
            AFC_E_WRITE_ERROR: "Write error",
            AFC_E_UNKNOWN_PACKET_TYPE: "Unknown packet type",
            AFC_E_INVALID_ARG: "Invalid argument",
            AFC_E_OBJECT_NOT_FOUND: "Object not found",
            AFC_E_OBJECT_IS_DIR: "Object is directory",
            AFC_E_PERM_DENIED: "Permission denied",
            AFC_E_SERVICE_NOT_CONNECTED: "Service not connected",
            AFC_E_OP_TIMEOUT: "OP timeout",
            AFC_E_TOO_MUCH_DATA: "Too much data",
            AFC_E_END_OF_DATA: "End of data",
            AFC_E_OP_NOT_SUPPORTED: "OP not supported",
            AFC_E_OBJECT_EXISTS: "Object exists",
            AFC_E_OBJECT_BUSY: "Object busy",
            AFC_E_NO_SPACE_LEFT: "No space left",
            AFC_E_OP_WOULD_BLOCK: "OP would block",
            AFC_E_IO_ERROR: "IO error",
            AFC_E_OP_INTERRUPTED: "OP interrupted",
            AFC_E_OP_IN_PROGRESS: "OP in progress",
            AFC_E_INTERNAL_ERROR: "Internal error",
            AFC_E_MUX_ERROR: "MUX error",
            AFC_E_NO_MEM: "No memory",
            AFC_E_NOT_ENOUGH_DATA: "Not enough data",
            AFC_E_DIR_NOT_EMPTY: "Directory not empty"
        }
        BaseError.__init__(self, *args, **kwargs)

# forward declaration of AfcClient
cdef class AfcClient(BaseService)

cdef class AfcFile(Base):
    cdef uint64_t _c_handle
    cdef AfcClient _client
    cdef bytes _filename

    def __init__(self, *args, **kwargs):
        raise TypeError("AfcFile cannot be instantiated")

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    cpdef close(self):
        self.handle_error(afc_file_close(self._client._c_client, self._c_handle))

    cpdef lock(self, int operation):
        self.handle_error(afc_file_lock(self._client._c_client, self._c_handle, <afc_lock_op_t>operation))

    cpdef seek(self, int64_t offset, int whence):
        self.handle_error(afc_file_seek(self._client._c_client, self._c_handle, offset, whence))

    cpdef uint64_t tell(self):
        cdef uint64_t position
        self.handle_error(afc_file_tell(self._client._c_client, self._c_handle, &position))
        return position

    cpdef truncate(self, uint64_t newsize):
        self.handle_error(afc_file_truncate(self._client._c_client, self._c_handle, newsize))

    cpdef bytes read(self, uint32_t size):
        cdef:
            uint32_t bytes_read
            char* c_data = <char *>malloc(size)
            bytes result
        try:
            self.handle_error(afc_file_read(self._client._c_client, self._c_handle, c_data, size, &bytes_read))
            result = c_data[:bytes_read]
            return result
        except BaseError, e:
            raise
        finally:
            free(c_data)

    cpdef uint32_t write(self, bytes data):
        cdef:
            uint32_t bytes_written
            char* c_data = data
        try:
            self.handle_error(afc_file_write(self._client._c_client, self._c_handle, c_data, len(data), &bytes_written))
        except BaseError, e:
            raise

        return bytes_written

    cdef inline BaseError _error(self, int16_t ret):
        return AfcError(ret)

cdef class AfcClient(BaseService):
    __service_name__ = "com.apple.afc"
    cdef afc_client_t _c_client

    def __cinit__(self, iDevice device = None, LockdownServiceDescriptor descriptor = None, *args, **kwargs):
        if (device is not None and descriptor is not None):
            self.handle_error(afc_client_new(device._c_dev, descriptor._c_service_descriptor, &(self._c_client)))
    
    def __dealloc__(self):
        cdef afc_error_t err
        if self._c_client is not NULL:
            err = afc_client_free(self._c_client)
            self.handle_error(err)

    cdef BaseError _error(self, int16_t ret):
        return AfcError(ret)

    cpdef list get_device_info(self):
        cdef:
            afc_error_t err
            char** infos = NULL
            bytes info
            int i = 0
            list result = []
        err = afc_get_device_info(self._c_client, &infos)
        try:
            self.handle_error(err)
        except BaseError, e:
            raise
        finally:
            if infos != NULL:
                while infos[i]:
                    info = infos[i]
                    result.append(info)
                    free(infos[i])
                    i = i + 1
                free(infos)

        return result

    cpdef list read_directory(self, bytes directory):
        cdef:
            afc_error_t err
            char** dir_list = NULL
            bytes f
            int i = 0
            list result = []
        err = afc_read_directory(self._c_client, directory, &dir_list)
        try:
            self.handle_error(err)
        except BaseError, e:
            raise
        finally:
            if dir_list != NULL:
                while dir_list[i]:
                    f = dir_list[i]
                    result.append(f)
                    free(dir_list[i])
                    i = i + 1
                free(dir_list)

        return result

    cpdef AfcFile open(self, bytes filename, bytes mode=b'r'):
        cdef:
            afc_file_mode_t c_mode
            uint64_t handle
            AfcFile f
        if mode == <bytes>'r':
            c_mode = AFC_FOPEN_RDONLY
        elif mode == <bytes>'r+':
            c_mode = AFC_FOPEN_RW
        elif mode == <bytes>'w':
            c_mode = AFC_FOPEN_WRONLY
        elif mode == <bytes>'w+':
            c_mode = AFC_FOPEN_WR
        elif mode == <bytes>'a':
            c_mode = AFC_FOPEN_APPEND
        elif mode == <bytes>'a+':
            c_mode = AFC_FOPEN_RDAPPEND
        else:
            raise ValueError("mode string must be 'r', 'r+', 'w', 'w+', 'a', or 'a+'")

        self.handle_error(afc_file_open(self._c_client, filename, c_mode, &handle))
        f = AfcFile.__new__(AfcFile)
        f._c_handle = handle
        f._client = self
        f._filename = filename

        return f

    cpdef list get_file_info(self, bytes path):
        cdef:
            list result = []
            char** c_result = NULL
            int i = 0
            bytes info
        try:
            self.handle_error(afc_get_file_info(self._c_client, path, &c_result))
        except BaseError, e:
            raise
        finally:
            if c_result != NULL:
                while c_result[i]:
                    info = c_result[i]
                    result.append(info)
                    free(c_result[i])
                    i = i + 1
                free(c_result)

        return result

    cpdef remove_path(self, bytes path):
        self.handle_error(afc_remove_path(self._c_client, path))

    cpdef rename_path(self, bytes f, bytes t):
        self.handle_error(afc_rename_path(self._c_client, f, t))

    cpdef make_directory(self, bytes d):
        self.handle_error(afc_make_directory(self._c_client, d))

    cpdef truncate(self, bytes path, uint64_t newsize):
        self.handle_error(afc_truncate(self._c_client, path, newsize))

    cpdef link(self, bytes source, bytes link_name):
        self.handle_error(afc_make_link(self._c_client, AFC_HARDLINK, source, link_name))

    cpdef symlink(self, bytes source, bytes link_name):
        self.handle_error(afc_make_link(self._c_client, AFC_SYMLINK, source, link_name))

    cpdef set_file_time(self, bytes path, uint64_t mtime):
        self.handle_error(afc_set_file_time(self._c_client, path, mtime))

cdef class Afc2Client(AfcClient):
    __service_name__ = "com.apple.afc2"

    cpdef AfcFile open(self, bytes filename, bytes mode=b'r'):
        cdef:
            afc_file_mode_t c_mode
            uint64_t handle
            AfcFile f
        if mode == <bytes>'r':
            c_mode = AFC_FOPEN_RDONLY
        elif mode == <bytes>'r+':
            c_mode = AFC_FOPEN_RW
        elif mode == <bytes>'w':
            c_mode = AFC_FOPEN_WRONLY
        elif mode == <bytes>'w+':
            c_mode = AFC_FOPEN_WR
        elif mode == <bytes>'a':
            c_mode = AFC_FOPEN_APPEND
        elif mode == <bytes>'a+':
            c_mode = AFC_FOPEN_RDAPPEND
        else:
            raise ValueError("mode string must be 'r', 'r+', 'w', 'w+', 'a', or 'a+'")

        self.handle_error(afc_file_open(self._c_client, filename, c_mode, &handle))
        f = AfcFile.__new__(AfcFile)
        f._c_handle = handle
        f._client = <AfcClient>self
        f._filename = filename

        return f

