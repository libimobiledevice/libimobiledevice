cdef extern from "libimobiledevice/debugserver.h":
    cdef struct debugserver_client_private:
        pass
    ctypedef debugserver_client_private *debugserver_client_t
    cdef struct debugserver_command_private:
        pass
    ctypedef debugserver_command_private *debugserver_command_t
    ctypedef enum debugserver_error_t:
        DEBUGSERVER_E_SUCCESS = 0
        DEBUGSERVER_E_INVALID_ARG = -1
        DEBUGSERVER_E_MUX_ERROR = -2
        DEBUGSERVER_E_SSL_ERROR = -3
        DEBUGSERVER_E_RESPONSE_ERROR = -4
        DEBUGSERVER_E_UNKNOWN_ERROR = -256

    debugserver_error_t debugserver_client_new(idevice_t device, lockdownd_service_descriptor_t service, debugserver_client_t * client)
    debugserver_error_t debugserver_client_free(debugserver_client_t client)

    debugserver_error_t debugserver_client_send(debugserver_client_t client, const char* data, uint32_t size, uint32_t *sent)
    debugserver_error_t debugserver_client_send_command(debugserver_client_t client, debugserver_command_t command, char** response)
    debugserver_error_t debugserver_client_receive(debugserver_client_t client, char *data, uint32_t size, uint32_t *received)
    debugserver_error_t debugserver_client_receive_with_timeout(debugserver_client_t client, char *data, uint32_t size, uint32_t *received, unsigned int timeout)
    debugserver_error_t debugserver_client_receive_response(debugserver_client_t client, char** response)
    debugserver_error_t debugserver_client_set_argv(debugserver_client_t client, int argc, char* argv[], char** response)
    debugserver_error_t debugserver_client_set_environment_hex_encoded(debugserver_client_t client, const char* env, char** response)

    debugserver_error_t debugserver_command_new(const char* name, int argc, const char* argv[], debugserver_command_t* command)
    debugserver_error_t debugserver_command_free(debugserver_command_t command)
    void debugserver_encode_string(const char* buffer, char** encoded_buffer, uint32_t* encoded_length)
    void debugserver_decode_string(const char *encoded_buffer, size_t encoded_length, char** buffer)


cdef class DebugServerError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            DEBUGSERVER_E_SUCCESS: "Success",
            DEBUGSERVER_E_INVALID_ARG: "Invalid argument",
            DEBUGSERVER_E_MUX_ERROR: "MUX error",
            DEBUGSERVER_E_SSL_ERROR: "SSL error",
            DEBUGSERVER_E_RESPONSE_ERROR: "Response error",
            DEBUGSERVER_E_UNKNOWN_ERROR: "Unknown error",
        }
        BaseError.__init__(self, *args, **kwargs)


# from http://stackoverflow.com/a/17511714
from cpython.string cimport PyString_AsString
cdef char ** to_cstring_array(list_str):
    if not list_str:
        return NULL
    cdef char **ret = <char **>malloc(len(list_str) * sizeof(char *))
    for i in xrange(len(list_str)):
        ret[i] = PyString_AsString(list_str[i])
    return ret


cdef class DebugServerCommand(Base):
    cdef debugserver_command_t _c_command

    def __init__(self, bytes name, int argc = 0, argv = None, *args, **kwargs):
        cdef:
            char* c_name = name
            char** c_argv = to_cstring_array(argv)

        try:
            self.handle_error(debugserver_command_new(c_name, argc, c_argv, &self._c_command))
        except BaseError, e:
            raise
        finally:
            free(c_argv)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.free()

    cdef free(self):
        cdef debugserver_error_t err
        if self._c_command is not NULL:
            err = debugserver_command_free(self._c_command)
            self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return DebugServerError(ret)


cdef class DebugServerClient(BaseService):
    __service_name__ = "com.apple.debugserver"
    cdef debugserver_client_t _c_client

    def __cinit__(self, iDevice device = None, LockdownServiceDescriptor descriptor = None, *args, **kwargs):
        if (device is not None and descriptor is not None):
            self.handle_error(debugserver_client_new(device._c_dev, descriptor._c_service_descriptor, &(self._c_client)))
    
    def __dealloc__(self):
        cdef debugserver_error_t err
        if self._c_client is not NULL:
            err = debugserver_client_free(self._c_client)
            self.handle_error(err)

    cdef BaseError _error(self, int16_t ret):
        return DebugServerError(ret)

    cpdef uint32_t send(self, bytes data):
        cdef:
            uint32_t bytes_send
            char* c_data = data
        try:
            self.handle_error(debugserver_client_send(self._c_client, c_data, len(data), &bytes_send))
        except BaseError, e:
            raise

        return bytes_send

    cpdef bytes send_command(self, DebugServerCommand command):
        cdef:
            char* c_response = NULL
            bytes result

        try:
            self.handle_error(debugserver_client_send_command(self._c_client, command._c_command, &c_response))
            if c_response:
                result = c_response
                return result
            else:
                return None
        except BaseError, e:
            raise
        finally:
            free(c_response)

    cpdef bytes receive(self, uint32_t size):
        cdef:
            uint32_t bytes_received
            char* c_data = <char *>malloc(size)
            bytes result

        try:
            self.handle_error(debugserver_client_receive(self._c_client, c_data, size, &bytes_received))
            result = c_data[:bytes_received]
            return result
        except BaseError, e:
            raise
        finally:
            free(c_data)

    cpdef bytes receive_with_timeout(self, uint32_t size, unsigned int timeout):
        cdef:
            uint32_t bytes_received
            char* c_data = <char *>malloc(size)
            bytes result

        try:
            self.handle_error(debugserver_client_receive_with_timeout(self._c_client, c_data, size, &bytes_received, timeout))
            result = c_data[:bytes_received]
            return result
        except BaseError, e:
            raise
        finally:
            free(c_data)

    cpdef bytes receive_response(self):
        cdef:
            char* c_response = NULL
            bytes result

        try:
            self.handle_error(debugserver_client_receive_response(self._c_client, &c_response))
            if c_response:
                result = c_response
                return result
            else:
                return None
        except BaseError, e:
            raise
        finally:
            free(c_response)

    cpdef bytes set_argv(self, int argc, argv):
        cdef:
            char** c_argv = to_cstring_array(argv)
            char* c_response = NULL
            bytes result

        try:
            self.handle_error(debugserver_client_set_argv(self._c_client, argc, c_argv, &c_response))
            if c_response:
                result = c_response
                return result
            else:
                return None
        except BaseError, e:
            raise
        finally:
            free(c_argv)
            free(c_response)

    cpdef bytes set_environment_hex_encoded(self, bytes env):
        cdef:
            char* c_env = env
            char* c_response = NULL
            bytes result

        try:
            self.handle_error(debugserver_client_set_environment_hex_encoded(self._c_client, c_env, &c_response))
            if c_response:
                result = c_response
                return result
            else:
                return None
        except BaseError, e:
            raise
        finally:
            free(c_response)

    cpdef bytes encode_string(self, bytes buffer):
        cdef:
            char *c_buffer = buffer
            uint32_t encoded_length = len(c_buffer) * 2 + 0x3 + 1
            char* c_encoded_buffer = <char *>malloc(encoded_length)
            bytes result

        try:
            debugserver_encode_string(c_buffer, &c_encoded_buffer, &encoded_length)
            result = c_encoded_buffer[:encoded_length]
            return result
        except BaseError, e:
            raise
        finally:
            free(c_encoded_buffer)

    cpdef bytes decode_string(self, bytes encoded_buffer):
        cdef:
            char* c_encoded_buffer = encoded_buffer
            uint32_t encoded_length = len(c_encoded_buffer)
            char *c_buffer = <char *>malloc(encoded_length)
            bytes result

        try:
            debugserver_decode_string(c_encoded_buffer, encoded_length, &c_buffer)
            result = c_buffer
            return result
        except BaseError, e:
            raise
        finally:
            free(c_buffer)
