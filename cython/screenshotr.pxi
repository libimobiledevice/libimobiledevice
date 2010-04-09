cdef extern from "libimobiledevice/screenshotr.h":
    cdef struct screenshotr_client_private:
        pass
    ctypedef screenshotr_client_private *screenshotr_client_t

    ctypedef enum screenshotr_error_t:
        SCREENSHOTR_E_SUCCESS = 0
        SCREENSHOTR_E_INVALID_ARG = -1
        SCREENSHOTR_E_PLIST_ERROR = -2
        SCREENSHOTR_E_MUX_ERROR = -3
        SCREENSHOTR_E_BAD_VERSION = -4
        SCREENSHOTR_E_UNKNOWN_ERROR = -256

    screenshotr_error_t screenshotr_client_new(idevice_t device, uint16_t port, screenshotr_client_t * client)
    screenshotr_error_t screenshotr_client_free(screenshotr_client_t client)
    screenshotr_error_t screenshotr_take_screenshot(screenshotr_client_t client, char **imgdata, uint64_t *imgsize)

cdef class ScreenshotrError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            SCREENSHOTR_E_SUCCESS: "Success",
            SCREENSHOTR_E_INVALID_ARG: "Invalid argument",
            SCREENSHOTR_E_PLIST_ERROR: "Property list error",
            SCREENSHOTR_E_MUX_ERROR: "MUX error",
            SCREENSHOTR_E_BAD_VERSION: "Bad version",
            SCREENSHOTR_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class ScreenshotrClient(Base):
    __service_name__ = "com.apple.mobile.screenshotr"
    cdef screenshotr_client_t _c_client

    def __cinit__(self, iDevice device not None, int port, *args, **kwargs):
        cdef:
            iDevice dev = device
            screenshotr_error_t err
        err = screenshotr_client_new(dev._c_dev, port, &self._c_client)
        self.handle_error(err)

    def __dealloc__(self):
        cdef screenshotr_error_t err
        if self._c_client is not NULL:
            err = screenshotr_client_free(self._c_client)
            self.handle_error(err)

    cpdef bytes take_screenshot(self):
        cdef:
            char* c_data
            uint64_t data_size
            bytes result
            screenshotr_error_t err

        err = screenshotr_take_screenshot(self._c_client, &c_data, &data_size)
        self.handle_error(err)
        result = c_data[:data_size]
        return result

    cdef inline BaseError _error(self, int16_t ret):
        return ScreenshotrError(ret)
