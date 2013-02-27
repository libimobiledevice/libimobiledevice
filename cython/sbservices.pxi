cdef extern from "libimobiledevice/sbservices.h":
    cdef struct sbservices_client_private:
        pass
    ctypedef sbservices_client_private *sbservices_client_t
    ctypedef enum sbservices_error_t:
        SBSERVICES_E_SUCCESS = 0
        SBSERVICES_E_INVALID_ARG = -1
        SBSERVICES_E_PLIST_ERROR = -2
        SBSERVICES_E_CONN_FAILED = -3
        SBSERVICES_E_UNKNOWN_ERROR = -256
    sbservices_error_t sbservices_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, sbservices_client_t *client)
    sbservices_error_t sbservices_client_free(sbservices_client_t client)
    sbservices_error_t sbservices_get_icon_state(sbservices_client_t client, plist.plist_t *state, char *format_version)
    sbservices_error_t sbservices_set_icon_state(sbservices_client_t client, plist.plist_t newstate)
    sbservices_error_t sbservices_get_icon_pngdata(sbservices_client_t client, char *bundleId, char **pngdata, uint64_t *pngsize)

cdef class SpringboardServicesError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            SBSERVICES_E_SUCCESS: "Success",
            SBSERVICES_E_INVALID_ARG: "Invalid argument",
            SBSERVICES_E_PLIST_ERROR: "Property list error",
            SBSERVICES_E_CONN_FAILED: "Connection failed",
            SBSERVICES_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class SpringboardServicesClient(PropertyListService):
    __service_name__ = "com.apple.springboardservices"
    cdef sbservices_client_t _c_client
    cdef char* format_version

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(sbservices_client_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))
        self.format_version = "2"
    
    def __dealloc__(self):
        if self._c_client is not NULL:
            err = sbservices_client_free(self._c_client)
            self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return SpringboardServicesError(ret)

    property format_version:
        def __get__(self):
            return <bytes>self.format_version
        def __set__(self, char* newversion):
            self.format_version = newversion

    property icon_state:
        def __get__(self):
            cdef:
                plist.plist_t c_node = NULL
                sbservices_error_t err
            err = sbservices_get_icon_state(self._c_client, &c_node, self.format_version)
            try:
                self.handle_error(err)

                return plist.plist_t_to_node(c_node)
            except BaseError, e:
                if c_node != NULL:
                    plist.plist_free(c_node)
                raise
        def __set__(self, plist.Node newstate not None):
            self.handle_error(sbservices_set_icon_state(self._c_client, newstate._c_node))

    cpdef bytes get_pngdata(self, bytes bundleId):
        cdef:
            char* pngdata = NULL
            uint64_t pngsize
            sbservices_error_t err
        err = sbservices_get_icon_pngdata(self._c_client, bundleId, &pngdata, &pngsize)
        try:
            self.handle_error(err)

            return pngdata[:pngsize]
        except BaseError, e:
            free(pngdata)
            raise
