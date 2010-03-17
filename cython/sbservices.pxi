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

    def __cinit__(self, iDevice device not None, LockdownClient lockdown=None, *args, **kwargs):
        cdef iDevice dev = device
        cdef LockdownClient lckd
        if lockdown is None:
            lckd = LockdownClient(dev)
        else:
            lckd = lockdown
        port = lockdown.start_service("com.apple.springboardservices")
        err = SpringboardServicesError(sbservices_client_new(dev._c_dev, port, &(self._c_client)))
        if err: raise err
    
    def __dealloc__(self):
        if self._c_client is not NULL:
            err = SpringboardServicesError(sbservices_client_free(self._c_client))
            if err: raise err

    property icon_state:
        def __get__(self):
            cdef plist.plist_t c_node = NULL
            cdef plist.Node node
            cdef SpringboardServicesError err = \
                SpringboardServicesError(sbservices_get_icon_state(self._c_client, &c_node))
            if err: raise err
            node = plist.plist_t_to_node(c_node)
            return node
        def __set__(self, plist.Node newstate not None):
            cdef plist.Node node = newstate
            cdef SpringboardServicesError err = \
                SpringboardServicesError(sbservices_set_icon_state(self._c_client, node._c_node))
            if err: raise err

    cpdef bytes get_pngdata(self, bytes bundleId):
        cdef bytes result
        cdef char* pngdata = NULL
        cdef uint64_t pngsize
        cdef SpringboardServicesError err = \
            SpringboardServicesError(sbservices_get_icon_pngdata(self._c_client, bundleId, &pngdata, &pngsize))
        if err: raise err
        result = pngdata[:pngsize]
        return result
