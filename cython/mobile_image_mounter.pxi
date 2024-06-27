cdef extern from "libimobiledevice/mobile_image_mounter.h":
    cdef struct mobile_image_mounter_client_private:
        pass
    ctypedef mobile_image_mounter_client_private *mobile_image_mounter_client_t

    ctypedef enum mobile_image_mounter_error_t:
        MOBILE_IMAGE_MOUNTER_E_SUCCESS = 0
        MOBILE_IMAGE_MOUNTER_E_INVALID_ARG = -1
        MOBILE_IMAGE_MOUNTER_E_PLIST_ERROR = -2
        MOBILE_IMAGE_MOUNTER_E_CONN_FAILED = -3
        MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR = -256

    mobile_image_mounter_error_t mobile_image_mounter_new(idevice_t device, lockdownd_service_descriptor_t descriptor, mobile_image_mounter_client_t *client)
    mobile_image_mounter_error_t mobile_image_mounter_free(mobile_image_mounter_client_t client)
    mobile_image_mounter_error_t mobile_image_mounter_lookup_image(mobile_image_mounter_client_t client, char *image_type, plist.plist_t *result)
    mobile_image_mounter_error_t mobile_image_mounter_mount_image_with_options(mobile_image_mounter_client_t client, char *image_path, const unsigned char *signature, unsigned int signature_length, char *image_type, plist.plist_t options, plist.plist_t *result)
    mobile_image_mounter_error_t mobile_image_mounter_mount_image(mobile_image_mounter_client_t client, char *image_path, const unsigned char *signature, unsigned int signature_length, char *image_type, plist.plist_t *result)
    mobile_image_mounter_error_t mobile_image_mounter_unmount_image(mobile_image_mounter_client_t client, const char *mount_path);
    mobile_image_mounter_error_t mobile_image_mounter_hangup(mobile_image_mounter_client_t client)

cdef class MobileImageMounterError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            MOBILE_IMAGE_MOUNTER_E_SUCCESS: "Success",
            MOBILE_IMAGE_MOUNTER_E_INVALID_ARG: "Invalid argument",
            MOBILE_IMAGE_MOUNTER_E_PLIST_ERROR: "Property list error",
            MOBILE_IMAGE_MOUNTER_E_CONN_FAILED: "Connection failed",
            MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class MobileImageMounterClient(PropertyListService):
    __service_name__ = "com.apple.mobile.mobile_image_mounter"
    cdef mobile_image_mounter_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(mobile_image_mounter_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))
    
    def __dealloc__(self):
        cdef mobile_image_mounter_error_t err
        if self._c_client is not NULL:
            err = mobile_image_mounter_free(self._c_client)
            self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return MobileImageMounterError(ret)

    cpdef plist.Node lookup_image(self, bytes image_type):
        cdef:
            plist.plist_t c_node = NULL
            mobile_image_mounter_error_t err
        err = mobile_image_mounter_lookup_image(self._c_client, image_type, &c_node)

        try:
            self.handle_error(err)

            return plist.plist_t_to_node(c_node)
        except Exception, e:
            if c_node != NULL:
                plist.plist_free(c_node)

    cpdef plist.Node mount_image_with_options(self, bytes image_path, bytes signature, bytes image_type, object options):
        cdef:
            plist.Node n_options
            plist.plist_t c_options
            plist.plist_t c_result = NULL
            bint free_options = False
            plist.plist_t c_node = NULL
            mobile_image_mounter_error_t err
        if isinstance(options, plist.Dict):
            n_options = options
            c_options = n_options._c_node
        elif isinstance(options, dict):
            c_options = plist.native_to_plist_t(options)
            free_options = True
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        err = mobile_image_mounter_mount_image_with_options(self._c_client, image_path, signature, len(signature),
                                               image_type, c_options, &c_node)
        if free_options:
            plist.plist_free(c_options)
        try:
            self.handle_error(err)

            return plist.plist_t_to_node(c_node)
        except Exception, e:
            if c_node != NULL:
                plist.plist_free(c_node)

    cpdef plist.Node mount_image(self, bytes image_path, bytes signature, bytes image_type):
        cdef:
            plist.plist_t c_node = NULL
            mobile_image_mounter_error_t err
        err = mobile_image_mounter_mount_image(self._c_client, image_path, signature, len(signature),
                                               image_type, &c_node)

        try:
            self.handle_error(err)

            return plist.plist_t_to_node(c_node)
        except Exception, e:
            if c_node != NULL:
                plist.plist_free(c_node)

    cpdef unmount_image(self, bytes mount_path):
        cdef:
            mobile_image_mounter_error_t err
        err = mobile_image_mounter_unmount_image(self._c_client, mount_path)

        self.handle_error(err)

    cpdef hangup(self):
        cdef mobile_image_mounter_error_t err
        err = mobile_image_mounter_hangup(self._c_client)
        self.handle_error(err)
