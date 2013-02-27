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
    mobile_image_mounter_error_t mobile_image_mounter_mount_image(mobile_image_mounter_client_t client, char *image_path, char *image_signature, uint16_t signature_length, char *image_type, plist.plist_t *result)
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

    cpdef plist.Node mount_image(self, bytes image_path, bytes image_signature, bytes image_type):
        cdef:
            plist.plist_t c_node = NULL
            mobile_image_mounter_error_t err
        err = mobile_image_mounter_mount_image(self._c_client, image_path, image_signature, len(image_signature),
                                               image_type, &c_node)

        try:
            self.handle_error(err)

            return plist.plist_t_to_node(c_node)
        except Exception, e:
            if c_node != NULL:
                plist.plist_free(c_node)

    cpdef hangup(self):
        cdef mobile_image_mounter_error_t err
        err = mobile_image_mounter_hangup(self._c_client)
        self.handle_error(err)
