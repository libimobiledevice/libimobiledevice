cdef extern from "libimobiledevice/house_arrest.h":
    cdef struct house_arrest_client_private:
        pass
    ctypedef house_arrest_client_private *house_arrest_client_t

    ctypedef enum house_arrest_error_t:
        HOUSE_ARREST_E_SUCCESS = 0
        HOUSE_ARREST_E_INVALID_ARG = -1
        HOUSE_ARREST_E_PLIST_ERROR = -2
        HOUSE_ARREST_E_CONN_FAILED = -3
        HOUSE_ARREST_E_INVALID_MODE = -4
        HOUSE_ARREST_E_UNKNOWN_ERROR = -256

    house_arrest_error_t house_arrest_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, house_arrest_client_t * client)
    house_arrest_error_t house_arrest_client_free(house_arrest_client_t client)

    house_arrest_error_t house_arrest_send_request(house_arrest_client_t client, plist.plist_t dict)
    house_arrest_error_t house_arrest_send_command(house_arrest_client_t client, char *command, char *appid)
    house_arrest_error_t house_arrest_get_result(house_arrest_client_t client, plist.plist_t *dict)

    afc_error_t afc_client_new_from_house_arrest_client(house_arrest_client_t client, afc_client_t *afc_client)

cdef class HouseArrestError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            HOUSE_ARREST_E_SUCCESS: "Success",
            HOUSE_ARREST_E_INVALID_ARG: "Invalid argument",
            HOUSE_ARREST_E_PLIST_ERROR: "Property list error",
            HOUSE_ARREST_E_CONN_FAILED: "Connection failed",
            HOUSE_ARREST_E_INVALID_MODE: "Invalid mode",
            HOUSE_ARREST_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class HouseArrestClient(PropertyListService):
    __service_name__ = "com.apple.mobile.house_arrest"
    cdef house_arrest_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        self.handle_error(house_arrest_client_new(device._c_dev, descriptor._c_service_descriptor, &self._c_client))

    def __dealloc__(self):
        cdef house_arrest_error_t err
        if self._c_client is not NULL:
            err = house_arrest_client_free(self._c_client)
            self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return HouseArrestError(ret)

    cpdef send_request(self, plist.Node message):
        self.handle_error(house_arrest_send_request(self._c_client, message._c_node))

    cpdef send_command(self, bytes command, bytes appid):
        self.handle_error(house_arrest_send_command(self._c_client, command, appid))

    cpdef plist.Node get_result(self):
        cdef:
            plist.plist_t c_node = NULL
            house_arrest_error_t err
        err = house_arrest_get_result(self._c_client, &c_node)
        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

    cpdef AfcClient to_afc_client(self):
        cdef:
            afc_client_t c_afc_client = NULL
            AfcClient result
            afc_error_t err
        err = afc_client_new_from_house_arrest_client(self._c_client, &c_afc_client)
        try:
            result = AfcClient.__new__(AfcClient)
            result._c_client = c_afc_client
            result.handle_error(err)
            return result
        except BaseError, e:
            if c_afc_client != NULL:
                afc_client_free(c_afc_client);
            raise
