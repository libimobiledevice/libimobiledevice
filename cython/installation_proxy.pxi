cdef extern from "libimobiledevice/installation_proxy.h":
    cdef struct instproxy_client_private:
        pass
    ctypedef instproxy_client_private *instproxy_client_t
    ctypedef void (*instproxy_status_cb_t) (plist.plist_t command, plist.plist_t status, void *user_data)

    ctypedef enum instproxy_error_t:
        INSTPROXY_E_SUCCESS = 0
        INSTPROXY_E_INVALID_ARG = -1
        INSTPROXY_E_PLIST_ERROR = -2
        INSTPROXY_E_CONN_FAILED = -3
        INSTPROXY_E_OP_IN_PROGRESS = -4
        INSTPROXY_E_OP_FAILED = -5
        INSTPROXY_E_UNKNOWN_ERROR = -256

    instproxy_error_t instproxy_client_new(idevice_t device, lockdownd_service_descriptor_t descriptor, instproxy_client_t *client)
    instproxy_error_t instproxy_client_free(instproxy_client_t client)
    instproxy_error_t instproxy_client_get_path_for_bundle_identifier(instproxy_client_t client, const char* bundle_id, char** path)

    instproxy_error_t instproxy_browse(instproxy_client_t client, plist.plist_t client_options, plist.plist_t *result)
    instproxy_error_t instproxy_install(instproxy_client_t client, char *pkg_path, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
    instproxy_error_t instproxy_upgrade(instproxy_client_t client, char *pkg_path, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
    instproxy_error_t instproxy_uninstall(instproxy_client_t client, char *appid, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)

    instproxy_error_t instproxy_lookup_archives(instproxy_client_t client, plist.plist_t client_options, plist.plist_t *result)
    instproxy_error_t instproxy_archive(instproxy_client_t client, char *appid, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
    instproxy_error_t instproxy_restore(instproxy_client_t client, char *appid, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
    instproxy_error_t instproxy_remove_archive(instproxy_client_t client, char *appid, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)

cdef void instproxy_notify_cb(plist.plist_t command, plist.plist_t status, void *py_callback) with gil:
    (<object>py_callback)(plist.plist_t_to_node(command, False), plist.plist_t_to_node(status, False))

cdef class InstallationProxyError(BaseError):
    def __init__(self, *args, **kwargs):
        self._lookup_table = {
            INSTPROXY_E_SUCCESS: "Success",
            INSTPROXY_E_INVALID_ARG: "Invalid argument",
            INSTPROXY_E_PLIST_ERROR: "Property list error",
            INSTPROXY_E_CONN_FAILED: "Connection failed",
            INSTPROXY_E_OP_IN_PROGRESS: "Operation in progress",
            INSTPROXY_E_OP_FAILED: "Operation failed",
            INSTPROXY_E_UNKNOWN_ERROR: "Unknown error"
        }
        BaseError.__init__(self, *args, **kwargs)

cdef class InstallationProxyClient(PropertyListService):
    __service_name__ = "com.apple.mobile.installation_proxy"
    cdef instproxy_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownServiceDescriptor descriptor, *args, **kwargs):
        cdef:
            iDevice dev = device
            instproxy_error_t err
        err = instproxy_client_new(dev._c_dev, descriptor._c_service_descriptor, &self._c_client)
        self.handle_error(err)

    def __dealloc__(self):
        cdef instproxy_error_t err
        if self._c_client is not NULL:
            err = instproxy_client_free(self._c_client)
            self.handle_error(err)

    cpdef get_path_for_bundle_identifier(self, bytes bundle_id):
        cdef:
            char* c_bundle_id = bundle_id
            char* c_path = NULL
            bytes result

        try:
            self.handle_error(instproxy_client_get_path_for_bundle_identifier(self._c_client, c_bundle_id, &c_path))
            if c_path != NULL:
                result = c_path
                return result
            else:
                return None
        except BaseError, e:
            raise
        finally:
            free(c_path)

    cpdef plist.Node browse(self, object client_options):
        cdef:
            plist.Node options
            plist.plist_t c_options
            plist.plist_t c_result = NULL
            bint free_options = False
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
            free_options = True
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        err = instproxy_browse(self._c_client, c_options, &c_result)

        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_result)
        except Exception, e:
            if c_result != NULL:
                plist.plist_free(c_result)
            raise
        finally:
            if free_options:
                plist.plist_free(c_options)

    cpdef install(self, bytes pkg_path, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            bint free_options = False
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
            free_options = True
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        if callback is None:
            err = instproxy_install(self._c_client, pkg_path, c_options, NULL, NULL)
        else:
            err = instproxy_install(self._c_client, pkg_path, c_options, instproxy_notify_cb, <void*>callback)

        try:
            self.handle_error(err)
        except Exception, e:
            raise
        finally:
            if free_options:
                plist.plist_free(c_options)

    cpdef upgrade(self, bytes pkg_path, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            bint free_options = False
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
            free_options = True
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        if callback is None:
            err = instproxy_upgrade(self._c_client, pkg_path, c_options, NULL, NULL)
        else:
            err = instproxy_upgrade(self._c_client, pkg_path, c_options, instproxy_notify_cb, <void*>callback)
        try:
            self.handle_error(err)
        except Exception, e:
            raise
        finally:
            if free_options:
                plist.plist_free(c_options)

    cpdef uninstall(self, bytes appid, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            instproxy_error_t err
            bint free_options = False
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
            free_options = True
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)

        if callback is None:
            err = instproxy_uninstall(self._c_client, appid, c_options, NULL, NULL)
        else:
            err = instproxy_uninstall(self._c_client, appid, c_options, instproxy_notify_cb, <void*>callback)

        try:
            self.handle_error(err)
        except Exception, e:
            raise
        finally:
            if free_options:
                plist.plist_free(c_options)

    cpdef plist.Node lookup_archives(self, object client_options):
        cdef:
            plist.Node options
            plist.plist_t c_options
            plist.plist_t c_node = NULL
            instproxy_error_t err
            bint free_options = False
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
            free_options = True
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)

        err = instproxy_lookup_archives(self._c_client, c_options, &c_node)

        try:
            self.handle_error(err)
            return plist.plist_t_to_node(c_node)
        except Exception, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise
        finally:
            if free_options:
                plist.plist_free(c_options)

    cpdef archive(self, bytes appid, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            bint free_options = False
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
            free_options = True
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)

        if callback is None:
            err = instproxy_archive(self._c_client, appid, c_options, NULL, NULL)
        else:
            err = instproxy_archive(self._c_client, appid, c_options, instproxy_notify_cb, <void*>callback)

        try:
            self.handle_error(err)
        except Exception, e:
            raise
        finally:
            if free_options:
                plist.plist_free(c_options)

    cpdef restore(self, bytes appid, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            bint free_options = False
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
            free_options = True
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)

        if callback is None:
            err = instproxy_restore(self._c_client, appid, c_options, NULL, NULL)
        else:
            err = instproxy_restore(self._c_client, appid, c_options, instproxy_notify_cb, <void*>callback)

        try:
            self.handle_error(err)
        except Exception, e:
            raise
        finally:
            if free_options:
                plist.plist_free(c_options)

    cpdef remove_archive(self, bytes appid, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            bint free_options = False
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
            free_options = True
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)

        if callback is None:
            err = instproxy_remove_archive(self._c_client, appid, c_options, NULL, NULL)
        else:
            err = instproxy_remove_archive(self._c_client, appid, c_options, instproxy_notify_cb, <void*>callback)

        try:
            self.handle_error(err)
        except Exception, e:
            raise
        finally:
            if free_options:
                plist.plist_free(c_options)

    cdef inline BaseError _error(self, int16_t ret):
        return InstallationProxyError(ret)
