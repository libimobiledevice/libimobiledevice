cdef extern from "libimobiledevice/installation_proxy.h":
    cdef struct instproxy_client_private:
        pass
    ctypedef instproxy_client_private *instproxy_client_t
    ctypedef void (*instproxy_status_cb_t) (const_char_ptr operation, plist.plist_t status, void *user_data)

    ctypedef enum instproxy_error_t:
        INSTPROXY_E_SUCCESS = 0
        INSTPROXY_E_INVALID_ARG = -1
        INSTPROXY_E_PLIST_ERROR = -2
        INSTPROXY_E_CONN_FAILED = -3
        INSTPROXY_E_OP_IN_PROGRESS = -4
        INSTPROXY_E_OP_FAILED = -5
        INSTPROXY_E_UNKNOWN_ERROR = -256

    instproxy_error_t instproxy_client_new(idevice_t device, uint16_t port, instproxy_client_t *client)
    instproxy_error_t instproxy_client_free(instproxy_client_t client)

    instproxy_error_t instproxy_browse(instproxy_client_t client, plist.plist_t client_options, plist.plist_t *result)
    instproxy_error_t instproxy_install(instproxy_client_t client, char *pkg_path, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
    instproxy_error_t instproxy_upgrade(instproxy_client_t client, char *pkg_path, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
    instproxy_error_t instproxy_uninstall(instproxy_client_t client, char *appid, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)

    instproxy_error_t instproxy_lookup_archives(instproxy_client_t client, plist.plist_t client_options, plist.plist_t *result)
    instproxy_error_t instproxy_archive(instproxy_client_t client, char *appid, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
    instproxy_error_t instproxy_restore(instproxy_client_t client, char *appid, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)
    instproxy_error_t instproxy_remove_archive(instproxy_client_t client, char *appid, plist.plist_t client_options, instproxy_status_cb_t status_cb, void *user_data)

cdef void instproxy_notify_cb(const_char_ptr operation, plist.plist_t status, void *py_callback) with gil:
    (<object>py_callback)(operation, plist.plist_t_to_node(status, False))

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

cdef class InstallationProxy(Base):
    cdef instproxy_client_t _c_client

    def __cinit__(self, iDevice device not None, LockdownClient lockdown=None, *args, **kwargs):
        cdef:
            iDevice dev = device
            LockdownClient lckd
            instproxy_error_t err
        if lockdown is None:
            lckd = LockdownClient(dev)
        else:
            lckd = lockdown
        port = lckd.start_service("com.apple.mobile.installation_proxy")
        err = instproxy_client_new(dev._c_dev, port, &self._c_client)
        self.handle_error(err)

    def __dealloc__(self):
        cdef instproxy_error_t err
        if self._c_client is not NULL:
            err = instproxy_client_free(self._c_client)
            self.handle_error(err)

    cpdef plist.Node browse(self, object client_options):
        cdef:
            plist.Node options
            plist.plist_t c_options
            plist.plist_t c_result = NULL
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        err = instproxy_browse(self._c_client, c_options, &c_result)
        self.handle_error(err)
        return plist.plist_t_to_node(c_result)

    cpdef install(self, bytes pkg_path, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        if callback is None:
            err = instproxy_install(self._c_client, pkg_path, options._c_node, NULL, NULL)
        else:
            err = instproxy_install(self._c_client, pkg_path, options._c_node, instproxy_notify_cb, <void*>callback)
        self.handle_error(err)

    cpdef upgrade(self, bytes pkg_path, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        if callback is None:
            err = instproxy_upgrade(self._c_client, pkg_path, options._c_node, NULL, NULL)
        else:
            err = instproxy_upgrade(self._c_client, pkg_path, options._c_node, instproxy_notify_cb, <void*>callback)
        self.handle_error(err)

    cpdef uninstall(self, bytes appid, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        if callback is None:
            err = instproxy_uninstall(self._c_client, appid, options._c_node, NULL, NULL)
        else:
            err = instproxy_uninstall(self._c_client, appid, options._c_node, instproxy_notify_cb, <void*>callback)
        self.handle_error(err)

    cpdef plist.Node lookup_archives(self, object client_options):
        cdef:
            plist.Node options
            plist.plist_t c_options
            plist.plist_t c_node = NULL
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        err = instproxy_lookup_archives(self._c_client, options._c_node, &c_node)
        self.handle_error(err)
        return plist.plist_t_to_node(c_node)

    cpdef archive(self, bytes appid, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        if callback is None:
            err = instproxy_archive(self._c_client, appid, options._c_node, NULL, NULL)
        else:
            err = instproxy_archive(self._c_client, appid, options._c_node, instproxy_notify_cb, <void*>callback)
        self.handle_error(err)

    cpdef restore(self, bytes appid, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        if callback is None:
            err = instproxy_restore(self._c_client, appid, options._c_node, NULL, NULL)
        else:
            err = instproxy_restore(self._c_client, appid, options._c_node, instproxy_notify_cb, <void*>callback)
        self.handle_error(err)

    cpdef remove_archive(self, bytes appid, object client_options, object callback=None):
        cdef:
            plist.Node options
            plist.plist_t c_options
            instproxy_error_t err
        if isinstance(client_options, plist.Dict):
            options = client_options
            c_options = options._c_node
        elif isinstance(client_options, dict):
            c_options = plist.native_to_plist_t(client_options)
        else:
            raise InstallationProxyError(INSTPROXY_E_INVALID_ARG)
        if callback is None:
            err = instproxy_remove_archive(self._c_client, appid, options._c_node, NULL, NULL)
        else:
            err = instproxy_remove_archive(self._c_client, appid, options._c_node, instproxy_notify_cb, <void*>callback)
        self.handle_error(err)

    cdef inline BaseError _error(self, int16_t ret):
        return InstallationProxyError(ret)
