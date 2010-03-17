cdef class PropertyListService:
    cpdef send(self, plist.Node node):
        cdef plist.Node n = node
        cdef BaseError err = self._send(n._c_node)
        if err: raise err

    cpdef plist.Node receive(self):
        cdef plist.plist_t c_node = NULL
        cdef BaseError err = self._receive(&c_node)
        if err: raise err

        return plist.plist_t_to_node(c_node)

    cdef _send(self, plist.plist_t node): pass
    cdef _receive(self, plist.plist_t* c_node): pass
