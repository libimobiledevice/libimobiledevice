cdef class PropertyListClient(Base):
    cpdef send(self, plist.Node node):
        cdef plist.Node n = node
        self.handle_error(self._send(n._c_node))

    cpdef object receive(self):
        cdef plist.plist_t c_node = NULL
        self.handle_error(self._receive(&c_node))

        return plist.plist_t_to_node(c_node)

    cdef inline int16_t _send(self, plist.plist_t node): pass
    cdef inline int16_t _receive(self, plist.plist_t* c_node): pass
