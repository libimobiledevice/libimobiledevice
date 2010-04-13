cdef class PropertyListClient(Base):
    cpdef send(self, plist.Node node):
        self.handle_error(self._send(node._c_node))

    cpdef object receive(self):
        cdef:
            plist.plist_t c_node = NULL
            int16_t err
        err = self._receive(&c_node)
        try:
            self.handle_error(err)
        except BaseError, e:
            if c_node != NULL:
                plist.plist_free(c_node)
            raise

        return plist.plist_t_to_node(c_node)

    cdef inline int16_t _send(self, plist.plist_t node): pass
    cdef inline int16_t _receive(self, plist.plist_t* c_node): pass
