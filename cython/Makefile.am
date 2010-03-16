AM_CPPFLAGS = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libusbmuxd_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) $(libplist_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS) $(libplist_LIBS) $(libusbmuxd_LIBS) $(libgcrypt_LIBS)

if HAVE_CYTHON

BUILT_SOURCES = imobiledevice.c

CLEANFILES =                \
        *.pyc               \
        *.pyo               \
        imobiledevice.so	\
        imobiledevice.c

EXTRA_DIST =                \
        imobiledevice.pyx

imobiledevicedir = $(pyexecdir)
imobiledevice_LTLIBRARIES = imobiledevice.la
nodist_imobiledevice_la_SOURCES = imobiledevice.c #imobiledevice_private.c
imobiledevice_la_CFLAGS = -I$(top_builddir)/include -I$(top_srcdir)/src $(PYTHON_CPPFLAGS) 
imobiledevice_la_LDFLAGS = -module -avoid-version $(PYTHON_LDFLAGS)
imobiledevice_la_LIBADD = $(top_builddir)/src/libimobiledevice.la

imobiledevice.c: imobiledevice.pyx $(CYTHON_PLIST_INCLUDE_DIR)/plist.pxd
	$(CYTHON) --line-directives -I$(CYTHON_PLIST_INCLUDE_DIR) -I$(top_srcdir)/src -o $@ $<

# imobiledevice_private.c: $(IMOBILEDEVICE_PRIVATE_SOURCES) $(IMOBILEDEVICE_INCLUDES) $(PLIST_INCLUDES)
#	$(CYTHON) $(IMOBILEDEVICE_CPPFLAGS) -I$(top_srcdir)/src -o $@ $<

endif
