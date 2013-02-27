AM_CPPFLAGS = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(openssl_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libgnutls_LIBS) $(libtasn1_LIBS) $(openssl_LIBS) $(libplist_LIBS)

if HAVE_CYTHON

BUILT_SOURCES = imobiledevice.c
PXDINCLUDES = imobiledevice.pxd $(CYTHON_PLIST_INCLUDE_DIR)/plist.pxd
PXIINCLUDES =					\
	lockdown.pxi				\
	mobilesync.pxi				\
	notification_proxy.pxi		\
	sbservices.pxi				\
	mobilebackup.pxi			\
	mobilebackup2.pxi			\
	afc.pxi						\
	file_relay.pxi				\
	screenshotr.pxi				\
	installation_proxy.pxi		\
	webinspector.pxi			\
	heartbeat.pxi				\
	diagnostics_relay.pxi		\
	misagent.pxi				\
	house_arrest.pxi			\
	restore.pxi					\
	mobile_image_mounter.pxi

CLEANFILES =                \
        *.pyc               \
        *.pyo               \
        imobiledevice.c

EXTRA_DIST = imobiledevice.pyx imobiledevice.pxd $(PXIINCLUDES)

imobiledevicedir = $(pyexecdir)
imobiledevice_LTLIBRARIES = imobiledevice.la
imobiledevice_la_SOURCES = imobiledevice.pyx
imobiledevice_la_CFLAGS = -I../include -I../src $(PYTHON_CPPFLAGS) $(AM_CFLAGS) -Wno-shadow -Wno-redundant-decls -Wno-switch-default -Wno-strict-aliasing -Wno-implicit-function-declaration
imobiledevice_la_LDFLAGS = -module -avoid-version -L$(libdir) $(PYTHON_LDFLAGS) $(AM_LDFLAGS)
imobiledevice_la_LIBADD = ../src/libimobiledevice.la

imobiledevice.c: imobiledevice.pyx $(PXDINCLUDES) $(PXIINCLUDES)

.pyx.c:
	$(CYTHON) -I$(CYTHON_PLIST_INCLUDE_DIR) -I$(top_srcdir)/src -o $@ $<

# imobiledevice_private.c: $(IMOBILEDEVICE_PRIVATE_SOURCES) $(IMOBILEDEVICE_INCLUDES) $(PLIST_INCLUDES)
#	$(CYTHON) $(IMOBILEDEVICE_CPPFLAGS) -I$(top_srcdir)/src -o $@ $<

endif
