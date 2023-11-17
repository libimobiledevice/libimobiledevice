AM_CPPFLAGS = \
	-I$(top_srcdir)/include

AM_CFLAGS = \
	$(GLOBAL_CFLAGS) \
	$(ssl_lib_CFLAGS) \
	$(LFS_CFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(libplist_CFLAGS)

AM_LIBS = \
	$(ssl_lib_LIBS) \
	$(PTHREAD_LIBS) \
	$(libplist_LIBS)

if HAVE_CYTHON

BUILT_SOURCES = imobiledevice.c
PXDINCLUDES = \
	imobiledevice.pxd \
	$(CYTHON_PLIST_INCLUDE_DIR)/plist.pxd

PXIINCLUDES = \
	lockdown.pxi \
	mobilesync.pxi \
	notification_proxy.pxi \
	sbservices.pxi \
	mobilebackup.pxi \
	mobilebackup2.pxi \
	afc.pxi \
	file_relay.pxi \
	screenshotr.pxi \
	installation_proxy.pxi \
	webinspector.pxi \
	heartbeat.pxi \
	diagnostics_relay.pxi \
	misagent.pxi \
	house_arrest.pxi \
	restore.pxi \
	mobile_image_mounter.pxi \
	debugserver.pxi

CLEANFILES = \
	*.pyc \
	*.pyo \
	imobiledevice.c

EXTRA_DIST = \
	imobiledevice.pyx \
	imobiledevice.pxd \
	$(PXIINCLUDES)

imobiledevicedir = $(pyexecdir)
imobiledevice_LTLIBRARIES = imobiledevice.la
imobiledevice_la_SOURCES = imobiledevice.pyx
imobiledevice_la_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src \
	$(PYTHON_CPPFLAGS) \
	$(AM_CFLAGS) \
	-Wno-shadow \
	-Wno-redundant-decls \
	-Wno-switch-default \
	-Wno-strict-aliasing \
	-Wno-implicit-function-declaration \
	-fvisibility=default \
	$(CYTHON_CFLAGS)

imobiledevice_la_LDFLAGS = \
	-module \
	-avoid-version \
	-L$(libdir) \
	$(PYTHON_LIBS) \
	$(AM_LIBS) \
	-no-undefined

imobiledevice_la_LIBADD = $(top_builddir)/src/libimobiledevice-1.0.la

imobiledevice.c: imobiledevice.pyx $(PXDINCLUDES) $(PXIINCLUDES)

.pyx.c:
	$(CYTHON) -I$(CYTHON_PLIST_INCLUDE_DIR) -I$(top_srcdir)/src -o $@ $<

endif
