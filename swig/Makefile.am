INCLUDES = -I$(top_srcdir)/include  $(libplist_CFLAGS) $(SWIG_PYTHON_CPPFLAGS) -I$(oldincludedir)

if HAVE_SWIG
BUILT_SOURCES = imobiledevice_wrap.cxx
SWIG_SOURCES = imobiledevice.i

CLEANFILES =                \
        *.pyc               \
        *.pyo               \
        _imobiledevice.so   \
        imobiledevice.py    \
        imobiledevice_wrap.cxx

EXTRA_DIST =                \
        __init__.py         \
        imobiledevice.i

swigincludedir =$(includedir)/libimobiledevice/swig
swiginclude_HEADERS = $(SWIG_SOURCES)

imobiledevicedir = $(pyexecdir)/imobiledevice
imobiledevice_PYTHON = __init__.py
nodist_imobiledevice_PYTHON = imobiledevice.py
imobiledevice_LTLIBRARIES = _imobiledevice.la
nodist__imobiledevice_la_SOURCES = imobiledevice_wrap.cxx $(SWIG_SOURCES)
_imobiledevice_la_CFLAGS = $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src
_imobiledevice_la_LDFLAGS = -module -avoid-version $(PYTHON_LDFLAGS)
_imobiledevice_la_LIBADD = $(top_builddir)/src/libimobiledevice.la $(libplistmm_LIBS)

imobiledevice_wrap.cxx : $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) $(INCLUDES) -I$(top_srcdir)/src -o $@ $<

endif # HAVE_SWIG

