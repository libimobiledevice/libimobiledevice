INCLUDES = -I$(top_srcdir)/include  $(libplist_CFLAGS) $(SWIG_PYTHON_CPPFLAGS) -I$(oldincludedir)

BUILT_SOURCES = iphone_wrap.cxx
SWIG_SOURCES = iphone.i

CLEANFILES =                \
        *.pyc               \
        *.pyo               \
        _iphone.so          \
        iphone.py           \
        iphone_wrap.cxx

EXTRA_DIST =                \
        __init__.py         \
        iphone.i

swigincludedir =$(includedir)/libiphone/swig
swiginclude_HEADERS = $(SWIG_SOURCES)

iphonedir = $(pyexecdir)/iphone
iphone_PYTHON = __init__.py
nodist_iphone_PYTHON = iphone.py
iphone_LTLIBRARIES = _iphone.la
nodist__iphone_la_SOURCES = iphone_wrap.cxx $(SWIG_SOURCES)
_iphone_la_CFLAGS = $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src
_iphone_la_LDFLAGS = -module -avoid-version $(PYTHON_LDFLAGS)
_iphone_la_LIBADD = $(top_builddir)/src/libiphone.la $(libplistmm_LIBS)

iphone_wrap.cxx : $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) $(INCLUDES) -I$(top_srcdir)/src -o $@ $<

