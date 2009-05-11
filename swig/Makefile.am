INCLUDES = -I$(top_srcdir)/include  $(libplist_CFLAGS) -I$(oldincludedir)

BUILT_SOURCES = iphone_wrap.c
SWIG_SOURCES = iphone.i

CLEANFILES =                \
        *.pyc               \
        *.pyo               \
        _iPhone.so          \
        iPhone.py           \
        iphone_wrap.c

EXTRA_DIST =                \
        __init__.py         \
	iphone.i

swigincludedir =$(includedir)/libiphone/swig
swiginclude_HEADERS = $(SWIG_SOURCES)

iPhonedir = $(pyexecdir)/libiphone
iPhone_PYTHON = __init__.py
nodist_iPhone_PYTHON = iPhone.py
iPhone_LTLIBRARIES = _iPhone.la
nodist__iPhone_la_SOURCES = iphone_wrap.c $(SWIG_SOURCES)
_iPhone_la_CFLAGS = $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src
_iPhone_la_LDFLAGS = -module -avoid-version $(PYTHON_LDFLAGS)
_iPhone_la_LIBADD = $(top_builddir)/src/libiphone.la

iphone_wrap.c : $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) $(INCLUDES) -I$(top_srcdir)/src -o $@ $<

