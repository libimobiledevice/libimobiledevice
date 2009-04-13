INCLUDES = -I$(top_srcdir)/include  $(libplist_CFLAGS)

BUILT_SOURCES = $(srcdir)/iphone_wrap.c
SWIG_SOURCES = iphone.i

swigincludedir =$(includedir)/libiphone/swig
swiginclude_HEADERS = $(SWIG_SOURCES)

pkgpython_PYTHON = iPhone.py __init__.py
pkgpyexec_LTLIBRARIES = _iPhone.la
_iPhone_la_SOURCES = $(srcdir)/iphone_wrap.c $(SWIG_SOURCES)
_iPhone_la_CFLAGS = $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src
_iPhone_la_LDFLAGS = -module $(PYTHON_LDFLAGS)
_iPhone_la_LIBADD = ../src/libiphone.la

$(srcdir)/iphone_wrap.c : $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) $(INCLUDES) -I$(top_srcdir)/src -o $@ $<

