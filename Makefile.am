AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = 3rd_party common src include $(CYTHON_SUB) tools docs

EXTRA_DIST = \
	docs \
	README.md \
	git-version-gen

dist-hook:
	@if ! git diff --quiet; then echo "Uncommitted changes present; not releasing"; exit 1; fi
	echo $(VERSION) > $(distdir)/.tarball-version

docs/html: $(top_builddir)/doxygen.cfg $(top_srcdir)/src/*.c $(top_srcdir)/src/*.h $(top_srcdir)/include/libimobiledevice/*.h
	rm -rf docs/html
	doxygen doxygen.cfg

docs: doxygen.cfg docs/html

indent:
	indent -kr -ut -ts4 -l120 src/*.c src/*.h

