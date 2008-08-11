#!/bin/sh
aclocal
libtoolize
autoheader
automake --add-missing
autoconf
