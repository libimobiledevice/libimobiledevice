#!/bin/sh
aclocal -I m4
libtoolize
autoheader
automake --add-missing
autoconf
