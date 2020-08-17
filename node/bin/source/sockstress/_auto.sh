#!/bin/sh

if test -f Makefile; then
	make distclean
fi

autoconf

rm -rf autom4te.cache
