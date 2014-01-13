#!/bin/sh
set -x
aclocal || exit 1
libtoolize --force || exit 1
automake || exit 1
autoconf || exit 1
