#!/bin/bash

make clean
set -o errexit

phpize
rm aclocal.m4
aclocal
autoconf
./configure --enable-ectoken
make
