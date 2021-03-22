# ------------------------------------------------------------------------------
# Copyright Verizon.
#
# \file:    ectoken.h
# \details: TODO
#
# Licensed under the terms of the Apache 2.0 open source license.
# Please refer to the LICENSE file in the project root for the terms.
# ------------------------------------------------------------------------------
.PHONY: all
# ------------------------------------------------------------------------------
# setup
# ------------------------------------------------------------------------------
OPENSSL_ROOT=
OPENSSL_INCLUDE=
OPENSSL_LIBS=-lssl -lcrypto
# ------------------------------------------------------------------------------
# all target
# ------------------------------------------------------------------------------
all: ectoken libectoken.a
# ------------------------------------------------------------------------------
# ectoken
# ------------------------------------------------------------------------------
ectoken: util/ec_encrypt.c ectoken.c base64.c
	gcc -m64 -O2 -Wall -Werror -std=gnu99 util/ec_encrypt.c -I. ectoken.c base64.c -o ectoken $(OPENSSL_LIBS) $(OPENSSL_INCLUDE) -lm
	strip ectoken
# ------------------------------------------------------------------------------
# libectoken
# ------------------------------------------------------------------------------
libectoken.a: ectoken.o base64.o
	ar rcs $@ ectoken.o base64.o
# ------------------------------------------------------------------------------
# tests
# ------------------------------------------------------------------------------
#ectoken_test.o: tests/ectoken_test.c base64.o
#	gcc -c -std=c99 tests/ectoken_test.c base64.o -g -Wall -Wno-format -Werror -O2 -o $@ $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)
#ectoken.o: ectoken.c
#	gcc -c -std=c99 ectoken.c -g -Wall -Wno-format -Werror -O2 -o $@ -fPIC $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)
#base64.o: base64.c
#	gcc -c -std=c99 base64.c -lm -g -Wall -Wno-format -Werror -O2 -o $@ -fPIC $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)
# ------------------------------------------------------------------------------
# 
# ------------------------------------------------------------------------------
#ectoken_test: ectoken_test.o libectoken.a
#	gcc -std=c99 ectoken_test.o libectoken.a -lm -g -Wall -Wno-format -O2 -o $@ $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)
# ------------------------------------------------------------------------------
# fails to link?
# ------------------------------------------------------------------------------
#ectoken_static:
#	gcc -std=c99 ectoken.c base64.c -static -Wall -Wno-format -Werror -O2 -o $@ $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)
# ------------------------------------------------------------------------------
# clean
# ------------------------------------------------------------------------------
clean:
	-rm *.o *.a ectoken
