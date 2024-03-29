# ------------------------------------------------------------------------------
# setup
# ------------------------------------------------------------------------------
.PHONY: all
OPENSSL_ROOT=
OPENSSL_INCLUDE=
OPENSSL_LIBS=-lcrypto
# ------------------------------------------------------------------------------
# all target
# ------------------------------------------------------------------------------
all: ectoken libectoken.a
# ------------------------------------------------------------------------------
# ectoken
# ------------------------------------------------------------------------------
ectoken: util/ectoken_cmd.c ectoken.c base64.c
	gcc -O2 -Wall -Werror -std=gnu99 util/ectoken_cmd.c -I. ectoken.c base64.c -o ectoken $(OPENSSL_LIBS) $(OPENSSL_INCLUDE) -lm
# ------------------------------------------------------------------------------
# libectoken
# ------------------------------------------------------------------------------
libectoken.a: ectoken.o base64.o
	ar rcs $@ ectoken.o base64.o
# ------------------------------------------------------------------------------
# ectoken_test
# ------------------------------------------------------------------------------
ectoken_test: tests/ectoken_test.c all
	gcc -std=c99 -I. tests/ectoken_test.c -lcrypto -lm -o ectoken_test
# ------------------------------------------------------------------------------
# test
# ------------------------------------------------------------------------------
test: ectoken_test
	./ectoken_test
# ------------------------------------------------------------------------------
# clean
# ------------------------------------------------------------------------------
clean:
	-rm -f *.o *.a ectoken ectoken_test
