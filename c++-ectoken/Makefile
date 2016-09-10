.PHONY: all check

OPENSSL_ROOT=
OPENSSL_INCLUDE=
OPENSSL_LIBS=-lssl -lcrypto

all: ectoken3

../c-ectoken/ecencrypt/libectoken3.a:
	$(MAKE) -C ../c-ectoken/ecencrypt/

ectoken3: ectoken.cc ../c-ectoken/ecencrypt/libectoken3.a
	c++ -o $@ -std=c++98 -Wall -Werror ectoken.cc ../c-ectoken/ecencrypt/libectoken3.a -I../c-ectoken/ecencrypt/ $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)

check: ectoken3
	./ectoken3 -2 -d "IMAKEY" "$(shell ./ectoken -2 -e "IMAKEY" "ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com")"
	./ectoken3 -d "IMAKEY" "$(shell ./ectoken -e "IMAKEY" "ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com")"
	./ectoken3 -3 -d "IMAKEY" "$(shell ./ectoken -e "IMAKEY" "ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com")"
