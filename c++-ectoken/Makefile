# /**
# * Copyright (C) 2016 Verizon. All Rights Reserved.
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *     http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# */

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
