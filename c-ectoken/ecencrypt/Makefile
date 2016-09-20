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

.PHONY: all 32 64

OPENSSL_ROOT=
OPENSSL_INCLUDE=
OPENSSL_LIBS=-lssl -lcrypto

all: 32 64 libectoken3.a ectoken_v3

# packages needed for 32-bit compilation:
# lib32gcc-4.8
# libssl-dev:i386
32: ec_encrypt.c ectoken_v3.c base64.c
	@echo "packages needed for 32-bit compilation on Ubuntu 14.04"
	@echo "  lib32gcc-4.8"
	@echo "  libssl-dev:i386"
	gcc -m32 -O2 -Wall -Werror -std=gnu99 ec_encrypt.c ectoken_v3.c base64.c -o 32/ectoken3 $(OPENSSL_LIBS) $(OPENSSL_INCLUDE) -lm
	strip 32/ectoken3

64: ec_encrypt.c ectoken_v3.c base64.c
	gcc -m64 -O2 -Wall -Werror -std=gnu99 ec_encrypt.c ectoken_v3.c base64.c -o 64/ectoken3 $(OPENSSL_LIBS) $(OPENSSL_INCLUDE) -lm
	strip 64/ectoken3

libectoken3.a: ectoken_v3.o base64.o
	ar rcs $@ ectoken_v3.o base64.o

ectoken_v3_test.o: ectoken_v3_test.c base64.o
	gcc -c -std=c99 ectoken_v3_test.c base64.o -g -Wall -Wno-format -Werror -O2 -o $@ $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)
ectoken_v3.o: ectoken_v3.c
	gcc -c -std=c99 ectoken_v3.c -g -Wall -Wno-format -Werror -O2 -o $@ -fPIC $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)
base64.o: base64.c
	gcc -c -std=c99 base64.c -lm -g -Wall -Wno-format -Werror -O2 -o $@ -fPIC $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)

ectoken_v3: ectoken_v3_test.o libectoken3.a
	gcc -std=c99 ectoken_v3_test.o libectoken3.a -lm -g -Wall -Wno-format -O2 -o $@ $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)

# fails to link?
ectoken_v3_static:
	gcc -std=c99 ectoken_v3.c base64.c -static -Wall -Wno-format -Werror -O2 -o $@ $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)

analyze:
	-clang --std=c99 -fsyntax-only -pedantic *.c
	-cppcheck --std=posix *.c *.h
	-cppcheck --std=c89 *.c *.h
	-cppcheck --std=c99 *.c *.h
	-cppcheck --std=c11 *.c *.h
	-cppcheck --std=c++03 *.c *.h
	-cppcheck --std=c++11 *.c *.h
	-clang --std=c89 --analyze -Xanalyzer -analyzer-output=text \
		-analyzer-checker=alpha \
		-analyzer-checker=core \
		-analyzer-checker=security \
		-analyzer-checker=unix \
		*.c
	-clang --std=c99 --analyze -Xanalyzer -analyzer-output=text \
		-analyzer-checker=alpha \
		-analyzer-checker=core \
		-analyzer-checker=security \
		-analyzer-checker=unix \
		*.c
	-clang --std=c11 --analyze -Xanalyzer -analyzer-output=text \
		-analyzer-checker=alpha \
		-analyzer-checker=core \
		-analyzer-checker=security \
		-analyzer-checker=unix \
		*.c
	-clang --std=c99 -O -g -fsanitize=address base64.c ectoken_v3_test.c -o ectoken_test_analyze  $(OPENSSL_LIBS) $(OPENSSL_INCLUDE)
	-./ectoken_test_analyze


clean:
	-rm *.o *.a ectoken_v3 64/* 32/* ectoken_test_analyze
