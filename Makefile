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

.PHONY: all check install install-source

all:
	$(MAKE) -C c-ectoken/ecencrypt
	$(MAKE) -C c++-ectoken
	cd php-ectoken && ./build.sh
	$(MAKE) -C java-ectoken
	$(MAKE) -C python-ectoken

check: ./c-ectoken/ecencrypt/32/ectoken3 ./c-ectoken/ecencrypt/64/ectoken3 ./c++-ectoken/ectoken3 ./php-ectoken/.libs/ectoken.so ./java-ectoken/ECToken3.java
    # run as many language-to-language checks as we have binaries for
	@./check_language_interoperability.sh

install-built: ./c-ectoken/ecencrypt/32/ectoken3 ./c-ectoken/ecencrypt/64/ectoken3
    	# install the binaries in the directory housing them for easier deployment
	@mkdir -p TokenGenerator/Linux/32
	@mkdir -p TokenGenerator/Linux/64
	@mkdir -p TokenGenerator/Windows
	@mkdir -p source_packages
	cp ./c-ectoken/ecencrypt/32/ectoken3 TokenGenerator/Linux/32/ectoken3
	file ECTokenAuthBinaries/Linux/32/ectoken3
	cp ./c-ectoken/ecencrypt/64/ectoken3 TokenGenerator/Linux/64/ectoken3
	file ECTokenAuthBinaries/Linux/64/ectoken3
	#cp c#-ectoken/ecencryptdotnet/bin/Release/ectoken3.exe TokenGenerator/Windows
	#cp c#-ectoken/ecencryptdotnet/bin/Release/BouncyCastle.Crypto.dll TokenGenerator/Windows
	@-rm -r source_packages/TokenGenerator.zip
	@zip -r source_packages/TokenGenerator.zip TokenGenerator
	@rm -rf TokenGenerator

install-source:
	# now need to install the source packages.  fun
	@mkdir -p source_packages
	@rm -rf php-ecencrypt
	@cp -r php-ectoken php-ecencrypt
	@-rm source_packages/php-ecencrypt.zip
	zip -r source_packages/php-ecencrypt.zip php-ecencrypt -i php-ecencrypt/build.sh -i php-ecencrypt/Makefile.in -i php-ecencrypt/config.m4 -i php-ecencrypt/example_memcache.php -i php-ecencrypt/example.php -i php-ecencrypt/example_v3.php -i php-ecencrypt/php_ectoken.h -i php-ecencrypt/README.txt -i php-ecencrypt/ectoken.c -i php-ecencrypt/base64.h  -i php-ecencrypt/base64.c  -i php-ecencrypt/ectoken_v3.c -i php-ecencrypt/ectoken_v3.h
	@rm -rf php-ecencrypt
	@rm -rf c-ecencrypt
	@cp -r c-ectoken/ecencrypt c-ecencrypt
	@-rm source_packages/c-ecencrypt.zip
	zip -r source_packages/c-ecencrypt.zip c-ecencrypt -i c-ecencrypt/Makefile -i c-ecencrypt/*.c -i c-ecencrypt/README -i c-ecencrypt/*.h
	@rm -rf c-ecencrypt
	@rm -rf perl-ecencrypt
	@cp -r perl-ectoken perl-ecencrypt
	@-rm source_packages/perl-ecencrypt.zip
	zip -r source_packages/perl-ecencrypt.zip perl-ecencrypt -i perl-ecencrypt/ectoken3.pl
	@rm -rf perl-ecencrypt
	@rm -rf python-ecencrypt
	@cp -r python-ectoken python-ecencrypt
	@-rm source_packages/python-ecencrypt.zip
	zip -r source_packages/python-ecencrypt.zip python-ecencrypt -i python-ecencrypt/*.py -i python-ecencrypt/requirements.txt -i python-ecencrypt/deps.sh
	@rm -rf python-ecencrypt
	@rm -rf java-ecencrypt
	@cp -r java-ectoken java-ecencrypt
	@-rm source_packages/java-ecencrypt.zip
	zip -r source_packages/java-ecencrypt.zip java-ecencrypt -i java-ecencrypt/ECToken3.java -i java-ecencrypt/lib/* -i java-ecencrypt/ECToken3.mf -i java-ecencrypt/Makefile -i java-ecencrypt/README.txt -i java-ecencrypt/build.sh
	@rm -rf java-ecencrypt
	@-rm source_packages/dotnet-ecencrypt.zip
	zip -r source_packages/dotnet-ecencrypt.zip c#-ectoken

install: install-built install-source
