dnl /**
dnl * Copyright (C) 2016 Verizon. All Rights Reserved.
dnl *
dnl * Licensed under the Apache License, Version 2.0 (the "License");
dnl * you may not use this file except in compliance with the License.
dnl * You may obtain a copy of the License at
dnl *     http://www.apache.org/licenses/LICENSE-2.0
dnl *
dnl * Unless required by applicable law or agreed to in writing, software
dnl * distributed under the License is distributed on an "AS IS" BASIS,
dnl * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl * See the License for the specific language governing permissions and
dnl * limitations under the License.
dnl */

PHP_ARG_ENABLE(ectoken, whether to enable EdgeCast Token support,
[ --enable-ectoken   Enable EdgeCast Token support])

if test "$PHP_ECTOKEN" = "yes"; then
  AC_DEFINE(HAVE_ECTOKEN, 1, [Whether you have EdgeCast Token])
  PHP_ADD_LIBRARY(crypto)
  #PHP_ADD_LIBRARY_WITH_PATH(ectoken3,../c-ectoken/ecencrypt/,ECTOKEN_SHARED_LIBADD)
  PHP_SUBST(ECTOKEN_SHARED_LIBADD)
  PHP_NEW_EXTENSION(ectoken, ectoken.c ectoken_v3.c base64.c, $ext_shared)
fi
