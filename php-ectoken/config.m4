PHP_ARG_ENABLE(ectoken, whether to enable EdgeCast Token support,
[ --enable-ectoken   Enable EdgeCast Token support])

if test "$PHP_ECTOKEN" = "yes"; then
  AC_DEFINE(HAVE_ECTOKEN, 1, [Whether you have EdgeCast Token])
  PHP_ADD_LIBRARY(crypto)
  #PHP_ADD_LIBRARY_WITH_PATH(ectoken3,../c-ectoken/ecencrypt/,ECTOKEN_SHARED_LIBADD)
  PHP_SUBST(ECTOKEN_SHARED_LIBADD)
  PHP_NEW_EXTENSION(ectoken, ectoken.c ectoken_v3.c base64.c, $ext_shared)
fi
