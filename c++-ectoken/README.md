EdgeCast Token Authentication extension for C++
===============================================

This software is tested on Ubuntu 12.04 and 14.04 using the 1.0.1 stream of OpenSSL.

The code can be compiled using 'make'.  It requires the C static
library to be built to provide v3 functionality (and will try to build
it if it's not).

Command-line usage for encrypting and decrypting is as
follows:

    ./ectoken -e key plaintext      # encrypt plaintext with key using v3 algorithm; print result
    ./ectoken -E key plaintext      # encrypt plaintext with key using v3 algorithm; print detailed information
    ./ectoken -d key ciphertext     # decrypt ciphertext with key using v3 algorithm; print result
    ./ectoken -D key ciphertext     # decrypt ciphertext with key using v3 algorithm; print detailed information

For instance, using an encryption key of "testkey123":

$ ./ectoken -e testkey123 'ec_expire=1257642471&ec_secure=33'
af0c6acf7906cd500aee63a4dd2e97ddcb0142601cf83aa9d622289718c4c85413

$ ./ectoken -d testkey123 af0c6acf7906cd500aee63a4dd2e97ddcb0142601cf83aa9d622289718c4c85413
ec_expire=1257642471&ec_secure=33
