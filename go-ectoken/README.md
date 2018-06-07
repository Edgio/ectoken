EdgeCast Token Authentication extension for Go
===============================================

Written against Go 1.10, but is expected to work with older versions.

To build and install the test utility, simply run
'go get -u github.com/VerizonDigital/ectoken/go-ectoken/ectoken'

Command-line usage for encrypting and decrypting is as
follows:

     To Encrypt:
         ec_encrypt <key> <text>
     or:
         ec_encrypt encrypt <key> <text>
     To Decrypt:
         ec_encrypt decrypt <key> <text>

For instance, using an encryption key of "testkey123":

$ ./ectoken encrypt testkey123 'ec_expire=1257642471&ec_secure=33'
af0c6acf7906cd500aee63a4dd2e97ddcb0142601cf83aa9d622289718c4c85413

$ ./ectoken decrypt testkey123 af0c6acf7906cd500aee63a4dd2e97ddcb0142601cf83aa9d622289718c4c85413
ec_expire=1257642471&ec_secure=33
