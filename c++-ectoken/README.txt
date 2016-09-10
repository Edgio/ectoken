Verizon Digital Media Services Token-Based Authentication Version 3.0
Copyright (C) Verizon.  All rights reserved.

Use of source and binary forms, with or without modification is permitted provided
that there is written consent by Verizon. Redistribution in source and binary
forms  is not permitted.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
