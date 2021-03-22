# ectoken
> C implementation of EdgeCast token (`ectoken`)_


## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)


## Background

C implementation of the "EdgeCast Token" (`ectoken`), an [AES-GCM](https://tools.ietf.org/html/rfc5288) token.

## Install

The C implementation requires [`gcc`](https://gcc.gnu.org/) to build and [OpenSSL](https://www.openssl.org/) `libcrypto`to link.
 
### Building with Make

To build, run the `make` command.

```sh
ectoken>make
gcc -m64 -O2 -Wall -Werror -std=gnu99 util/ec_encrypt.c -I. ectoken.c base64.c -o ectoken -lcrypto  -lm
strip ectoken
cc    -c -o ectoken.o ectoken.c
cc    -c -o base64.o base64.c
ar rcs libectoken.a ectoken.o base64.o
```

This will build a library and an executable (`ectoken`) for command line usage.

### Running tests

Run `make test` from the project directory.

```sh
ectoken>make test
gcc -O2 -Wall -Werror -std=gnu99 util/ec_encrypt.c -I. ectoken.c base64.c -o ectoken -lcrypto  -lm
cc    -c -o ectoken.o ectoken.c
cc    -c -o base64.o base64.c
ar rcs libectoken.a ectoken.o base64.o
gcc -std=c99 -I. tests/ectoken_test.c -lcrypto -lm -o ectoken_test
./ectoken_test
test_short_size_calculations
success
...
test_full_flow
success

test_full_flow
success
```


## Usage

### Help
```sh
>./ectoken 
Error wrong number of arguments specified
Usage: 
 To Encrypt:
     ec_encrypt <key> <text>
 or:
     ec_encrypt encrypt <key> <text>
 To Decrypt:
     ec_encrypt decrypt <key> <text>
```

### Encrypt

Encrypt clear text token `<token>` with key: `<key>`:
```sh
>./ectoken encrypt MY_SECRET_KEY MY_COOL_TOKEN
fVSYBBTynMkvQECGV-Kdfp333R-MGY2fsrrpVyuqd7OiuAUsQ8ITrL0
```

### Decrypt

Decrypt ciphertext token `<token>` with key: `<key>`:
```sh
>./ectoken decrypt MY_SECRET_KEY fVSYBBTynMkvQECGV-Kdfp333R-MGY2fsrrpVyuqd7OiuAUsQ8ITrL0
MY_COOL_TOKEN
```


## Contribute

- We welcome issues, questions and pull requests.


## License

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to the `LICENSE-2.0.txt` file for the full terms.
