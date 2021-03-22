# ectoken
> C implementation of EdgeCast token (`ectoken`)_


## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)


## Background

C implementation of the "EdgeCast Token" (`ectoken`)

## Install

### With `pip`

```sh
pip install -r requirements.txt
```

## Usage

### Help
```sh
>./ectoken3.py -h
usage: ectoken3.py

Generate Random Security Config Post from Template.

optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     Token Key.
  -t TOKEN, --token TOKEN
                        Token to encrypt or decrypt.
  -d, --decrypt         Decrypt.
  -v, --verbose         Verbosity.
```

### Encrypt

Encrypt clear text token `<token>` with key: `<key>`:
```sh
~>./ectoken3.py -k MY_SECRET_KEY -t MY_COOL_TOKEN
26oBaqCbdLyJD5RjsHBYGsIDQGOehPo2rZfGwGey-ubhciakzPwRIdQ
```

### Decrypt

Decrypt ciphertext token `<token>` with key: `<key>`:
```sh
~>./ectoken3.py -k MY_SECRET_KEY -t '26oBaqCbdLyJD5RjsHBYGsIDQGOehPo2rZfGwGey-ubhciakzPwRIdQ' -d
MY_COOL_TOKEN
```


## Contribute

- We welcome issues, questions and pull requests.


## License

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to the `LICENSE-2.0.txt` file for the full terms.
