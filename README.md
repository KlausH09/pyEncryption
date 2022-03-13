# pyencryption

[![codecov](https://codecov.io/gh/KlausH09/pyEncryption/branch/main/graph/badge.svg?token=pyEncryption_token_here)](https://codecov.io/gh/KlausH09/pyEncryption)
[![CI](https://github.com/KlausH09/pyEncryption/actions/workflows/main.yml/badge.svg)](https://github.com/KlausH09/pyEncryption/actions/workflows/main.yml)

Encryption based on RSA with AES.

## Install

```bash
pip install git+https://github.com/KlausH09/pyEncryption.git@main
```

## Usage

```py
import pyencryption

pyencryption.save_random_RSA_key_pair("./private.pem", "./public.pem")
encrypt = pyencryption.Encryption("./public.pem")
decrypt = pyencryption.Decryption("./private.pem")

with open("msg.bin", "rb") as fd0, open("cipher.bin", "wb") as fd1:
    encrypt.encrypt_stream(fd0, fd1)

with open("cipher.bin", "rb") as fd0, open("msg_.bin", "wb") as fd1:
    decrypt.decrypt_stream(fd0, fd1)
```

or

```py
from Crypto.PublicKey import RSA
import pyencryption

key = RSA.generate(2048)
encrypt = pyencryption.Encryption(key.public_key())
decrypt = pyencryption.Decryption(key)

msg = b"foo" * 1000
cipher = encrypt.encrypt(msg)
msg_ = decrypt.decrypt(cipher)
```
