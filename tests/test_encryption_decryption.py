import pytest
from io import BytesIO

from Crypto.PublicKey import RSA
import pyencryption

_messages = {
    "short": b"foobar",
    "long": b"foobar" * 1000,
}


@pytest.mark.parametrize("msg", ["short", "long"])
def test_encrypt_decrypt(msg):
    msg = _messages[msg]
    key = RSA.generate(2048)
    encrypt = pyencryption.Encryption(key.public_key())
    decrypt = pyencryption.Decryption(key)

    cipher = encrypt.encrypt(msg)
    msg_ = decrypt.decrypt(cipher)
    assert msg_ == msg

    with pytest.raises(pyencryption.MacCheckFailed):
        decrypt.decrypt(cipher[:-1])
    with pytest.raises(pyencryption.MacCheckFailed):
        decrypt.decrypt(cipher[:-18] + b'x' + cipher[-17:])


@pytest.mark.parametrize("msg", ["short", "long"])
def test_encrypt_decrypt_stream(msg: bytes):
    msg = _messages[msg]
    key = RSA.generate(2048)
    encrypt = pyencryption.Encryption(key.public_key())
    decrypt = pyencryption.Decryption(key)

    msg_stream = BytesIO(msg)
    msg_stream.seek(0)

    cipher_stream = BytesIO()
    encrypt.encrypt_stream(msg_stream, output_stream=cipher_stream)

    msg_stream_ = BytesIO()
    cipher_stream.seek(0)
    decrypt.decrypt_stream(cipher_stream, output_stream=msg_stream_)
    msg_stream_.seek(0)

    msg_ = msg_stream_.read()
    assert msg_ == msg

    with pytest.raises(pyencryption.MacCheckFailed):
        cipher_stream.seek(-17, 2)
        cipher_stream.write(b'x')
        cipher_stream.seek(0)
        decrypt.decrypt_stream(cipher_stream, output_stream=BytesIO())
