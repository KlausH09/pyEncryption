from pathlib import Path
from io import BytesIO
from typing import BinaryIO, Union

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from .utils import EncryptSettings, ChunkedStreaming


class Encryption():

    def __init__(self, key: Union[RSA.RsaKey, bytes, Path], settings: EncryptSettings = None):
        """Encryption

        Args:
            key (RSA.RsaKey, bytes, Path): public or private RSA key, this argument can passed as:
                                            - RSA.RsaKey
                                            - bytes: binary key data
                                            - Path: path to the key file
            settings (EncryptSettings): encryption settings
        """
        if isinstance(key, RSA.RsaKey):
            pass
        elif isinstance(key, bytes):
            key = RSA.import_key(key)
        elif isinstance(key, Path):
            with open(key, 'rb') as fd:
                key = RSA.import_key(fd.read())
        else:
            raise ValueError()

        if settings is None:
            settings = EncryptSettings()

        self._settings = settings
        self._key = key.public_key()

    def encrypt(self, msg: bytes) -> bytes:
        result = BytesIO()
        self.encrypt_stream(msg, result)

        result.seek(0)
        return result.read()

    def encrypt_stream(self, input_stream: Union[BinaryIO, bytes], output_stream: BinaryIO):
        if isinstance(input_stream, bytes):
            input_stream = BytesIO(input_stream)
            input_stream.seek(0)

        # generate a random AES key and encrypt it with public RSA key
        session_key = get_random_bytes(self._settings.aes_len)
        enc_session_key = PKCS1_OAEP.new(self._key).encrypt(session_key)
        nonce = get_random_bytes(self._settings.nonce_len)

        # Encrypt the data with the AES session key
        # (use the EAX mode to allow detection of unauthorized modifications)
        cipher_aes = AES.new(session_key, AES.MODE_EAX,
                             mac_len=self._settings.tag_len, nonce=nonce)

        output_stream.write(enc_session_key)
        output_stream.write(nonce)

        for c in ChunkedStreaming.chunked_stream(input_stream):
            output_stream.write(cipher_aes.encrypt(c))

        tag = cipher_aes.digest()
        output_stream.write(tag)
