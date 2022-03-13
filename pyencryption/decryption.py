from pathlib import Path
from io import BytesIO
from typing import BinaryIO, Union

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

from .utils import EncryptSettings, ChunkedStreaming


class MacCheckFailed(ValueError):
    pass


class Decryption:

    def __init__(self, key: Union[RSA.RsaKey, bytes, Path], settings: EncryptSettings = None):
        """Decryption

        Args:
            key (RSA.RsaKey, bytes, Path): private RSA key, this argument can passed as:
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
        self._key = key

    def decrypt(self, msg: bytes) -> bytes:
        result = BytesIO()
        self.decrypt_stream(msg, result)

        result.seek(0)
        return result.read()

    def decrypt_stream(self, input_stream: Union[BinaryIO, bytes], output_stream: BinaryIO):

        if isinstance(input_stream, bytes):
            input_stream = BytesIO(input_stream)
            input_stream.seek(0)

        enc_session_key = input_stream.read(self._key.size_in_bytes())
        nonce = input_stream.read(self._settings.nonce_len)

        # Decrypt the session key with the private RSA key
        session_key = PKCS1_OAEP.new(self._key).decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)

        tag_len = self._settings.tag_len
        chunked_streaming = ChunkedStreaming()
        for c in chunked_streaming.chunked_padding_stream(input_stream, padding_end=tag_len):
            output_stream.write(cipher_aes.decrypt(c))

        tag = chunked_streaming.padding
        try:
            cipher_aes.verify(tag)
        except ValueError as e:
            raise MacCheckFailed() from e
