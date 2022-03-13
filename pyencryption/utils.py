"""Helper functions
"""
from typing import BinaryIO
from pathlib import Path
from dataclasses import dataclass

from Crypto.PublicKey import RSA


@dataclass(frozen=True)
class EncryptSettings:
    """Settings for encryption"""
    aes_len: int = 16  # 16 (AES-128), 24 (AES-192), or 32 (AES-256)
    nonce_len: int = 16
    tag_len: int = 16


class ChunkedStreaming:
    def __init__(self):
        self._padding = None

    @property
    def padding(self) -> bytes:
        return self._padding

    @staticmethod
    def chunked_stream(stream: BinaryIO, chunk_size: int = 1024):
        while True:
            chunk = stream.read(chunk_size)
            if len(chunk) == 0:
                break
            yield chunk

    def chunked_padding_stream(self, stream: BinaryIO, padding_end: int, chunk_size: int = 1024):
        buffer_size_max = chunk_size + padding_end
        buffer = b''
        is_end = False
        while True:
            while not is_end and buffer_size_max - len(buffer) > 0:
                tmp = stream.read(buffer_size_max - len(buffer))
                buffer += tmp
                is_end = len(tmp) == 0

            if padding_end == 0:
                chunk, buffer = buffer, b''
            else:
                chunk, buffer = buffer[:-padding_end], buffer[-padding_end:]
            if len(chunk) > 0:
                yield chunk
            if is_end:
                self._padding = buffer
                break


def save_random_RSA_key_pair(dest_private_key: Path = Path("./private.pem"),
                             dest_public_key: Path = Path("./public.pem")):
    """Create and save a random RSA key pair

    Args:
        dest_private_key (Path): path to save the private key
        dest_public_key (Path): path to save the public key
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.public_key().export_key()
    with open(dest_private_key, 'wb') as fd:
        fd.write(private_key)
    with open(dest_public_key, 'wb') as fd:
        fd.write(public_key)
