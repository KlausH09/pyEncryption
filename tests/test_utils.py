import pytest

from io import BytesIO
from pathlib import Path

from Crypto.PublicKey import RSA

import pyencryption

_messages = {
    "short": b"foobar",
    "long": b"foobar" * 1000,
}


class TestChunkedStreaming:

    @pytest.mark.parametrize("msg", ["short", "long"])
    @pytest.mark.parametrize("chunk_size", [6, 37])
    def test_chunked_stream(self, msg: str, chunk_size: int):
        msg = _messages[msg]

        expected_nof_chunks = len(msg) // chunk_size
        expected_chunk_sizes = [chunk_size] * expected_nof_chunks
        if len(msg) % chunk_size > 0:
            expected_nof_chunks += 1
            expected_chunk_sizes.append(len(msg) % chunk_size)

        msg_stream = BytesIO(msg)
        msg_stream.seek(0)

        chunks = [c for c in pyencryption.utils.ChunkedStreaming.chunked_stream(msg_stream, chunk_size)]

        assert len(chunks) == expected_nof_chunks
        assert all(n == len(c) for n, c in zip(expected_chunk_sizes, chunks))

        msg_ = b''
        for c in chunks:
            msg_ += c
        assert msg == msg_

    @pytest.mark.parametrize("msg", ["short", "long"])
    @pytest.mark.parametrize("chunk_size", [6, 37])
    @pytest.mark.parametrize("padding_size", [0, 6])
    def test_chunked_padding_stream(self, msg: str, chunk_size: int, padding_size: int):
        msg_all = _messages[msg]
        if padding_size == 0:
            msg, padding = msg_all, b''
        else:
            msg, padding = msg_all[:-padding_size], msg_all[-padding_size:]

        expected_nof_chunks = len(msg) // chunk_size
        expected_chunk_sizes = [chunk_size] * expected_nof_chunks
        if len(msg) % chunk_size > 0:
            expected_nof_chunks += 1
            expected_chunk_sizes.append(len(msg) % chunk_size)

        msg_stream = BytesIO(msg_all)
        msg_stream.seek(0)

        chunked_streamer = pyencryption.utils.ChunkedStreaming()
        chunks = [c for c in chunked_streamer.chunked_padding_stream(msg_stream, padding_size, chunk_size)]
        assert chunked_streamer.padding == padding

        assert len(chunks) == expected_nof_chunks
        assert all(n == len(c) for n, c in zip(expected_chunk_sizes, chunks))

        msg_ = b''
        for c in chunks:
            msg_ += c
        assert msg == msg_


def test_save_random_RSA_key_pair(tmpdir):
    path_key_private = Path(tmpdir) / "private.pem"
    path_key_public = Path(tmpdir) / "public.pem"

    pyencryption.save_random_RSA_key_pair(path_key_private, path_key_public)

    with open(path_key_private, "rb") as fd:
        key_private = RSA.import_key(fd.read())

    with open(path_key_public, "rb") as fd:
        key_public = RSA.import_key(fd.read())

    assert key_private.has_private()
    assert not key_public.has_private()
    assert key_private != key_public
    assert key_private.public_key() == key_public
