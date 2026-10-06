# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The snapshot file's pieces, against what `bitcoind` v31.1.0 writes.

The coin bytes are read from a dump bitcoind made of coinbases paying
each script; `tests/integration/dumptxoutset_test.py` holds a whole file
to bitcoind's own.
"""

import pytest
from btclib.hashes import hash160
from btclib.tx.tx_out import TxOut

from btclib_node.block_db import Coin
from btclib_node.snapshot import (
    compress_amount,
    compress_script,
    core_varint,
    serialize_coin,
    serialize_metadata,
    serialize_tx_coins,
)

KEY = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
UNCOMPRESSED = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
KEY_HASH = hash160(KEY)


@pytest.mark.parametrize(
    ("number", "encoded"),
    [
        (0, "00"),
        (127, "7f"),
        (128, "8000"),
        (255, "807f"),
        (256, "8100"),
        (16384, "ff00"),
    ],
)
def test_varint_is_core_s_and_not_a_compact_size(number: int, encoded: str) -> None:
    """`serialize_tests.cpp`'s vectors: a number has one encoding."""
    assert core_varint(number).hex() == encoded


@pytest.mark.parametrize(
    ("amount", "compressed"),
    [
        (0, 0),
        (1, 1),
        (100_000_000, 9),
        (5_000_000_000, 50),
        (21_000_000 * 100_000_000, 21_000_000),
        (123_456_789, 1 + (12_345_678 * 9 + 8) * 10),
    ],
)
def test_amount_compression(amount: int, compressed: int) -> None:
    """Trailing zeros are an exponent, up to nine of them."""
    assert compress_amount(amount) == compressed


@pytest.mark.parametrize(
    ("script", "compressed"),
    [
        (b"\x76\xa9\x14" + KEY_HASH + b"\x88\xac", "00" + KEY_HASH.hex()),
        (
            b"\xa9\x14" + hash160(b"\x00\x14" + KEY_HASH) + b"\x87",
            "01bcfeb728b584253d5f3f70bcb780e9ef218a68f4",
        ),
        (b"\x21" + KEY + b"\xac", KEY.hex()),
        (b"\x41" + UNCOMPRESSED + b"\xac", "04" + UNCOMPRESSED[1:33].hex()),
        (b"\x00\x14" + KEY_HASH, "1c0014" + KEY_HASH.hex()),
        (b"\x51", "0751"),
        (b"", "06"),
    ],
)
def test_script_compression(script: bytes, compressed: str) -> None:
    """The three standard shapes are a type byte and a hash or a coordinate."""
    assert compress_script(script).hex() == compressed


def test_an_uncompressed_key_off_the_curve_is_a_script_as_it_is() -> None:
    """Core compresses it only where `IsFullyValid`."""
    script = b"\x41" + b"\x04" + b"\x00" * 31 + b"\x05" + bytes(32) + b"\xac"
    assert compress_script(script) == core_varint(len(script) + 6) + script


def test_an_odd_y_uncompressed_key_is_type_five() -> None:
    """The parity of y is in the type byte: `-G` has y odd."""
    field = 2**256 - 2**32 - 977
    y = (field - int.from_bytes(UNCOMPRESSED[33:], "big")).to_bytes(32, "big")
    script = b"\x41" + UNCOMPRESSED[:33] + y + b"\xac"
    assert compress_script(script).hex() == "05" + UNCOMPRESSED[1:33].hex()


def test_a_coin_is_height_and_coinbase_then_amount_then_script() -> None:
    """A coinbase of height 2 paying a key: `05 32` and the key."""
    out = TxOut(5_000_000_000, b"\x21" + KEY + b"\xac")
    coin = Coin(out, 2, is_coinbase=True)
    assert serialize_coin(coin).hex() == "0532" + KEY.hex()
    assert serialize_coin(Coin(out, 2, is_coinbase=False))[0] == 0x04


def test_a_transaction_is_its_txid_and_each_coin_by_index() -> None:
    """A compact size of the count, then each index and coin."""
    out = TxOut(1, b"\x51")
    coin = Coin(out, 1, is_coinbase=False)
    txid = bytes(range(32))
    assert serialize_tx_coins(txid, [(0, coin), (300, coin)]) == (
        txid
        + b"\x02"
        + b"\x00"
        + serialize_coin(coin)
        + b"\xfd\x2c\x01"
        + serialize_coin(coin)
    )


def test_the_metadata_is_magic_version_network_hash_and_count() -> None:
    """The hash is written in the order a transaction id is, not displayed."""
    base = bytes(range(32))
    assert serialize_metadata(b"\xfa\xbf\xb5\xda", base, 6).hex() == (
        "7574786fff0200fabfb5da" + base[::-1].hex() + "0600000000000000"
    )
