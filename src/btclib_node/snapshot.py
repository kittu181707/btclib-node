# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The UTXO set snapshot file `dumptxoutset` writes.

Core's `SnapshotMetadata` (`src/node/utxo_snapshot.h`) and the coin
serialization of `WriteUTXOSnapshot` (`src/rpc/blockchain.cpp`) with
`Coin::Serialize` (`src/coins.h`), `TxOutCompression` and
`ScriptCompression` (`src/compressor.h`, `src/compressor.cpp`), all at
bitcoin/bitcoin@9be056a8a7, the v31.1 tag.

The file is the metadata, then each transaction's unspent outputs: its
txid, how many there are, and for each the output's index and the coin.
A coin is its height and coinbase flag, its amount and its script, the
last two compressed. Core's `VARINT` is not a compact size: each byte
but the last carries a continuation bit, and the number is less one for
each byte after the first, so that every number has one encoding.

btclib has neither compression, which is generic and so btclib's to have
(btclib-org/btclib#2558).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from btclib import var_int
from btclib_ecc.curves import point_from_pub_key, secp256k1
from btclib_ecc.exceptions import BTClibEccException

if TYPE_CHECKING:
    from collections.abc import Iterable

    from btclib_node.block_db import Coin

__all__ = [
    "compress_amount",
    "compress_script",
    "core_varint",
    "serialize_coin",
    "serialize_metadata",
    "serialize_tx_coins",
]

# `SNAPSHOT_MAGIC_BYTES` and `SnapshotMetadata::VERSION`
_MAGIC = b"utxo\xff"
_VERSION = 2

# `ScriptCompression::nSpecialScripts`: sizes below it name a compressed form
_SPECIAL_SCRIPTS = 6

_OP_DUP, _OP_HASH160, _OP_EQUALVERIFY, _OP_EQUAL, _OP_CHECKSIG = (
    0x76,
    0xA9,
    0x88,
    0x87,
    0xAC,
)

# the seven bits of a `VARINT` byte that carry the number
_VARINT_PAYLOAD = 0x7F

_P2PKH_SIZE = 25
_P2SH_SIZE = 23
_COMPRESSED_PUBKEY_SCRIPT_SIZE = 35
_UNCOMPRESSED_PUBKEY_SCRIPT_SIZE = 67


def core_varint(number: int) -> bytes:
    """Return `number` as Core's `VARINT` writes it (`src/serialize.h`)."""
    out = [number & _VARINT_PAYLOAD]
    while number > _VARINT_PAYLOAD:
        number = (number >> 7) - 1
        out.append((number & _VARINT_PAYLOAD) | 0x80)
    return bytes(reversed(out))


def compress_amount(amount: int) -> int:
    """Return Core's `CompressAmount`: trailing zeros made an exponent."""
    if amount == 0:
        return 0
    exponent = 0
    while amount % 10 == 0 and exponent < 9:  # noqa: PLR2004
        amount //= 10
        exponent += 1
    if exponent < 9:  # noqa: PLR2004
        digit = amount % 10
        amount //= 10
        return 1 + (amount * 9 + digit - 1) * 10 + exponent
    return 1 + (amount - 1) * 10 + 9


def compress_script(script: bytes) -> bytes:
    """Return a script as `ScriptCompression::Ser` writes it.

    A pay-to-pubkey-hash, a pay-to-script-hash and a pay-to-pubkey of a
    key that is on the curve are a type byte and the hash or the x
    coordinate. Any other script is its size plus six, then the script.
    """
    size = len(script)
    if (
        size == _P2PKH_SIZE
        and script[0] == _OP_DUP
        and script[1] == _OP_HASH160
        and script[2] == 20  # noqa: PLR2004
        and script[23] == _OP_EQUALVERIFY
        and script[24] == _OP_CHECKSIG
    ):
        return b"\x00" + script[3:23]
    if (
        size == _P2SH_SIZE
        and script[0] == _OP_HASH160
        and script[1] == 20  # noqa: PLR2004
        and script[22] == _OP_EQUAL
    ):
        return b"\x01" + script[2:22]
    if (
        size == _COMPRESSED_PUBKEY_SCRIPT_SIZE
        and script[0] == 33  # noqa: PLR2004
        and script[34] == _OP_CHECKSIG
        and script[1] in (0x02, 0x03)
    ):
        return script[1:34]
    if (
        size == _UNCOMPRESSED_PUBKEY_SCRIPT_SIZE
        and script[0] == 65  # noqa: PLR2004
        and script[66] == _OP_CHECKSIG
        and script[1] == 0x04  # noqa: PLR2004
        and _is_on_curve(script[1:66])
    ):
        return bytes([0x04 | (script[65] & 1)]) + script[2:34]
    return core_varint(size + _SPECIAL_SCRIPTS) + script


def _is_on_curve(pub_key: bytes) -> bool:
    """Say whether an uncompressed public key is a point of the curve."""
    try:
        point_from_pub_key(pub_key, secp256k1)
    except BTClibEccException:
        return False
    return True


def serialize_coin(coin: Coin) -> bytes:
    """Return `Coin::Serialize`: height and coinbase, amount, script."""
    code = coin.height * 2 + int(coin.is_coinbase)
    return (
        core_varint(code)
        + core_varint(compress_amount(coin.tx_out.value))
        + compress_script(coin.tx_out.script_pub_key.script)
    )


def serialize_metadata(magic: bytes, base_hash: bytes, coins_count: int) -> bytes:
    """Return `SnapshotMetadata`, `base_hash` as a block hash is displayed."""
    return (
        _MAGIC
        + _VERSION.to_bytes(2, "little")
        + magic
        + base_hash[::-1]
        + coins_count.to_bytes(8, "little")
    )


def serialize_tx_coins(txid: bytes, coins: Iterable[tuple[int, Coin]]) -> bytes:
    """Return one transaction's coins, `txid` as the coins key holds it."""
    rows = [var_int.serialize(n) + serialize_coin(coin) for n, coin in coins]
    return txid + var_int.serialize(len(rows)) + b"".join(rows)
