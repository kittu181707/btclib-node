# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The RPCs that read the UTXO set whole: `scantxoutset`.

Core's `scantxoutset` is in `src/rpc/blockchain.cpp`, with the descriptor
arguments in `src/rpc/util.cpp` and `InferScript` in
`src/script/descriptor.cpp`, all at bitcoin/bitcoin@9be056a8a7, the v31.1
tag. Each handler has `rpc.callbacks`' signature and runs on `Node`'s
thread (`ARCHITECTURE.md`).

A scan is a generator that `rpc.main` resumes on each pass of `Node`'s
loop. It walks the stored coins `_STEP` at a time and yields between
steps, so the loop serves other requests meanwhile, `status` and `abort`
among them. Core runs the scan on an HTTP worker and the two others on
workers of their own, which share atomics; here all three run on `Node`'s
thread, and the scan's state needs no lock.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any
from weakref import WeakKeyDictionary

from bitcoin_core_rpc import RPCErrorCode
from btclib.exceptions import BTClibException, BTClibValueError
from btclib.hashes import hash160
from btclib_wallet.bip32 import BIP32KeyOrigin, fingerprint
from btclib_wallet.descriptors import (
    ComboDescriptor,
    Descriptor,
    KeyExpression,
    MultiA,
    MultiDescriptor,
    PkDescriptor,
    PkhDescriptor,
    ShDescriptor,
    TrDescriptor,
    WpkhDescriptor,
    WshDescriptor,
    add_checksum,
    multipath_descriptors,
    strip_checksum,
)
from btclib_wallet.descriptors import parse as parse_descriptor

# private until btclib-org/btclib-wallet#256 publishes it
from btclib_wallet.descriptors.descriptors import _mapped_keys

from btclib_node.block_db import Coin
from btclib_node.rpc.connection import btc_amount
from btclib_node.rpc.errors import RpcError, json_type_name, type_errors
from btclib_node.rpc.help import HELP_TEXT

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator

    from btclib_node import Node
    from btclib_node.rpc.connection import RpcConnection

__all__ = ["scan_tx_out_set"]

# Coins read between two yields, and between two looks at `terminate_flag`
# and the abort flag. Core looks every 8192 coins (`FindScriptPubKey`),
# which is a longer pause than `Node`'s loop should be asked to wait here.
_STEP = 1024

# Keys derived between two yields of the expansion: a key is an extended
# key's derivation, about a tenth of a millisecond, so a step stays near
# the walk's few milliseconds however many keys a descriptor has
_EXPAND_STEP = 16

# `FindScriptPubKey` updates the progress every 256 coins
_PROGRESS_EVERY = 256

# `RPCArg::Default{1000}`, the range a ranged descriptor is expanded over
_DEFAULT_RANGE_END = 1000

# `ParseDescriptorRange`'s own bound
_MAX_RANGE_SIZE = 1_000_000

_INT64 = range(-(2**63), 2**63)


@dataclass
class _Scan:
    """The scan `Node` runs, as `status` and `abort` see it."""

    progress: int = 0
    abort: bool = False


# `g_scan_in_progress`, `g_scan_progress` and `g_should_abort_scan` in Core,
# which are process globals; one scan at a time per node here
_scans: WeakKeyDictionary[Node, _Scan] = WeakKeyDictionary()


@dataclass(frozen=True)
class _Source:
    """A parsed descriptor, and the private keys it was read with."""

    descriptor: Descriptor
    prv_keys: dict[str, str]


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _int64(value: object) -> int:
    """`UniValue::getInt<int64_t>()`: an integer number in range."""
    if not isinstance(value, int) or value not in _INT64:
        raise RpcError(RPCErrorCode.MISC_ERROR, "JSON integer out of range")
    return value


def _range(value: object) -> tuple[int, int]:
    """Return a `range` as Core's `ParseDescriptorRange` reads it."""
    if _is_number(value):
        low, high = 0, _int64(value)
    elif (
        isinstance(value, list)
        and len(value) == 2  # noqa: PLR2004
        and all(_is_number(end) for end in value)
    ):
        low, high = _int64(value[0]), _int64(value[1])
        if low > high:
            raise RpcError(
                RPCErrorCode.INVALID_PARAMETER,
                "Range specified as [begin,end] must not have begin after end",
            )
    else:
        raise RpcError(
            RPCErrorCode.INVALID_PARAMETER,
            "Range must be specified as end or as [begin,end]",
        )
    if low < 0:
        raise RpcError(
            RPCErrorCode.INVALID_PARAMETER, "Range should be greater or equal than 0"
        )
    if high >> 31:
        raise RpcError(RPCErrorCode.INVALID_PARAMETER, "End of range is too high")
    if high >= low + _MAX_RANGE_SIZE:
        raise RpcError(RPCErrorCode.INVALID_PARAMETER, "Range is too large")
    return low, high


def _parse(node: Node, text: str) -> list[_Source]:
    """Parse `text`, which is one descriptor or a multipath one's several.

    Core's `Parse`. Its message names what it found wrong and is
    btclib_wallet's here, which words it differently.
    """
    if any(key.count("<") > 1 for key in re.split(r"[(),{}]", text)):
        raise RpcError(
            RPCErrorCode.INVALID_ADDRESS_OR_KEY,
            "Multiple multipath key path specifiers found",
        )
    prv_keys: dict[str, str] = {}
    try:
        sources = [
            _Source(parse_descriptor(one, node.chain.name, prv_keys), prv_keys)
            for one in multipath_descriptors(strip_checksum(text))
        ]
    except BTClibException as err:
        raise RpcError(RPCErrorCode.INVALID_ADDRESS_OR_KEY, str(err)) from err
    return sources


def _scan_object(
    node: Node, scan_object: object
) -> tuple[list[_Source], int, int, str]:
    """Return a scan object's descriptors, expansion indexes and text.

    Core's `EvalDescriptorStringOrObject`.
    """
    low, high = 0, _DEFAULT_RANGE_END
    if isinstance(scan_object, str):
        text = scan_object
    elif isinstance(scan_object, dict):
        desc = scan_object.get("desc")
        if desc is None:
            raise RpcError(
                RPCErrorCode.INVALID_PARAMETER,
                "Descriptor needs to be provided in scan object",
            )
        if not isinstance(desc, str):
            raise RpcError(
                RPCErrorCode.TYPE_ERROR,
                f"JSON value of type {json_type_name(desc)} "
                "is not of expected type string",
            )
        text = desc
        if scan_object.get("range") is not None:
            low, high = _range(scan_object["range"])
    else:
        raise RpcError(
            RPCErrorCode.INVALID_PARAMETER,
            "Scan object needs to be either a string or an object",
        )
    sources = _parse(node, text)
    if not sources[0].descriptor.is_ranged:
        low = high = 0
    return sources, low, high, text


def _concrete(
    key: KeyExpression, index: int, network: str, prv_keys: dict[str, str]
) -> KeyExpression:
    """Return `key` as the one public key it is at `index`, with its origin.

    What `InferPubkey` finds in the provider the expansion filled: the key
    itself, behind an origin that is the key's own where it was given one,
    and otherwise the extended key's fingerprint or the key's own.
    """
    sec = key.sec(index, network, prv_keys)
    if key.pub_key is not None or key.participants:
        # a `musig` aggregate is a key of no extended key's
        origin = key.origin or BIP32KeyOrigin(hash160(sec)[:4], [])
    else:
        steps = list(key.der_path)
        if key.wildcard is not None:
            steps.append(key.wildcard + index)
        origin = BIP32KeyOrigin(
            key.origin.master_fingerprint if key.origin else fingerprint(key.xkey),
            [*(key.origin.der_path if key.origin else []), *steps],
        )
    return KeyExpression(origin=origin, pub_key=sec, x_only=key.x_only)


def _unsorted(value: Any) -> Any:  # noqa: ANN401
    """Return `value` with each sorted multisig as the `multi` Core infers.

    The script holds the keys in order, and `InferScript` reads them back
    in that order, with no word of the sorting.
    """
    if isinstance(value, (MultiDescriptor, MultiA)):
        keys = sorted(value.keys, key=lambda key: key.pub_key or b"")
        return replace(value, keys=tuple(keys), sort=False) if value.sort else value
    if isinstance(value, (ShDescriptor, WshDescriptor)):
        return replace(value, inner=_unsorted(value.inner))
    if isinstance(value, TrDescriptor) and value.tree is not None:
        return replace(value, tree=_unsorted(value.tree))
    return value


def _inferred(source: _Source, index: int, position: int, network: str) -> str:
    """Return the descriptor `InferDescriptor` answers for a matched script.

    `position` is the script's place among those the descriptor describes
    at `index`: `combo` describes up to four and the match is one of them.
    """
    prv_keys = source.prv_keys
    descriptor = _mapped_keys(
        source.descriptor, lambda key: _concrete(key, index, network, prv_keys)
    )
    if isinstance(descriptor, ComboDescriptor):
        key = descriptor.key
        fragments: list[Descriptor] = [
            PkDescriptor(key=key, network=network),
            PkhDescriptor(key=key, network=network),
            WpkhDescriptor(key=key, network=network),
        ]
        fragments.append(ShDescriptor(inner=fragments[2], network=network))
        descriptor = fragments[position]
    if isinstance(descriptor, TrDescriptor):
        # the key of a `tr` is x-only, a `musig` aggregate's being 33 octets
        descriptor = replace(
            descriptor, internal_key=replace(descriptor.internal_key, x_only=True)
        )
    return add_checksum(str(_unsorted(descriptor)))


def scan_tx_out_set(
    node: Node, conn: RpcConnection, params: list[Any]
) -> dict[str, Any] | bool | Generator[bool, None, dict[str, Any]] | None:
    """Answer `scantxoutset`: report on, stop, or run a scan of the UTXO set.

    `start` searches the stored coins for the scripts of the scan objects'
    descriptors, a ranged one expanded over its `range` and `combo` over
    its four scripts, and answers each coin found with the descriptor that
    describes its script. A coin is listed once, as Core's `std::map` has
    it, and is found in the set as it was when the scan began: the
    chainstate is flushed and a cursor opened, whose view RocksDB fixes
    (`UtxoIndex.cursor`). `success` is false for a scan that was aborted
    or met a record it cannot read, and the rest of the answer is what was
    found by then. A coin's `desc` is one of Core's `InferDescriptor`,
    built from the descriptor that matched it, so a key carries its
    origin, a `sortedmulti` is a `multi`, and a `combo` is the one of its
    four scripts that matched. What Core infers from the script alone, a
    miniscript or a taproot tree, is the descriptor as written with its
    keys made concrete, and a tree of several leaves may be in another
    order than Core's.

    Core's parse errors are worded by its own parser: the code is Core's
    and the message is btclib_wallet's.
    """
    if not params:
        raise RpcError(RPCErrorCode.MISC_ERROR, HELP_TEXT["scantxoutset"])
    action = params[0]
    scan_objects = params[1] if len(params) > 1 else None
    mismatches: list[tuple[int, str, object, str]] = []
    if not isinstance(action, str):
        mismatches.append((1, "action", action, "string"))
    if scan_objects is not None and not isinstance(scan_objects, list):
        mismatches.append((2, "scanobjects", scan_objects, "array"))
    if mismatches:
        raise type_errors(*mismatches)

    scan = _scans.get(node)
    if action == "status":
        return None if scan is None else {"progress": scan.progress}
    if action == "abort":
        if scan is None:
            return False
        scan.abort = True
        return True
    if action == "start":
        return _start(node, params)
    raise RpcError(RPCErrorCode.INVALID_PARAMETER, f"Invalid action '{action}'")


def _start(node: Node, params: list[Any]) -> Generator[bool, None, dict[str, Any]]:
    """Run `scantxoutset`'s `start`, `_Scan` held for as long as it runs."""
    if node in _scans:
        raise RpcError(
            RPCErrorCode.INVALID_PARAMETER,
            'Scan already in progress, use action "abort" or "status"',
        )
    scan = _scans[node] = _Scan()
    try:
        return (yield from _scan(node, scan, params))
    finally:
        del _scans[node]


def _interruption_point(node: Node) -> None:
    """Raise where the node is stopping, as Core's interruption point does."""
    if node.terminate_flag.is_set():
        raise RpcError(RPCErrorCode.CLIENT_NOT_CONNECTED, "Shutting down")


def _expand(
    node: Node, scan: _Scan, scan_objects: list[Any]
) -> Generator[bool, None, dict[bytes, tuple[_Source, int, int]]]:
    """Return the scripts the scan objects describe."""
    # `descriptors.emplace` keeps the first descriptor a script is found for
    needles: dict[bytes, tuple[_Source, int, int]] = {}
    keys = 0
    for scan_object in scan_objects:
        sources, low, high, text = _scan_object(node, scan_object)
        for index in range(low, high + 1):
            for source in sources:
                try:
                    scripts = source.descriptor.script_pub_keys(index, source.prv_keys)
                except BTClibException as err:
                    raise RpcError(
                        RPCErrorCode.INVALID_ADDRESS_OR_KEY,
                        f"Cannot derive script without private keys: '{text}'",
                    ) from err
                for position, script in enumerate(scripts):
                    needles.setdefault(script.script, (source, index, position))
                keys += max(1, len(source.descriptor.key_expressions))
            if keys >= _EXPAND_STEP:
                keys = 0
                yield True
                _interruption_point(node)
    return needles


def _walk(
    node: Node,
    scan: _Scan,
    cursor: Iterator[tuple[bytes, bytes]],
    needles: dict[bytes, tuple[_Source, int, int]],
    found: dict[tuple[bytes, int], Coin],
) -> Generator[bool, None, tuple[bool, int]]:
    """Read `cursor`'s coins into `found` where a script is `needles`'.

    Return whether the walk was whole, and the coins read: Core's
    `FindScriptPubKey`.
    """
    prefix = len(b"utxo-")
    count = 0
    for key, value in cursor:
        try:
            coin = Coin.parse(value, check_validity=False)
        except BTClibValueError:
            return False, count
        count += 1
        if count % _STEP == 0:
            yield True
            _interruption_point(node)
            if scan.abort:
                return False, count
        if count % _PROGRESS_EVERY == 0:
            scan.progress = int(
                (0x100 * key[prefix] + key[prefix + 1]) * 100.0 / 65536.0 + 0.5
            )
        if coin.tx_out.script_pub_key.script in needles:
            out_point = key[prefix:]
            found[out_point[:32], int.from_bytes(out_point[32:], "little")] = coin
    scan.progress = 100
    return True, count


def _scan(
    node: Node, scan: _Scan, params: list[Any]
) -> Generator[bool, None, dict[str, Any]]:
    """Expand the scan objects, walk the coins and answer, as `start` does."""
    if len(params) < 2:  # noqa: PLR2004
        raise RpcError(
            RPCErrorCode.MISC_ERROR,
            "scanobjects argument is required for the start action",
        )
    if params[1] is None:
        raise RpcError(
            RPCErrorCode.TYPE_ERROR,
            "JSON value of type null is not of expected type array",
        )
    needles = yield from _expand(node, scan, params[1])
    # `g_should_abort_scan = false`: an abort during the expansion is lost
    scan.abort = False
    node.chainstate.flush()
    hashes = list(node.chainstate.block_index.active_chain)
    cursor = node.chainstate.utxo_index.cursor()
    found: dict[tuple[bytes, int], Coin] = {}
    walked = yield from _walk(node, scan, cursor, needles, found)
    success, count = walked
    tip_height = len(hashes) - 1
    unspents: list[dict[str, Any]] = []
    total = 0
    # `std::map<COutPoint, Coin>`: by txid as stored, then by index
    for (txid, vout), coin in sorted(found.items(), key=lambda item: item[0]):
        script = coin.tx_out.script_pub_key.script
        source, index, position = needles[script]
        total += coin.tx_out.value
        unspents.append(
            {
                "txid": txid[::-1],
                "vout": vout,
                "scriptPubKey": script,
                "desc": _inferred(source, index, position, node.chain.name),
                "amount": btc_amount(coin.tx_out.value),
                "coinbase": coin.is_coinbase,
                "height": coin.height,
                "blockhash": hashes[coin.height],
                "confirmations": tip_height - coin.height + 1,
            }
        )
        if len(unspents) % _STEP == 0:
            yield True
    return {
        "success": success,
        "txouts": count,
        "height": tip_height,
        "bestblock": hashes[-1],
        "unspents": unspents,
        "total_amount": btc_amount(total),
    }
