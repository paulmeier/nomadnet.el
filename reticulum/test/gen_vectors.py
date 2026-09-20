#!/usr/bin/env python3
"""Generate LXMF reference vectors from the Python implementation.

Reads test/vectors.json, replaces its "lxmf" section with values recorded
from the installed RNS and LXMF packages, and writes the file back.  The
other sections are left untouched; they were recorded once (see README.md).

Usage: python3 gen_vectors.py   (needs the rns and lxmf packages)
"""

import hashlib
import json
import os
import time

import RNS
import RNS.vendor.umsgpack as msgpack
import LXMF
import LXMF.LXStamper as LXStamper
from LXMF import LXMessage

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors.json")


def hexs(b):
    return None if b is None else b.hex()


def identity(seed):
    return RNS.Identity.from_bytes(hashlib.sha512(seed).digest())


def delivery(ident):
    return RNS.Destination(ident, RNS.Destination.OUT, RNS.Destination.SINGLE, LXMF.APP_NAME, "delivery")


def stamp_for(message_id, cost):
    """Single-threaded stamp search; cost is small so this is quick."""
    workblock = LXStamper.stamp_workblock(message_id)
    while True:
        stamp = os.urandom(LXStamper.STAMP_SIZE)
        if LXStamper.stamp_valid(stamp, cost, workblock):
            return stamp


def message_vector(name, dest, src, content, title, fields, timestamp, stamp_cost=None):
    m = LXMessage(dest, src, content, title, fields=fields)
    m.timestamp = timestamp
    if stamp_cost is not None:
        m.pack()
        stamp = stamp_for(m.hash, stamp_cost)
        m.packed = None
        m.stamp = stamp
        m.stamp_cost = stamp_cost
        m.defer_stamp = False
        m.pack()
        assert m.packed[96:] == msgpack.packb([timestamp, m.title, m.content, m.fields, stamp])
    else:
        m.pack()
    return {
        "name": name,
        "packed": hexs(m.packed),
        "hash": hexs(m.hash),
        "signature": hexs(m.signature),
        "timestamp": timestamp,
        "title": hexs(m.title),
        "content": hexs(m.content),
        "fields": hexs(msgpack.packb(m.fields)),
        "stamp": hexs(m.stamp),
        "stamp_cost": stamp_cost,
    }


def main():
    with open(VECTORS) as f:
        vectors = json.load(f)

    src_id = identity(b"lxmf-source")
    dst_id = identity(b"lxmf-destination")
    src = delivery(src_id)
    dst = delivery(dst_id)
    ts = 1758400000.25

    messages = [
        message_vector("plain", dst, src, "Hello from Python", "Greeting", None, ts),
        message_vector("empty", dst, src, "", "", None, ts + 1),
        message_vector("unicode", dst, src, "Grüße 🌍 — héllo", "Ünïcode", None, ts + 2),
        message_vector("fields", dst, src, "Rendered as micron", "With fields",
                       {LXMF.FIELD_RENDERER: LXMF.RENDERER_MICRON,
                        LXMF.FIELD_REPLY_TO: bytes(range(32)),
                        0x1234: [1, "two", 3.5]}, ts + 3),
        message_vector("stamped", dst, src, "This one carries a stamp", "Stamped", None, ts + 4,
                       stamp_cost=8),
        message_vector("stamped fields", dst, src, "Stamp and fields", "",
                       {LXMF.FIELD_RENDERER: LXMF.RENDERER_MARKDOWN}, ts + 5, stamp_cost=8),
    ]

    # Opportunistic payloads: the packed message without the leading
    # destination hash, encrypted to the destination identity, once with
    # the identity key and once with a ratchet.
    ratchet_prv = hashlib.sha256(b"lxmf-ratchet").digest()
    ratchet_pub = RNS.Identity._ratchet_public_bytes(ratchet_prv)
    plain = messages[0]
    packed = bytes.fromhex(plain["packed"])
    opportunistic = {
        "message": plain["name"],
        "encrypted": hexs(dst_id.encrypt(packed[LXMessage.DESTINATION_LENGTH:])),
        "encrypted_ratchet": hexs(dst_id.encrypt(packed[LXMessage.DESTINATION_LENGTH:], ratchet=ratchet_pub)),
        "ratchet_private": hexs(ratchet_prv),
        "ratchet_public": hexs(ratchet_pub),
        "ratchet_id": hexs(RNS.Identity._get_ratchet_id(ratchet_pub)),
    }

    app_data = [
        {"name": "name and cost", "display_name": "Emacs Peer", "stamp_cost": 12,
         "packed": hexs(msgpack.packb(["Emacs Peer".encode("utf-8"), 12, [LXMF.SF_COMPRESSION]]))},
        {"name": "name only", "display_name": "Anonymous Peer", "stamp_cost": None,
         "packed": hexs(msgpack.packb(["Anonymous Peer".encode("utf-8"), None, [LXMF.SF_COMPRESSION]]))},
        {"name": "no name", "display_name": None, "stamp_cost": 4,
         "packed": hexs(msgpack.packb([None, 4, [LXMF.SF_COMPRESSION]]))},
        {"name": "legacy string", "display_name": "Old Peer", "stamp_cost": None,
         "packed": hexs("Old Peer".encode("utf-8")), "legacy": True},
    ]
    for entry in app_data:
        data = bytes.fromhex(entry["packed"])
        assert LXMF.display_name_from_app_data(data) == entry["display_name"]
        assert LXMF.stamp_cost_from_app_data(data) == entry["stamp_cost"]

    # Ratchet file in RNS.Destination's persisted format.
    ratchets = [hashlib.sha256(b"ratchet-%d" % i).digest() for i in range(3)]
    packed_ratchets = msgpack.packb(ratchets)
    ratchet_file = msgpack.packb({"signature": dst_id.sign(packed_ratchets), "ratchets": packed_ratchets})
    tampered = bytearray(ratchet_file)
    tampered[-1] ^= 0x01

    vectors["lxmf"] = {
        "source_private": hexs(src_id.get_private_key()),
        "source_public": hexs(src_id.get_public_key()),
        "source_hash": hexs(src.hash),
        "destination_private": hexs(dst_id.get_private_key()),
        "destination_public": hexs(dst_id.get_public_key()),
        "destination_hash": hexs(dst.hash),
        "messages": messages,
        "opportunistic": opportunistic,
        "app_data": app_data,
        "ratchet_file": {
            "ratchets": [hexs(r) for r in ratchets],
            "packed": hexs(ratchet_file),
            "tampered": hexs(bytes(tampered)),
        },
        "versions": {"rns": RNS.__version__, "lxmf": LXMF.__version__},
    }

    with open(VECTORS, "w") as f:
        json.dump(vectors, f, indent=1)
        f.write("\n")
    print("wrote %d LXMF message vectors to %s" % (len(messages), VECTORS))


if __name__ == "__main__":
    main()
