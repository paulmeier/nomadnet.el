# Native Nomad Network client in Emacs Lisp

Goal: a Nomad Network **client** that runs entirely inside Emacs, with no
Python process. Reticulum, LXMF and the nomadnet client behaviour are
reimplemented in Emacs Lisp. The Python bridge that bootstrapped the project
was removed on 2026-09-20; the repository contains only Emacs Lisp.

Scope is deliberately *client*: browsing nodes, LXMF conversations, announce
stream and directory, propagation node sync. No page or file serving, no
propagation node, no transport routing for others. The one inbound capability
a client needs is accepting links on its own `lxmf.delivery` destination,
because that is how peers deliver messages directly.

## What Emacs gives us natively

Verified on Emacs 30.2 (macOS, GnuTLS build):

| Need | Emacs primitive | Status |
|------|-----------------|--------|
| SHA-256 / SHA-512 | `secure-hash` | built in |
| HMAC-SHA256 | `gnutls-hash-mac` | matches Python byte for byte |
| AES-256-CBC / AES-128-CBC | `gnutls-symmetric-encrypt/decrypt` | matches RNS byte for byte |
| Arbitrary precision integers | bignums (Emacs 27+) | built in |
| IEEE 754 float packing | `frexp`, `ldexp` | built in |
| zlib | `zlib-decompress-region` | built in, not needed by RNS |
| TCP sockets | `make-network-process` | built in |
| Secure random | none | read `/dev/urandom` via `head -c` |

Missing and implemented in Elisp: X25519 (RFC 7748), Ed25519 (RFC 8032),
HKDF (RNS variant), msgpack, HDLC framing, bz2 decompression (RNS resources
are bz2 compressed by the sender when it saves space).

The Elisp curve arithmetic is not constant time. For a client this is an
accepted trade-off and is documented for users.

## Reticulum facts the implementation is built on (RNS 1.5.0)

- Hashes: `full_hash` = SHA-256, `truncated_hash` = first 16 bytes.
  Identity hash = truncated_hash(pubkey 64 bytes = X25519 pub || Ed25519 pub).
- Destination hash = truncated(sha256(name_hash || identity_hash)), where
  name_hash = sha256("app.aspect...")[:10].
- Packet: `flags(1) hops(1) [transport_id(16)] destination(16) context(1) data`.
  flags = header_type<<6 | context_flag<<5 | transport_type<<4 | dest_type<<2 | packet_type.
  Packet hash = sha256((flags & 0x0f) || everything after the addresses).
- Announce data: `pub(64) name_hash(10) random_hash(10) [ratchet(32)] signature(64) app_data`.
  Ratchet present when context_flag is set. Signed data =
  `dest_hash || pub || name_hash || random_hash || ratchet || app_data`.
- Identity encryption: ephemeral X25519 pub (32) || Token, where the token key
  is HKDF(64, shared_secret, salt = identity hash) and the shared secret is
  ECDH with the destination's ratchet key if one is known, else its identity key.
- Token (Fernet without header): `iv(16) || AES-CBC(pkcs7) || HMAC-SHA256(32)`,
  key = signing_key(32) || encryption_key(32).
- Link request: data = `x25519_pub(32) || ed25519_pub(32) || signalling(3)`.
  Link id = truncated_hash(hashable part without the signalling bytes).
  Proof: `signature(64) || peer_x25519_pub(32) || signalling(3)` signed by the
  destination identity over `link_id || peer_pub || peer_sig_pub || signalling`.
  Link key = HKDF(64, ECDH, salt = link_id). After the proof the initiator sends
  an LRRTT packet with msgpack(rtt).
- Requests: msgpack `[time, truncated_hash(path), data]` in a REQUEST packet
  (or a resource when larger than the MDU). Responses: msgpack
  `[request_id, response]` in a RESPONSE packet, or a resource whose
  advertisement carries the request id.
- Resource advertisement: msgpack map with keys t d n h r o i l q f m.
  Parts are requested by map hash (first 4 bytes of sha256 of the part) and
  reassembled, then decrypted with the link token and bz2 decompressed when the
  compressed flag is set.
- Transport for a leaf client: keep a path table from announces
  (next hop = transport_id of the announce packet, hops = packet hops). Send
  with HEADER_2 and the next hop's transport id when hops > 1, otherwise
  HEADER_1. Path requests are plain packets to `rnstransport.path.request`
  with data `dest_hash || random_tag`.
- TCP interface: HDLC framing, flag 0x7E, escape 0x7D with XOR 0x20. The same
  framing is used by the local shared-instance interface on TCP port 37428, so
  a running `rnsd` can serve as the network interface.
- LXMF message: `dest(16) || source(16) || signature(64) || msgpack([ts, title, content, fields, stamp?])`.
  Hash = sha256(dest || source || packed_payload). Signature over hash input || hash.
  Announce app data for a peer: msgpack `[display_name, stamp_cost, [0]]`.
- Delivery methods: opportunistic (single packet encrypted to the destination,
  data = packed message without the leading destination hash), direct (link to
  the peer, packet or resource), propagated (link to a PN, msgpack
  `[time, [dest || encrypted_rest || propagation_stamp]]`).
- PN sync: link to the PN's `lxmf.propagation` destination, identify, request
  `/get` with `[None, None]` for the list, then `[wants, haves, limit]`, then
  `[None, haves]` to acknowledge.
- Stamps: workblock = 3000 (peer) or 1000 (PN) rounds of HKDF(256) expansion;
  a stamp is valid when sha256(workblock || stamp) has `cost` leading zero bits.

## Module layout

The repository holds two packages: `reticulum/` (the library, entry point
`reticulum.el`) and `nomadnet/` (the client, which depends on it). They stay in
one repository until a second consumer of the library exists.  The library is
under the Reticulum License; the client is GPL-3 because it ports nomadnet code.

```
reticulum-bytes.el      unibyte helpers, hex, int conversions, random
reticulum-msgpack.el    msgpack pack/unpack (umsgpack compatible)
reticulum-crypto.el     sha, hmac, hkdf, token, x25519, ed25519, pkcs7
reticulum-bz2.el        bz2 decoder in Lisp (bzip2 binary optional)
reticulum-identity.el   identities, known destinations, ratchets, announces
reticulum-packet.el     packet pack/unpack/hash
reticulum-interface.el  HDLC + TCP client interface, local instance interface
reticulum-transport.el  path table, outbound/inbound dispatch, receipts, path requests
reticulum-link.el       links, requests/responses, keepalive
reticulum-resource.el   inbound (and small outbound) resources
lxmf-message.el         message codec, fields, peer announce app data
lxmf-router.el          delivery destination with ratchets, inbound delivery (client side)
nomadnet-*.el           existing UI, switched from the bridge to the native API
```

The UI modules already talk to an abstract API (`nomadnet-request`), so the
switch is a new backend behind the same calls.

## Status (2026-09-20)

Phases 1 to 4 are done and verified live: announces from the public network
validate, links establish through transport nodes, pages come back as
compressed resources and render. `nomadnet-native.el` answers the UI's
requests for status, announces, directory, peer info and browsing, reading and
writing nomadnet's own files. Phase 5 is under way: the LXMF codec and the
inbound half of the router are done and verified live (opportunistic and
direct delivery from the Python LXMF router through a public transport node,
with proofs accepted by the sender). Remaining: outbound delivery, stamps,
propagation node sync, conversation storage, file downloads (resources with
metadata) and the guide text; tracked as repository issues.

## Phases

1. Foundation: bytes, msgpack, crypto, tests against Python generated vectors.
2. Identity, destination hashing, packet codec, announce validation.
3. TCP/HDLC interface and transport: receive announces from a real transport
   node, maintain the path table, send path requests.
4. Links: establish a link to a node, request `/page/index.mu`, receive packet
   responses and resources (needs bz2). Browser on the native stack.
5. LXMF: delivery destination with ratchets, receive opportunistic and direct
   messages, send direct/opportunistic/propagated, stamps, PN sync.
   Conversations on the native stack, storage compatible with nomadnet's.
6. Remove the bridge (done).

Each phase ends with a live check against the public Reticulum network.
