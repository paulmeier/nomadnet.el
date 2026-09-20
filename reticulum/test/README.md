# reticulum.el test suite

`reticulum-test.el` is an ERT suite run by `make test-reticulum`. It needs no
network access.

`vectors.json` holds reference vectors: RFC 7748 and RFC 8032 test cases plus
values recorded once from the reference Python implementation (RNS 1.5.0,
LXMF 1.1.1) on 2026-09-20: msgpack encodings, HKDF outputs, encrypted tokens,
key pairs and shared secrets, signatures, identity hashes, encryptions with and
without ratchets, complete announce packets (valid and tampered) and bzip2
streams. The file is a fixed fixture; the tests compare this implementation
against it. Add new vectors by recording them from the reference
implementation and appending to the JSON by hand.
