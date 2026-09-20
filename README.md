# nomadnet.el

Two Emacs packages in one repository:

- `reticulum/`: **reticulum.el**, a client implementation of the
  [Reticulum](https://reticulum.network) network stack in Emacs Lisp. A
  library with no user interface.
- `nomadnet/`: **nomadnet.el**, the Nomad Network client built on it.

[Nomad Network](https://github.com/markqvist/NomadNet) for Emacs: encrypted
LXMF messaging over [Reticulum](https://github.com/markqvist/Reticulum), an
announce stream and directory of known nodes, and a browser for micron pages
hosted on Nomad Network nodes.

Everything is Emacs Lisp: Reticulum (crypto, transport, links, resources) in
`reticulum/`, the client in `nomadnet/`. Browsing nodes, the announce stream
and the directory of known nodes work today; LXMF messaging is in progress
(see the repository issues and `docs/native-plan.md`).

The client shares nomadnet's configuration directory, so your identity, known
nodes, announce stream and page cache are the same in Emacs and in the
`nomadnet` program.

## Requirements

- Emacs 28.1 or newer, built with GnuTLS (all common builds are)
- A Reticulum configuration file whose `TCPClientInterface` entries point at
  reachable transport nodes; they are read from `~/.reticulum/config` (see
  `nomadnet-native-interfaces` to configure interfaces by hand)

## Installation

Clone the repository, add both package directories to your `load-path` and
require the client (it loads the library on demand):

```elisp
(add-to-list 'load-path "~/src/nomadnet.el/reticulum")
(add-to-list 'load-path "~/src/nomadnet.el/nomadnet")
(require 'nomadnet)
```

With `use-package` and a VC source:

```elisp
(use-package nomadnet
  :vc (:url "https://github.com/paulmeier/nomadnet.el")
  :commands (nomadnet nomadnet-conversations nomadnet-announces
             nomadnet-known-nodes nomadnet-browse nomadnet-guide))
```

Do not run the `nomadnet` terminal client and nomadnet.el on the same
configuration directory at the same time; both would use the same identity.
Set `nomadnet-native-config-directory` to use a separate configuration.

## Usage

| Command                   | What it does                                          |
|---------------------------|-------------------------------------------------------|
| `M-x nomadnet`            | Dashboard with status, interfaces and shortcuts to everything |
| `M-x nomadnet-conversations` | List LXMF conversations; `RET` opens, `n` starts a new one |
| `M-x nomadnet-announces`  | Announce stream; `RET` opens an announce, `/` searches by name |
| `M-x nomadnet-known-nodes`| Saved nodes; `RET` connects, `t` toggles trust, `e` edits notes |
| `M-x nomadnet-browse`     | Open a node URL such as `abb3ebcd03cb2388a838e70c001291f9:/page/index.mu` |
| `M-x nomadnet-guide`      | Read the built in Nomad Network guide                 |
| `M-x nomadnet-announce-now` | Announce your LXMF address                          |
| `M-x nomadnet-sync-messages` | Fetch messages from the propagation node           |
| `M-x nomadnet-log`        | Tail the nomadnet log file                            |

### Browser

Keys in the browser buffer: `u` open URL, `l` back, `r` forward, `g` reload
(bypasses the cache), `d` disconnect, `s` save node to known nodes, `c` copy
URL, `m` message the node operator, `v` view page source, `TAB`/`S-TAB` move
between links and fields, `RET` follow a link, edit a text field in the
minibuffer, or toggle a checkbox or radio button.

Links with request variables and field lists (`` `[Submit`:/page/x.mu`*] ``)
submit the page's fields to node-side scripts exactly as the nomadnet browser
does. Partials (`` `{...} ``) load after the page and honour their refresh
interval. Anchor links (`#name`) and `/file/` downloads (saved to nomadnet's
downloads path) are supported. Pages that declare `#!fg=` and `#!bg=` colours
are painted with them across the whole buffer, as in nomadnet.

Submitting fields larger than one link packet needs outbound resources, which
are not implemented yet (see the repository issues); the browser reports this
and keeps the page and its field values so you can shorten them and retry.

### Dashboard

The dashboard lists the Reticulum interfaces with their online state and
transferred bytes, like nomadnet's Interfaces section, and refreshes itself
every `nomadnet-dashboard-refresh-interval` seconds while displayed.

### Announce stream and known nodes

`/` in the announce stream filters it by a search text matched against names
and addresses, like nomadnet's search box; an empty search shows everything.
`f` cycles the kind filter. In the known nodes list `e` edits the notes stored
with a node; they are kept in nomadnet's directory and shown in the list.

### Conversations

The conversation list refreshes automatically when messages arrive. In a
conversation buffer, `c` composes a message (`C-c C-c` sends, `C-c C-k`
cancels), `A` saves the attachments of the message at point, `P` purges failed
messages, `t` toggles trust of the peer, `n` and `p` move between messages.
Long messages wrap at word boundaries. Composed messages are tagged as
markdown to match nomadnet's default; see `nomadnet-compose-renderer`.
Messages tagged as micron are rendered with the micron renderer.

## Micron renderer

`nomadnet-micron.el` is a pure Emacs Lisp port of nomadnet's micron parser:
sections and headings, alignment, bold/underline/italic, 3 and 6 digit colours,
dividers, comments, literal blocks, links, text fields, checkboxes, radio
groups, anchors, tables and partial placeholders. `nomadnet-micron-render`
inserts rendered markup into any buffer; `nomadnet-micron-to-string` returns it
as a string. Heading colours are the faces `nomadnet-micron-heading-1..3`.

## Reticulum in Emacs Lisp

The library implements X25519, Ed25519, HKDF, RNS tokens (AES-256-CBC +
HMAC via GnuTLS), msgpack, HDLC framed TCP interfaces, a leaf transport with
path table and path requests, links with requests/responses, and inbound
resources. It is verified against vectors recorded from the reference Python
implementation (`make vectors` regenerates them) and against the live network.
The curve arithmetic runs in Emacs Lisp on bignums and is not constant time.

## Development

```
make compile      # byte-compile both packages with warnings as errors
make test         # ERT tests for reticulum (test-reticulum) and nomadnet (test-nomadnet)
```

`reticulum/test/vectors.json` is a fixed fixture of reference values (see
`reticulum/test/README.md`).

```
```

## Not yet translated

- RRC channels (the Channels section of nomadnet 1.2)
- The interface configuration and map sections
- Paper messages (QR output)
- Editing nomadnet's configuration file from Emacs (edit `~/.nomadnetwork/config`)

## License

- `reticulum/` (reticulum.el) is released under the
  [Reticulum License](reticulum/LICENSE), the same MIT-style license with two
  use conditions that the Reticulum Network Stack uses.
- `nomadnet/` (nomadnet.el) is GPL-3.0-or-later
  ([license](nomadnet/LICENSE)), because they port code and text from Nomad
  Network, which is GPL-3.

Nomad Network, Reticulum and LXMF are by Mark Qvist.
