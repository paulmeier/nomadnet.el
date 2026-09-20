EMACS ?= emacs

RETICULUM_SOURCES := reticulum/reticulum-bytes.el reticulum/reticulum-msgpack.el \
  reticulum/reticulum-crypto.el reticulum/reticulum-packet.el reticulum/reticulum-identity.el \
  reticulum/reticulum-interface.el reticulum/reticulum-transport.el reticulum/reticulum-bz2.el \
  reticulum/reticulum-link.el reticulum/reticulum-resource.el reticulum/reticulum.el

NOMADNET_SOURCES := nomadnet/nomadnet-core.el nomadnet/nomadnet-native.el \
  nomadnet/nomadnet-micron.el nomadnet/nomadnet-browser.el nomadnet/nomadnet-conversations.el \
  nomadnet/nomadnet-network.el nomadnet/nomadnet-guide.el nomadnet/nomadnet.el

LOAD := -L reticulum -L nomadnet

.PHONY: all compile compile-reticulum compile-nomadnet test test-reticulum test-nomadnet check clean

all: compile

compile: compile-reticulum compile-nomadnet

compile-reticulum:
	$(EMACS) -Q --batch $(LOAD) \
	  --eval '(setq byte-compile-error-on-warn t)' \
	  -f batch-byte-compile $(RETICULUM_SOURCES)

compile-nomadnet:
	$(EMACS) -Q --batch $(LOAD) \
	  --eval '(setq byte-compile-error-on-warn t)' \
	  -f batch-byte-compile $(NOMADNET_SOURCES)

test: test-reticulum test-nomadnet

test-reticulum:
	$(EMACS) -Q --batch $(LOAD) -L reticulum/test \
	  -l reticulum-test.el -f ert-run-tests-batch-and-exit

test-nomadnet:
	$(EMACS) -Q --batch $(LOAD) -L nomadnet/test \
	  -l nomadnet-micron-test.el -l nomadnet-ui-test.el -f ert-run-tests-batch-and-exit

check: compile test

clean:
	rm -f reticulum/*.elc nomadnet/*.elc reticulum/test/*.elc nomadnet/test/*.elc
