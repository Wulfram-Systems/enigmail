# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


DEPTH		= ../..

include $(DEPTH)/config/autoconf.mk

GENDIR = $(DIST)/chrome/content/modules/cryptoAPI

MODFILES = \
	gnupg-keyEditor.jsm \
	gpgme.js \
	openpgp-js.js \
	pgpjs-crypto-main.jsm \
	pgpjs-encrypt.jsm \
	pgpjs-keys.jsm \
	pgpjs-keystore.jsm \
	pgpjs-keymanipulation.jsm \
	interface.js

WORKERS = \
	pgpjs-crypto-worker.js

GENFILES = $(addprefix $(GENDIR)/,$(MODFILES))

$(GENDIR)/%.jsm: %.jsm
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

$(GENDIR)/%.js: %.js
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

build: $(GENFILES) deploy

deploy:
	$(DEPTH)/util/install -m 644 $(GENDIR) $(WORKERS)

all: build

clean:
	$(DEPTH)/util/install -u $(DIST)/chrome/content/modules/cryptoAPI $(MODFILES)
	$(DEPTH)/util/install -u $(DIST)/chrome/content/modules/cryptoAPI $(WORKERS)
