GHCFLAGS=-Wall -XNoCPP -fno-warn-name-shadowing -XHaskell98
HLINTFLAGS=-XHaskell98 -XNoCPP -i 'Use camelCase' -i 'Use String' -i 'Use head' -i 'Use string literal' -i 'Use list comprehension' --utf8
VERSION=0.3

.PHONY: all clean doc install debian

all: sign verify keygen report.html doc dist/build/libHSopenpgp-$(VERSION).a dist/openpgp-$(VERSION).tar.gz

install: dist/build/libHSopenpgp-$(VERSION).a
	cabal install

debian: debian/control

sign: examples/sign.hs Data/*.hs Data/OpenPGP/*.hs
	ghc --make $(GHCFLAGS) -o $@ $^

verify: examples/verify.hs Data/*.hs Data/OpenPGP/*.hs
	ghc --make $(GHCFLAGS) -o $@ $^

keygen: examples/keygen.hs Data/*.hs Data/OpenPGP/*.hs
	ghc --make $(GHCFLAGS) -o $@ $^

report.html: examples/*.hs Data/*.hs Data/OpenPGP/*.hs
	-hlint $(HLINTFLAGS) --report Data examples

doc: dist/doc/html/openpgp/index.html README

README: openpgp.cabal
	tail -n+$$(( `grep -n ^description: $^ | head -n1 | cut -d: -f1` + 1 )) $^ > .$@
	head -n+$$(( `grep -n ^$$ .$@ | head -n1 | cut -d: -f1` - 1 )) .$@ > $@
	-printf ',s/        //g\n,s/^.$$//g\nw\nq\n' | ed $@
	$(RM) .$@

dist/doc/html/openpgp/index.html: dist/setup-config Data/OpenPGP.hs Data/OpenPGP/Crypto.hs
	cabal haddock --hyperlink-source

dist/setup-config: openpgp.cabal
	cabal configure

clean:
	find -name '*.o' -o -name '*.hi' | xargs $(RM)
	$(RM) sign verify keygen
	$(RM) -r dist dist-ghc

debian/control: openpgp.cabal
	cabal-debian --update-debianization

dist/build/libHSopenpgp-$(VERSION).a: openpgp.cabal dist/setup-config Data/BaseConvert.hs Data/OpenPGP.hs Data/OpenPGP/Crypto.hs
	cabal build

dist/openpgp-$(VERSION).tar.gz: openpgp.cabal dist/setup-config Data/BaseConvert.hs Data/OpenPGP.hs Data/OpenPGP/Crypto.hs README
	cabal check
	cabal sdist
