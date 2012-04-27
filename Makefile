ifdef CEREAL
GHCFLAGS=-Wall -DCEREAL -fno-warn-name-shadowing -XHaskell98
else
GHCFLAGS=-Wall -fno-warn-name-shadowing -XHaskell98
endif

HLINTFLAGS=-XHaskell98 -XCPP -i 'Use camelCase' -i 'Use String' -i 'Use head' -i 'Use string literal' -i 'Use list comprehension' --utf8
VERSION=0.3

.PHONY: all clean doc install debian test

all: test report.html doc dist/build/libHSopenpgp-$(VERSION).a dist/openpgp-$(VERSION).tar.gz

install: dist/build/libHSopenpgp-$(VERSION).a
	cabal install

debian: debian/control

test: tests/suite
	tests/suite

tests/suite: tests/suite.hs Data/OpenPGP.hs
	ghc --make $(GHCFLAGS) -o $@ $^

report.html: Data/OpenPGP.hs tests/suite.hs
	-hlint $(HLINTFLAGS) --report $^

doc: dist/doc/html/openpgp/index.html README

README: openpgp.cabal
	tail -n+$$(( `grep -n ^description: $^ | head -n1 | cut -d: -f1` + 1 )) $^ > .$@
	head -n+$$(( `grep -n ^$$ .$@ | head -n1 | cut -d: -f1` - 1 )) .$@ > $@
	-printf ',s/        //g\n,s/^.$$//g\nw\nq\n' | ed $@
	$(RM) .$@

# XXX: Is there a way to make this just pass through $(GHCFLAGS)
ifdef CEREAL
dist/doc/html/openpgp/index.html: dist/setup-config Data/OpenPGP.hs
	cabal haddock --hyperlink-source --haddock-options="--optghc=-DCEREAL"
else
dist/doc/html/openpgp/index.html: dist/setup-config Data/OpenPGP.hs
	cabal haddock --hyperlink-source
endif

ifdef CEREAL
dist/setup-config: openpgp.cabal
	-printf '1c\nname:            openpgp-cereal\n.\n,s/binary,$$/cereal,/g\nw\nq\n' | ed openpgp.cabal
	cabal configure
else
dist/setup-config: openpgp.cabal
	cabal configure
endif

clean:
	-printf '1c\nname:            openpgp\n.\n,s/cereal,$$/binary,/g\nw\nq\n' | ed openpgp.cabal
	find -name '*.o' -o -name '*.hi' | xargs $(RM)
	$(RM) sign verify keygen tests/suite
	$(RM) -r dist dist-ghc

debian/control: openpgp.cabal
	cabal-debian --update-debianization

dist/build/libHSopenpgp-$(VERSION).a: openpgp.cabal dist/setup-config Data/OpenPGP.hs
	cabal build --ghc-options="$(GHCFLAGS)"

dist/openpgp-$(VERSION).tar.gz: openpgp.cabal dist/setup-config Data/OpenPGP.hs README
	cabal check
	cabal sdist
