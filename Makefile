ifdef CEREAL
GHCFLAGS=-Wall -O2 -DCEREAL -fno-warn-name-shadowing -XHaskell98
else
GHCFLAGS=-Wall -O2 -fno-warn-name-shadowing -XHaskell98
endif

HLINTFLAGS=-u -XHaskell98 -XCPP -i 'Use camelCase' -i 'Use String' -i 'Use string literal' -i 'Use list comprehension'
VERSION=0.5

.PHONY: all clean doc install debian test

all: test report.html doc dist/build/libHSopenpgp-$(VERSION).a dist/openpgp-$(VERSION).tar.gz

install: dist/build/libHSopenpgp-$(VERSION).a
	cabal install

debian: debian/control

test: tests/suite
	tests/suite

tests/suite: tests/suite.hs Data/OpenPGP.hs Data/OpenPGP/Internal.hs Data/OpenPGP/Arbitrary.hs
	ghc --make $(GHCFLAGS) -o $@ $^

Data/OpenPGP/Arbitrary.hs: Data/OpenPGP.hs Arbitrary.patch
	derive -d Arbitrary -m Data.OpenPGP.Arbitrary -iData.OpenPGP -iData.OpenPGP.Internal -iTest.QuickCheck -iTest.QuickCheck.Instances -iNumeric -iData.Char -iData.Word -o $@ Data/OpenPGP.hs
	patch $@ Arbitrary.patch

report.html: tests/suite.hs Data/OpenPGP.hs Data/OpenPGP/Internal.hs
	-hlint $(HLINTFLAGS) --report $^

doc: dist/doc/html/openpgp/index.html README

README: openpgp.cabal
	tail -n+$$(( `grep -n ^description: $^ | head -n1 | cut -d: -f1` + 1 )) $^ > .$@
	head -n+$$(( `grep -n ^$$ .$@ | head -n1 | cut -d: -f1` - 1 )) .$@ > $@
	-printf ',s/        //g\n,s/^.$$//g\nw\nq\n' | ed $@
	$(RM) .$@

# XXX: Is there a way to make this just pass through $(GHCFLAGS)
ifdef CEREAL
dist/doc/html/openpgp/index.html: dist/setup-config Data/OpenPGP.hs Data/OpenPGP/Internal.hs
	cabal haddock --hyperlink-source --haddock-options="--optghc=-DCEREAL"
else
dist/doc/html/openpgp/index.html: dist/setup-config Data/OpenPGP.hs Data/OpenPGP/Internal.hs
	cabal haddock --hyperlink-source
endif

ifdef CEREAL
dist/setup-config: openpgp.cabal
	-printf '1c\nname:            openpgp-cereal\n.\n,s/binary >= 0.6.4.0,$$/cereal,/g\nw\nq\n' | ed openpgp.cabal
	cabal configure --enable-tests
else
dist/setup-config: openpgp.cabal
	cabal configure --enable-tests
endif

clean:
	-printf '1c\nname:            openpgp\n.\n,s/cereal,$$/binary >= 0.6.4.0,/g\nw\nq\n' | ed openpgp.cabal
	find -name '*.o' -o -name '*.hi' | xargs $(RM)
	$(RM) sign verify keygen tests/suite
	$(RM) -r dist dist-ghc

debian/control: openpgp.cabal
	cabal-debian --update-debianization

dist/build/libHSopenpgp-$(VERSION).a: openpgp.cabal dist/setup-config Data/OpenPGP.hs Data/OpenPGP/Internal.hs
	cabal build --ghc-options="$(GHCFLAGS)"

dist/openpgp-$(VERSION).tar.gz: openpgp.cabal dist/setup-config README Data/OpenPGP.hs Data/OpenPGP/Internal.hs
	cabal check
	cabal sdist
