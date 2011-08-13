GHCFLAGS=-Wall -XNoCPP -fno-warn-name-shadowing -XHaskell98
HLINTFLAGS=-XHaskell98 -XNoCPP -i 'Use camelCase' -i 'Use String' -i 'Use head' -i 'Use string literal' -i 'Use list comprehension' --utf8

.PHONY: all clean doc install

all: sign verify keygen report.html doc dist/build/libHSopenpgp-0.2.a dist/openpgp-0.2.tar.gz

install: dist/build/libHSopenpgp-0.2.a
	cabal install

sign: examples/sign.hs Data/*.hs Data/OpenPGP/*.hs
	ghc --make $(GHCFLAGS) -o $@ $^

verify: examples/verify.hs Data/*.hs Data/OpenPGP/*.hs
	ghc --make $(GHCFLAGS) -o $@ $^

keygen: examples/keygen.hs Data/*.hs Data/OpenPGP/*.hs
	ghc --make $(GHCFLAGS) -o $@ $^

report.html: examples/*.hs Data/*.hs Data/OpenPGP/*.hs
	hlint $(HLINTFLAGS) --report Data examples || true

doc: dist/doc/html/openpgp/index.html README

README: openpgp.cabal
	tail -n+$$(( `grep -n ^description: $^ | head -n1 | cut -d: -f1` + 1 )) $^ > .$@
	head -n+$$(( `grep -n ^$$ .$@ | head -n1 | cut -d: -f1` - 1 )) .$@ > $@
	printf ',s/        //g\n,s/^.$$//g\nw\nq\n' | ed $@
	$(RM) .$@

dist/doc/html/openpgp/index.html: dist/setup-config Data/OpenPGP.hs Data/OpenPGP/Crypto.hs
	cabal haddock --hyperlink-source

dist/setup-config: openpgp.cabal
	cabal configure

clean:
	find -name '*.o' -o -name '*.hi' | xargs $(RM)
	$(RM) sign verify
	$(RM) -r dist

# The following need to be changed on version change

dist/build/libHSopenpgp-0.2.a: openpgp.cabal dist/setup-config Data/BaseConvert.hs Data/OpenPGP.hs Data/OpenPGP/Crypto.hs
	cabal build

dist/openpgp-0.2.tar.gz: openpgp.cabal dist/setup-config Data/BaseConvert.hs Data/OpenPGP.hs Data/OpenPGP/Crypto.hs README
	cabal check
	cabal sdist
