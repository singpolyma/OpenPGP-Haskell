GHCFLAGS=-Wall -XNoCPP -fno-warn-name-shadowing -XHaskell98
HLINTFLAGS=-XHaskell98 -XNoCPP -i 'Use camelCase' -i 'Use String' -i 'Use head' -i 'Use string literal' -i 'Use list comprehension' --utf8

.PHONY: all cleas

all: verify report.html README

verify: examples/verify.hs
	ghc --make $(GHCFLAGS) -o $@ $^

report.html:
	hlint $(HLINTFLAGS) --report Data examples

README: openpgp.cabal
	tail -n+$$(( `grep -n ^description: $^ | head -n1 | cut -d: -f1` + 1 )) $^ > .$@
	head -n+$$(( `grep -n ^$$ .$@ | head -n1 | cut -d: -f1` - 1 )) .$@ > $@
	printf ',s/        //g\n,s/^.$$//g\nw\nq\n' | ed $@
	$(RM) .$@

clean:
	find -name '*.o' -o -name '*.hi' | xargs $(RM)
	$(RM) verify
