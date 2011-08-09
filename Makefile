GHCFLAGS=-Wall -XNoCPP -fno-warn-name-shadowing -XHaskell98
HLINTFLAGS=-XHaskell98 -XNoCPP -i 'Use camelCase' -i 'Use String' -i 'Use head' -i 'Use string literal' -i 'Use list comprehension' --utf8

.PHONY: all cleas

all: verify report.html

verify: examples/verify.hs
	ghc --make $(GHCFLAGS) -o $@ $^

report.html:
	hlint $(HLINTFLAGS) --report Data examples

clean:
	find -name '*.o' -o -name '*.hi' | xargs $(RM)
	$(RM) verify
