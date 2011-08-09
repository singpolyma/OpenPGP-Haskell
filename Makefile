GHCFLAGS=-Wall -XNoCPP -fno-warn-name-shadowing -XHaskell98

verify: examples/verify.hs
	ghc --make $(GHCFLAGS) -o $@ $^

clean:
	find -name '*.o' -o -name '*.hi' | xargs $(RM)
	$(RM) verify
