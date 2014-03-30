

all: keystore markdown


keystore: .prep
	cabal install

.prep: keystore.manifest
	hub load    keystore <keystore.manifest
	hub comment keystore "keystore build"
	hub set     keystore
	ghc-pkg hide monads-tf
	cabal configure
	touch .prep

save-hub:
	hub save >keystore.manifest

markdown:
	runghc -isrc scripts/markdown.hs

clean:
	cabal clean
	rm -rf build .prep
