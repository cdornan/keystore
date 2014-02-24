OD = dist/build/certstore
HC = mkdir -p $(OD); ghc -XHaskell2010 --make -O1 -Werror -outputdir build -Wall


all: keystore


keystore: .prep
	cabal build

.prep: keystore.manifest
	hub load    keystore <keystore.manifest
	hub comment keystore "keystore build"
	hub set     keystore
	ghc-pkg hide monads-tf
	cabal configure
	touch .prep

save-hub:
	hub save >keystore.manifest

clean:
	cabal clean
	rm -rf build .prep
