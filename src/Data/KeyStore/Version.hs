module Data.KeyStore.Version where

version :: String
version = show a ++ "." ++ show b ++ "." ++ show c ++ "." ++ show d
  where
    (a,b,c,d) = versionTuple

versionTuple :: (Int,Int,Int,Int)
versionTuple = (0,5,1,0)
