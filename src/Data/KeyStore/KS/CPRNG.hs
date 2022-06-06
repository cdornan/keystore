{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}

module Data.KeyStore.KS.CPRNG
    ( CPRNG
    , newCPRNG
    , testCPRNG
    , generateCPRNG
    ) where

import           Crypto.Random
import qualified Data.ByteArray                 as BA
import           System.IO.Unsafe


newtype CPRNG
    = CPRNG { _CPRNG :: SystemDRG }
    deriving (DRG)


newCPRNG :: IO CPRNG
newCPRNG = CPRNG <$> getSystemDRG

testCPRNG :: CPRNG
testCPRNG = unsafePerformIO newCPRNG

generateCPRNG :: BA.ByteArray ba => Int -> CPRNG -> (ba,CPRNG)
generateCPRNG = randomBytesGenerate
