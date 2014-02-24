{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}

module Data.KeyStore.CPRNG
    ( CPRNG
    , newCPRNG
    , testCPRNG
    , generateCPRNG
    ) where

import           Crypto.Random
import           Control.Applicative
import qualified Data.ByteString                as B


newtype CPRNG
    = CPRNG { _CPRNG :: SystemRNG }
    deriving (CPRG)


newCPRNG :: IO CPRNG
newCPRNG = cprgCreate <$> createEntropyPool

testCPRNG :: CPRNG
testCPRNG = cprgSetReseedThreshold 0 $
                    cprgCreate $ createTestEntropyPool "Data.CertStore.Tools"

generateCPRNG :: Int -> CPRNG -> (B.ByteString,CPRNG)
generateCPRNG = cprgGenerate
