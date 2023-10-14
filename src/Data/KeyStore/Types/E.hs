{-# LANGUAGE DeriveDataTypeable         #-}

module Data.KeyStore.Types.E
    ( E
    , Reason
    , strMsg
    , rsaError
    , eWrap
    , showReason
    ) where

import           Crypto.PubKey.RSA
import           Data.Typeable
import qualified Control.Monad.Except           as E
import qualified Control.Exception              as X
import           System.IO
import           System.Exit


type E a = Either Reason a

data Reason
    = R_RSA Error
    | R_MSG String
    | R_GEN
    deriving (Typeable,Show)

instance X.Exception Reason

-- instance E.Error Reason where
--     noMsg  = R_GEN
--     strMsg = R_MSG

strMsg :: String -> Reason
strMsg = R_MSG

rsaError :: Error -> Reason
rsaError = R_RSA

eWrap :: IO a -> IO a
eWrap p = X.catch p h
  where
    h     = rpt . showReason

    rpt s = hPutStrLn stderr s >> exitFailure

showReason :: Reason -> String
showReason r =
    case r of
      R_RSA e -> "error: " ++ show e
      R_MSG s -> "error: " ++ s
      R_GEN   -> "error"
