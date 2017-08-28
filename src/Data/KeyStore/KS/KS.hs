{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE BangPatterns               #-}

module Data.KeyStore.KS.KS
    ( KS
    , Ctx(..)
    , State(..)
    , LogEntry(..)
    , withKey
    , trun
    , e2io
    , e2ks
    , run_
    , randomBytes
    , currentTime
    , putStrKS
    , btw
    , debugLog
    , catchKS
    , errorKS
    , throwKS
    , lookupOpt
    , storeKS
    , getSettings
    , lookupKey
    , insertNewKey
    , insertKey
    , adjustKeyKS
    , deleteKeysKS
    , randomRSA
    , randomKS
    , getKeymap
    , getConfig
    , modConfig
    ) where

import           Data.KeyStore.KS.CPRNG
import           Data.KeyStore.KS.Configuration
import           Data.KeyStore.KS.Opt
import           Data.KeyStore.Types
import           Crypto.PubKey.RSA
import qualified Data.Map                       as Map
import qualified Data.ByteString                as B
import           Data.Typeable
import           Data.Time
import           Control.Monad.RWS.Strict
import qualified Control.Monad.Error            as E
import           Control.Exception
import           Control.Lens


newtype KS a = KS { _KS :: E.ErrorT Reason (RWS Ctx [LogEntry] State) a }
    deriving (Functor, Applicative, Monad, E.MonadError Reason)

data Ctx
    = Ctx
        { ctx_now      :: UTCTime
        , ctx_store    :: FilePath
        , ctx_settings :: Settings
        }
    deriving (Typeable,Show)

data State
    = State
        { st_keystore :: KeyStore
        , st_cprng    :: CPRNG
        }
        deriving (Typeable)

data LogEntry
    = LogEntry
        { le_debug   :: Bool
        , le_message :: String
        }
    deriving (Show)

withKey :: Name -> KS a -> KS a
withKey nm p =
 do ctx <- KS ask
    st  <- KS get
    let cfg  = _ks_config $ st_keystore st
        stgs = _cfg_settings cfg
    stgs' <- e2ks $ trigger nm cfg stgs
    case run_ ctx {ctx_settings=stgs'} st p of
      (e,st',les) ->
         do KS $ put st'
            KS $ tell les
            either throwKS return e

trun :: KS a -> a
trun p =
    case run_ (Ctx u "keystore.json" defaultSettings) s p of
      (Left  e,_,_) -> error $ show e
      (Right x,_,_) -> x
  where
    s = State
            { st_cprng    = testCPRNG
            , st_keystore = emptyKeyStore $ defaultConfiguration defaultSettings
            }

    u = read "2014-01-01 00:00:00"

e2io :: E a -> IO a
e2io = either throwIO return

e2ks :: E a -> KS a
e2ks = either throwKS return

run_ :: Ctx -> State -> KS a -> (E a,State,[LogEntry])
run_ c s p = runRWS (E.runErrorT (_KS p)) c s

randomBytes :: Octets -> (B.ByteString->a) -> KS a
randomBytes (Octets sz) k = k <$> randomKS (generateCPRNG sz)

currentTime :: KS UTCTime
currentTime = ctx_now <$> KS ask

putStrKS :: String -> KS ()
putStrKS msg = KS $ tell [LogEntry False msg]

btw :: String -> KS ()
btw = debugLog

debugLog :: String -> KS ()
debugLog msg = KS $ tell [LogEntry True msg]

catchKS :: KS a -> (Reason -> KS a) -> KS a
catchKS = E.catchError

errorKS :: String -> KS a
errorKS = throwKS . strMsg

throwKS :: Reason -> KS a
throwKS = E.throwError

storeKS :: KS FilePath
storeKS = ctx_store <$> KS ask

lookupOpt :: Show a => Opt a -> KS a
lookupOpt opt = getSettingsOpt opt <$> getSettings

getSettings :: KS Settings
getSettings = ctx_settings <$> KS ask

lookupKey :: Name -> KS Key
lookupKey nm =
 do mp <- getKeymap
    maybe oops return $ Map.lookup nm mp
  where
    oops = errorKS $ _name nm ++ ": no such keystore key"

insertNewKey :: Key -> KS ()
insertNewKey key =
 do mp <- getKeymap
    maybe (return ()) (const oops) $ Map.lookup nm mp
    insertKey key
  where
    oops = errorKS $ _name nm ++ ": key already in use"

    nm   = _key_name key

insertKey :: Key -> KS ()
insertKey key = mod_keymap $ Map.insert (_key_name key) key

adjustKeyKS :: Name -> (Key->Key) -> KS ()
adjustKeyKS nm adj = mod_keymap $ Map.adjust adj nm

deleteKeysKS :: [Name] -> KS ()
deleteKeysKS nms =
 do s <- KS get
    let mp  = _ks_keymap $ st_keystore s
        mp' = foldr Map.delete mp nms
    case Map.null $ Map.filter tst mp' of
      True  -> mod_keymap $ const mp'
      False -> errorKS "cannot delete these keys because they are still being used"
  where
    tst key = or [ any (`elem` safeguardKeys sg) nms |
                                    sg<-Map.keys $ _key_secret_copies key ]

randomRSA :: (CPRNG->(Either Error a,CPRNG)) -> KS a
randomRSA f = randomKS f >>= either (throwKS . rsaError) return

randomKS :: (CPRNG->(a,CPRNG)) -> KS a
randomKS f = KS $
 do s <- get
    let (x,!g') = f $ st_cprng s
    put s { st_cprng = g' }
    return x

getKeymap :: KS KeyMap
getKeymap = _ks_keymap.st_keystore <$> KS get

getConfig :: KS Configuration
getConfig = _ks_config.st_keystore <$> KS get

mod_keymap :: (KeyMap->KeyMap) -> KS ()
mod_keymap upd = KS get >>= \st -> KS $ put
    st
        { st_keystore = over ks_keymap upd (st_keystore st)
        }

modConfig :: (Configuration->Configuration) -> KS ()
modConfig upd = KS get >>= \st -> KS $ put
    st
        { st_keystore = over ks_config upd (st_keystore st)
        }
