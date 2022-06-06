{-# LANGUAGE CPP                        #-}

module Data.KeyStore.Types.AesonCompat
  ( module A
  , module Data.KeyStore.Types.AesonCompat
  ) where

import qualified Data.HashMap.Strict            as HM
import qualified Data.Text                      as T


#if MIN_VERSION_aeson(2,0,0)


import           Data.Aeson                     as A  hiding (Key)
import qualified Data.Aeson.Key                 as A
import qualified Data.Aeson.KeyMap              as A

type KM a = A.KeyMap a

fromKM :: KM a -> HM.HashMap T.Text a
fromKM = HM.mapKeys A.toText . A.toHashMap

intoKM :: HM.HashMap T.Text a -> KM a
intoKM = A.fromHashMap . HM.mapKeys A.fromText


#else


import           Data.Aeson                     as A

type KM a = HM.HashMap T.Text a

fromKM :: KM a -> HM.HashMap T.Text a
fromKM = id

intoKM :: HM.HashMap T.Text a -> KM a
intoKM = id


#endif
