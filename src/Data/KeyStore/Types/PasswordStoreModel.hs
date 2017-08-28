{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE ExistentialQuantification  #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TypeSynonymInstances       #-}
{-# LANGUAGE FlexibleInstances          #-}

module Data.KeyStore.Types.PasswordStoreModel where

import qualified Control.Lens               as L
import           Data.Aeson
import           Data.API.JSON
import           Data.KeyStore.Types.PasswordStoreSchema
import qualified Data.Map                                 as Map
import           Data.API.Tools
import           Data.Time
import           Data.KeyStore.Types.UTC


$(generate passwordStoreSchema)
$(generateAPITools passwordStoreSchema
                   [ enumTool
                   , jsonTool'
                   , lensTool
                   ])


instance ToJSON PasswordStore where
  toJSON = toJSON . toPasswordStore_

instance FromJSON PasswordStore where
  parseJSON = fmap fromPasswordStore_ . parseJSON

instance FromJSONWithErrs PasswordStore where
  parseJSONWithErrs = fmap fromPasswordStore_ . parseJSONWithErrs


data PasswordStore =
  PasswordStore
    { _ps_comment :: PasswordStoreComment
    , _ps_map     :: PasswordMap
    , _ps_setup   :: UTCTime
    }
  deriving (Show,Eq)

toPasswordStore_ :: PasswordStore -> PasswordStore_
toPasswordStore_ PasswordStore{..} =
  PasswordStore_
    { _z_ps_comment =                _ps_comment
    , _z_ps_map     = toPasswordMap_ _ps_map
    , _z_ps_setup   = UTC            _ps_setup
    }

fromPasswordStore_ :: PasswordStore_ -> PasswordStore
fromPasswordStore_ PasswordStore_{..} =
  PasswordStore
    { _ps_comment =                  _z_ps_comment
    , _ps_map     = fromPasswordMap_ _z_ps_map
    , _ps_setup   = _UTC             _z_ps_setup
    }


-- The PasswordStre and SessionMap association lists are represented internally
-- with maps.


type PasswordMap = Map.Map PasswordName Password

toPasswordMap_ :: PasswordMap -> PasswordMap_
toPasswordMap_ mp = PasswordMap_ $
  [ NamePasswordAssoc_ nm $ toPassword_ pw
    | (nm,pw) <- Map.assocs mp
    ]

fromPasswordMap_ :: PasswordMap_ -> PasswordMap
fromPasswordMap_ mp_ = Map.fromList
  [ (_z_npa_name,fromPassword_ _z_npa_password)
    | NamePasswordAssoc_{..} <- _z_pm_map mp_
    ]


data Password =
  Password
    { _pw_name        :: PasswordName
    , _pw_text        :: PasswordText
    , _pw_sessions    :: SessionMap
    , _pw_isOneShot   :: Bool
    , _pw_primed      :: Bool
    , _pw_setup       :: UTCTime
    }
  deriving (Show,Eq)

toPassword_ :: Password -> Password_
toPassword_ Password{..} =
  Password_
    { _z_pw_name        =               _pw_name
    , _z_pw_text        =               _pw_text
    , _z_pw_sessions    = toSessionMap_ _pw_sessions
    , _z_pw_isOneShot   =               _pw_isOneShot
    , _z_pw_primed      =               _pw_primed
    , _z_pw_setup       = UTC           _pw_setup
    }

fromPassword_ :: Password_ -> Password
fromPassword_ Password_{..} =
  Password
    { _pw_name        =                 _z_pw_name
    , _pw_text        =                 _z_pw_text
    , _pw_sessions    = fromSessionMap_ _z_pw_sessions
    , _pw_isOneShot   =                 _z_pw_isOneShot
    , _pw_primed      =                 _z_pw_primed
    , _pw_setup       = _UTC            _z_pw_setup
    }


type SessionMap = Map.Map SessionName Session

toSessionMap_ :: SessionMap -> SessionMap_
toSessionMap_ mp = SessionMap_ $
  [ SessionPasswordAssoc_ nm ssn
    | (nm,ssn) <- Map.assocs mp
    ]

fromSessionMap_ :: SessionMap_ -> SessionMap
fromSessionMap_ mp_ = Map.fromList
  [ (_z_spa_name,_z_spa_session)
    | SessionPasswordAssoc_{..} <- _z_smp_map mp_
    ]


L.makeLenses ''PasswordStore
L.makeLenses ''Password
