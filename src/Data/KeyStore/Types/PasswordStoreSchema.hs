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
{-# LANGUAGE OverloadedStrings          #-}
{-# OPTIONS_GHC -fno-warn-orphans       #-}

module Data.KeyStore.Types.PasswordStoreSchema
    ( passwordStoreSchema
    , passwordStoreChangelog
    ) where

import           Data.API.Parse
import           Data.API.Types
import           Data.API.Changes


passwordStoreSchema    :: API
passwordStoreChangelog :: APIChangelog
(passwordStoreSchema, passwordStoreChangelog) = [apiWithChangelog|

ps :: PasswordStore
    = record
        comment     :: PasswordStoreComment
        map         :: PasswordMap
        setup       :: utc

pm :: PasswordMap
    // the password map, represented internally with a Map
    // from PasswordName to Password
    = record
        map         :: [NamePasswordAssoc]
    with inj_pwmap, prj_pwmap

npa :: NamePasswordAssoc
    = record
        name        :: PasswordName
        password    :: Password

pw  :: Password
    // passwords may be simple, or be a collection of 'sessions',
    // one of which is selected
    = record
        name        :: PasswordName
        text        :: PasswordText
        sessions    :: SessionMap
        isOneShot   :: Bool
        primed      :: boolean
        setup       :: utc

smp :: SessionMap
    // collections of sessions are represented internally as a Map
    // from SessionName to PasswordText
    = record
        map         :: [SessionPasswordAssoc]
    with inj_snmap, prj_snmap

spa :: SessionPasswordAssoc
    = record
        name        :: SessionName
        session     :: Session

ssn :: Session
    // a session just consists of a password and the stup time
    = record
        name        :: SessionName
        password    :: PasswordText
        isOneShot   :: Bool
        setup       :: utc

pwsc :: PasswordStoreComment
    // a short comment on the PasswordStore
    = basic string

pnm :: PasswordName
    // used to identify a password in the store
    = basic string

ptx :: PasswordText
    // used to contain the secret text of a Password
    = basic string

snm :: SessionName
    // used to identify the different sessions in a session password
    = basic string

changes

// Initial version
version "0.0.0.1"

|]
