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

//
// External Representation Only
//

// The builtin support for map-like types introduced in Aeson 1.0 has broken
// the mechanism for representing Map in this schema. In order to minimise the
// disruption and preserve the existing schema representation we have renamed
// all of the types in the schema that contain Map types. In the model these
// types are reconstructed just as they would have been in previous KeyStore
// editions and mapping functions have been introduced to convert between the
// two representations. The PasswordStore gets read with this representation,
// matching the representation of past keystore packages and gets
// converted into the internal type representation (with the maps) that the
// rest of the keystore code base expects.

z_ps :: PasswordStore_
    = record
        comment     :: PasswordStoreComment
        map         :: PasswordMap_
        setup       :: UTC

z_pm :: PasswordMap_
    // the password map, represented internally with a Map
    // from PasswordName to Password
    = record
        map         :: [NamePasswordAssoc_]

z_npa :: NamePasswordAssoc_
    = record
        name        :: PasswordName
        password    :: Password_

z_pw  :: Password_
    // passwords may be simple, or be a collection of 'sessions',
    // one of which is selected
    = record
        name        :: PasswordName
        text        :: PasswordText
        sessions    :: SessionMap_
        isOneShot   :: Bool
        primed      :: boolean
        setup       :: UTC

z_smp :: SessionMap_
    // collections of sessions are represented internally as a Map
    // from SessionName to PasswordText
    = record
        map         :: [SessionPasswordAssoc_]

z_spa :: SessionPasswordAssoc_
    = record
        name        :: SessionName
        session     :: Session


//
// Classic Schema Definitions
//

ssn :: Session
    // a session just consists of a password and the stup time
    = record
        name        :: SessionName
        password    :: PasswordText
        isOneShot   :: Bool
        setup       :: UTC

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
