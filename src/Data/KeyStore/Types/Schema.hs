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

module Data.KeyStore.Types.Schema
    ( keystoreSchema
    , keystoreChangelog
    ) where

import           Data.API.Parse
import           Data.API.Types
import           Data.API.Changes


keystoreSchema    :: API
keystoreChangelog :: APIChangelog
(keystoreSchema, keystoreChangelog) = [apiWithChangelog|

//
// External Representation Only
//

// The builtin support for map-like types introduced in Aeson 1.0 has broken
// the mechanism for representing Map in this schema. In order to minimise the
// disruption and preserve the existing schema representation we have renamed
// all of the types in the schema that contain Map types. In the model these
// types are reconstructed just as they would have been in previous KeyStore
// editions and mapping functions have been introduced to convert between the
// two representations. The KeyStore gets read with this representation,
// matching the representation of past keystore packages and gets converted
//  into the internal type representation (with the maps) that the rest of the
// keystore code base expects.

z_ks :: KeyStore_
    // the keystore
    = record
        config :: Configuration_
        keymap :: KeyMap_

z_cfg :: Configuration_
    = record
        settings :: Settings
        triggers :: TriggerMap_

z_tmp :: TriggerMap_
    = record
        map :: [Trigger]

z_kmp :: KeyMap_
    = record
        map :: [NameKeyAssoc_]

z_nka :: NameKeyAssoc_
    = record
        name :: Name
        key  :: Key_

z_key :: Key_
    = record
        name          :: Name
        comment       :: Comment
        identity      :: Identity
        is_binary     :: boolean
        env_var       :: ? EnvVar
        hash          :: ? Hash
        public        :: ? PublicKey
        secret_copies :: EncrypedCopyMap_
        clear_text    :: ? ClearText
        clear_private :: ? PrivateKey
        created_at    :: UTC

z_ecm :: EncrypedCopyMap_
    = record
        map :: [EncrypedCopy]


//
// Classic Schema Definitions
//

trg :: Trigger
    = record
        id       :: TriggerID
        pattern  :: Pattern
        settings :: Settings

stgs :: Settings
    = record
        'json'   :: json
    with inj_settings, prj_settings

hash :: Hash
    = record
        description :: HashDescription
        hash        :: HashData

hashd :: HashDescription
    = record
          comment      :: Comment
          prf          :: HashPRF
          iterations   :: Iterations
          width_octets :: Octets
          salt_octets  :: Octets
          salt         :: Salt

ec :: EncrypedCopy
    = record
        safeguard   :: Safeguard
        cipher      :: Cipher
        prf         :: HashPRF
        iterations  :: Iterations
        salt        :: Salt
        secret_data :: EncrypedCopyData

sg :: Safeguard
    = record
        names :: [Name]
    with inj_safeguard, prj_safeguard

ecd :: EncrypedCopyData
    = union
      | rsa     :: RSASecretData
      | aes     :: AESSecretData
      | clear   :: ClearText
      | no_data :: Void

rsd :: RSASecretData
    = record
        encrypted_key   :: RSAEncryptedKey
        aes_secret_data :: AESSecretData

asd :: AESSecretData
    = record
        iv           :: IV
        secret_data  :: SecretData

puk :: PublicKey
    = record
        size :: integer
        n    :: Integer
        e    :: Integer
    with inj_PublicKey, prj_PublicKey

prk :: PrivateKey
    = record
        pub  :: PublicKey
        d    :: Integer
        p    :: Integer
        q    :: Integer
        dP   :: Integer
        dQ   :: Integer
        qinv :: Integer
    with inj_PrivateKey, prj_PrivateKey

cph :: Cipher
    = enum
      | aes128
      | aes192
      | aes256

prf :: HashPRF
    = enum
      | sha1
      | sha256
      | sha512

ek :: EncryptionKey
    = union
      | public     :: PublicKey
      | private    :: PrivateKey
      | symmetric  :: AESKey
      | none       :: Void

fid :: FragmentID
    // name of a settings fragment
    = basic string

pat :: Pattern
    // a regular expression to match keynames
    = basic string
    with inj_pattern, prj_pattern

its :: Iterations
    = basic integer

octs :: Octets
    = basic integer

nm :: Name
    = basic string
    with inj_name, prj_name

idn :: Identity
    = basic string

sid :: SettingID
    = basic string

tid :: TriggerID
    = basic string

cmt :: Comment
    = basic string

ev :: EnvVar
    = basic string

ct :: ClearText
    = basic binary

slt :: Salt
    = basic binary

iv :: IV
    = basic binary

hd :: HashData
    = basic binary

aek :: AESKey
    = basic binary

sd :: SecretData
    = basic binary

rek :: RSAEncryptedKey
    = basic binary

rsb :: RSASecretBytes
    = basic binary

rsg :: RSASignature
    = basic binary

ep :: EncryptionPacket
    = basic binary

sp :: SignaturePacket
    = basic binary


void :: Void
    = basic integer

changes

// Initial version
version "0.0.0.1"

|]
