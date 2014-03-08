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
ks :: KeyStore
    // the keystore
    = record
        config :: Configuration
        keymap :: KeyMap

cfg :: Configuration
    = record
        settings :: Settings
        triggers :: TriggerMap

tmp :: TriggerMap
    = record
        map :: [Trigger]
    with inj_trigger_map, prj_trigger_map

trg :: Trigger
    = record
        id       :: TriggerID
        pattern  :: Pattern
        settings :: Settings

stgs :: Settings
    = record
        'json'   :: json
    with inj_settings, prj_settings

tja :: TextJsonAssoc
    = record
        id  :: SettingID
        key :: json

kmp :: KeyMap
    = record
        map :: [NameKeyAssoc]
    with inj_keymap, prj_keymap

nka :: NameKeyAssoc
    = record
        name :: Name
        key  :: Key

key :: Key
    = record
        name          :: Name
        comment       :: Comment
        identity      :: Identity
        is_binary     :: boolean
        env_var       :: ? EnvVar
        hash          :: ? Hash
        public        :: ? PublicKey
        secret_copies :: EncrypedCopyMap
        clear_text    :: ? ClearText
        clear_private :: ? PrivateKey
        created_at    :: utc

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

ecm :: EncrypedCopyMap
    = record
        map :: [EncrypedCopy]
    with inj_encrypted_copy_map, prj_encrypted_copy_map

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
