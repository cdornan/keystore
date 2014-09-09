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

import           Data.KeyStore.Types.PasswordStoreSchema
import qualified Data.Map                                 as Map
import           Data.API.Tools
import           Data.API.JSON


$(generate passwordStoreSchema)


-- The PasswordStre and SessionMap association lists are represented internally
-- with maps.


type PasswordMap = Map.Map PasswordName Password

inj_pwmap :: REP__PasswordMap -> ParserWithErrs PasswordMap
inj_pwmap (REP__PasswordMap as) =
  return $ Map.fromList [ (_npa_name,_npa_password) | NamePasswordAssoc{..}<-as ]

prj_pwmap :: PasswordMap -> REP__PasswordMap
prj_pwmap mp = REP__PasswordMap [ NamePasswordAssoc nme pwd | (nme,pwd)<-Map.toList mp ]


type SessionMap = Map.Map SessionName Session

inj_snmap :: REP__SessionMap -> ParserWithErrs SessionMap
inj_snmap (REP__SessionMap as) =
  return $ Map.fromList [ (_spa_name,_spa_session) | SessionPasswordAssoc{..}<-as ]

prj_snmap :: SessionMap -> REP__SessionMap
prj_snmap mp = REP__SessionMap [ SessionPasswordAssoc snm ssn | (snm,ssn)<-Map.toList mp ]


$(generateAPITools passwordStoreSchema
                   [ enumTool
                   , jsonTool
                   , lensTool
                   ])
