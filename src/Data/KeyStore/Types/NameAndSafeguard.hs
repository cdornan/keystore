{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Data.KeyStore.Types.NameAndSafeguard
    ( Name
    , name
    , _name
    , Safeguard
    , safeguard
    , safeguardKeys
    , isWildSafeguard
    , printSafeguard
    , parseSafeguard
    ) where

import           Data.KeyStore.Types.E
import qualified Data.Set                       as Set
import           Data.String
import           Data.Char
import qualified Control.Exception              as X

newtype Name
    = Name            { _Name            :: String       }
    deriving (Eq,Ord,IsString,Read,Show)

name :: String -> E Name
name s =
    case all is_nm_char s of
        True  -> Right $ Name s
        False -> Left  $ strMsg "bad name syntax"

_name :: Name -> String
_name = _Name


newtype Safeguard
    = Safeguard { _Safeguard :: Set.Set Name }
    deriving (Eq,Ord,Show)

instance IsString Safeguard where
    fromString s =
        case parseSafeguard s of
          Left err -> X.throw err
          Right sg -> sg


safeguard :: [Name] -> Safeguard
safeguard = Safeguard . Set.fromList

safeguardKeys :: Safeguard -> [Name]
safeguardKeys = Set.elems . _Safeguard

isWildSafeguard :: Safeguard -> Bool
isWildSafeguard = null . safeguardKeys

printSafeguard :: Safeguard -> String
printSafeguard (Safeguard st) =
    case Set.null st of
      True  -> "*"
      False -> map tr $ unwords $ map _name $ Set.elems st
  where
    tr ' ' = ','
    tr c   = c

parseSafeguard :: String -> E Safeguard
parseSafeguard s =
    case s of
      "*"             -> Right $ safeguard []
      _   | all chk s -> chk'  $ safeguard $ map Name $ words $ map tr s
          | otherwise -> oops
  where
    chk c   = c==',' || is_nm_char c

    chk' sg =
        case isWildSafeguard sg of
          True  -> oops
          False -> Right sg

    tr ','  = ' '
    tr c    = c

    oops    = Left $ strMsg "bad safeguard syntax"

is_nm_char :: Char -> Bool
is_nm_char c = isAscii c || isDigit c || c `Set.member` sg_sym_chs

sg_sym_chs :: Set.Set Char
sg_sym_chs = Set.fromList ".-_:'=#$%"

