{-# LANGUAGE ExistentialQuantification  #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE OverloadedStrings          #-}

module Data.KeyStore.KS.Opt
    ( Opt
    , OptEnum(..)
    , opt_enum
    , getSettingsOpt
    , getSettingsOpt'
    , setSettingsOpt
    , opt__debug_enabled
    , opt__verify_enabled
    , opt__sections_fix
    , opt__backup_keys
    , opt__hash_comment
    , opt__hash_prf
    , opt__hash_iterations
    , opt__hash_width_octets
    , opt__hash_salt_octets
    , opt__crypt_cipher
    , opt__crypt_prf
    , opt__crypt_iterations
    , opt__crypt_salt_octets
    , Opt_(..)
    , opt_
    , listSettingsOpts
    , optHelp
    , optName
    , parseOpt
    ) where

import           Data.KeyStore.Types
import qualified Data.Vector                    as V
import qualified Data.Map                       as Map
import qualified Data.ByteString.Lazy.Char8     as LBS
import qualified Data.HashMap.Strict            as HM
import           Data.Aeson
import qualified Data.Text                      as T
import           Data.Monoid
import           Data.Maybe
import           Data.Char
import           Text.Printf
import           Control.Applicative


data Opt a
    = Opt
        { opt_enum    :: OptEnum
        , opt_default :: a
        , opt_from    :: Value -> a
        , opt_to      :: a -> Value
        , opt_help    :: Help
        }

data Help
    = Help
        { hlp_text :: [T.Text]
        , hlp_type :: T.Text
        }
    deriving Show

getSettingsOpt :: Opt a -> Settings -> a
getSettingsOpt opt = maybe (opt_default opt) id . getSettingsOpt' opt

getSettingsOpt' :: Opt a -> Settings -> Maybe a
getSettingsOpt' Opt{..} (Settings hm) = opt_from <$> HM.lookup (optName opt_enum) hm

setSettingsOpt :: Opt a -> a -> Settings -> Settings
setSettingsOpt Opt{..} x (Settings hm) =
                  Settings $ HM.insert (optName opt_enum) (opt_to x) hm


opt__debug_enabled        :: Opt Bool
opt__debug_enabled        = bool_opt dbg_help                            False       Debug__enabled

opt__verify_enabled       :: Opt Bool
opt__verify_enabled       = bool_opt vfy_help                            False       Verify__enabled

opt__sections_fix         :: Opt Bool
opt__sections_fix         = bool_opt sfx_help                            False       Sections__fix

opt__backup_keys          :: Opt [Name]
opt__backup_keys          = backup_opt bku_help                                      Backup__keys

opt__hash_comment         :: Opt Comment
opt__hash_comment         = text_opt hcm_help (Comment   ,_Comment)      ""          Hash__comment

opt__hash_prf             :: Opt HashPRF
opt__hash_prf             = enum_opt hpr_help  _text_HashPRF             PRF_sha512  Hash__prf

opt__hash_iterations      :: Opt Iterations
opt__hash_iterations      = intg_opt hit_help (Iterations,_Iterations)   5000        Hash__iterations

opt__hash_width_octets    :: Opt Octets
opt__hash_width_octets    = intg_opt hwd_help (Octets    ,_Octets    )   64          Hash__width_octets

opt__hash_salt_octets     :: Opt Octets
opt__hash_salt_octets     = intg_opt hna_help (Octets    ,_Octets    )   16          Hash__salt_octets

opt__crypt_cipher         :: Opt Cipher
opt__crypt_cipher         = enum_opt ccy_help  _text_Cipher              CPH_aes256  Crypt__cipher

opt__crypt_prf            :: Opt HashPRF
opt__crypt_prf            = enum_opt cpr_help  _text_HashPRF             PRF_sha512  Crypt__prf

opt__crypt_iterations     :: Opt Iterations
opt__crypt_iterations     = intg_opt cit_help (Iterations,_Iterations)   5000        Crypt__iterations

opt__crypt_salt_octets    :: Opt Octets
opt__crypt_salt_octets    = intg_opt cna_help (Octets    ,_Octets    )   16          Crypt__salt_octets


data OptEnum
    = Debug__enabled
    | Verify__enabled
    | Sections__fix
    | Backup__keys
    | Hash__comment
    | Hash__prf
    | Hash__iterations
    | Hash__width_octets
    | Hash__salt_octets
    | Crypt__cipher
    | Crypt__prf
    | Crypt__iterations
    | Crypt__salt_octets
    deriving (Bounded,Enum,Eq,Ord,Show)

data Opt_ = forall a. Opt_ (Opt a)

opt_ :: OptEnum -> Opt_
opt_ enm =
    case enm of
      Debug__enabled        -> Opt_ opt__debug_enabled
      Verify__enabled       -> Opt_ opt__verify_enabled
      Sections__fix         -> Opt_ opt__sections_fix
      Backup__keys          -> Opt_ opt__backup_keys
      Hash__comment         -> Opt_ opt__hash_comment
      Hash__prf             -> Opt_ opt__hash_prf
      Hash__iterations      -> Opt_ opt__hash_iterations
      Hash__width_octets    -> Opt_ opt__hash_width_octets
      Hash__salt_octets     -> Opt_ opt__hash_salt_octets
      Crypt__cipher         -> Opt_ opt__crypt_cipher
      Crypt__prf            -> Opt_ opt__crypt_prf
      Crypt__iterations     -> Opt_ opt__crypt_iterations
      Crypt__salt_octets    -> Opt_ opt__crypt_salt_octets


listSettingsOpts :: Maybe OptEnum -> T.Text
listSettingsOpts Nothing   = T.unlines $ map optName [minBound..maxBound]
listSettingsOpts (Just oe) = optHelp oe

optHelp :: OptEnum -> T.Text
optHelp = help . opt_

help :: Opt_ -> T.Text
help (Opt_ Opt{..}) = T.unlines $ map f
    [ (,) pth           ""
    , (,) "  type:"     hlp_type
    , (,) "  default:"  dflt
    , (,) ""            ""
    ] <> map ("  "<>) hlp_text
  where
    f (l,v) = T.pack $ printf "%-12s %s" (T.unpack l) (T.unpack v)

    pth     = optName opt_enum

    dflt    = T.pack $ LBS.unpack $ encode $ opt_to opt_default

    Help{..} = opt_help

optName :: OptEnum -> T.Text
optName opt = T.pack $ map toLower grp ++ "." ++ drop 2 __nme
  where
    (grp,__nme) = splitAt (f (-1) ' ' so) so
      where
        f i _   []      = i+1
        f i '_' ('_':_) = i
        f i _    (h:t)  = f (i+1) h t

        so              = show opt

parseOpt :: T.Text -> Maybe OptEnum
parseOpt txt = listToMaybe [ oe | oe<-[minBound..maxBound], optName oe==txt ]

backup_opt :: [T.Text] -> OptEnum -> Opt [Name]
backup_opt hp ce =
    Opt
        { opt_enum    = ce
        , opt_default = []
        , opt_from    = frm
        , opt_to      = Array . V.fromList . map (String . T.pack . _name)
        , opt_help    = Help hp "[<string>]"
        }
  where
    frm  val =
        case val of
          Array v -> catMaybes $ map extr $ V.toList v
          _       -> []

    extr val =
        case val of
          String t | Right nm <- name $ T.unpack t -> Just nm
          _                                        -> Nothing

bool_opt ::     [T.Text] -> Bool -> OptEnum -> Opt Bool
bool_opt hp x0 ce =
    Opt
        { opt_enum    = ce
        , opt_default = x0
        , opt_from    = frm
        , opt_to      = Bool
        , opt_help    = Help hp "<boolean>"
        }
  where
    frm v =
        case v of
          Bool b -> b
          _      -> x0

intg_opt :: [T.Text] -> (Int->a,a->Int) -> a -> OptEnum -> Opt a
intg_opt hp (inj,prj) x0 ce =
    Opt
        { opt_enum    = ce
        , opt_default = x0
        , opt_from    = frm
        , opt_to      = toJSON . prj
        , opt_help    = Help hp "<integer>"
        }
  where
    frm v =
        case fromJSON v of
          Success i -> inj i
          _         -> x0

text_opt :: [T.Text] -> (T.Text->a,a->T.Text) -> a -> OptEnum -> Opt a
text_opt hp (inj,prj) x0 ce =
    Opt
        { opt_enum    = ce
        , opt_default = x0
        , opt_from    = frm
        , opt_to      = String . prj
        , opt_help    = Help hp "<string>"
        }
  where
    frm v =
        case v of
          String t -> inj t
          _        -> x0

enum_opt :: (Bounded a,Enum a) => [T.Text] -> (a->T.Text) -> a -> OptEnum -> Opt a
enum_opt hp shw x0 ce =
    Opt
        { opt_enum    = ce
        , opt_default = x0
        , opt_from    = frm
        , opt_to      = String . shw
        , opt_help    = Help hp typ
       }
  where
    frm v =
        case v of
          String s | Just x <- Map.lookup s mp -> x
          _                                    -> x0

    mp    = Map.fromList [ (shw v,v) | v<-[minBound..maxBound] ]

    typ   = T.intercalate "|" $ map shw [minBound..maxBound]

dbg_help, vfy_help, sfx_help, bku_help, hcm_help, hpr_help, hit_help, hwd_help,
    hna_help, ccy_help, cpr_help, cit_help, cna_help :: [T.Text]

dbg_help =
  ["Controls whether debug output is enabled or not."
  ]
vfy_help =
  [ "Controls whether verification mode is enabled or not,"
  , "in which the secret text loaded from environment"
  , "variables is checked against the stored MACs."
  , "These checks can consume a lot of compute time."
  ]
sfx_help =
  [ "Set when a 'Sections' keystore has been fixed so that"
  , "section, key and host names no longer contrained to avoid"
  , "prefixes."
  ]
bku_help =
  [ "Controls the default keys that will be used to make secret copies"
  , "(i.e., backup) each key. Each key may individually specify their"
  , "backup/save keys which will operate in addition to those specify here."
  , "This setting usually set to empty globally accross a keystore but"
  , "triggered to backup keys on a per-section basis with the section's"
  , "backup key."
  ]
hcm_help =
  [ "Controls the default comment attribute for hashes."
  ]
hpr_help =
  [ "Controls the default psuedo-random/hash function used in the PBKDF2"
  , "function used to generate the MACs."
  ]
hit_help =
  [ "Controls the default number of iterations used in the PBKDF2"
  , "function used to generate the MACs."
  ]
hwd_help =
  [ "Controls the default width (in bytes) of the output of the PBKDF2"
  , "function used to generate the MACs."
  ]
hna_help =
  [ "Controls the default width (in bytes) of the salt generated for the PBKDF2"
  , "function used to generate the MACs."
  ]
ccy_help =
  [ "Controls the default cipher used to encrypt the keys."
  ]
cpr_help =
  [ "Controls the default psuedo-random/hash function used in the PBKDF2."
  , "function used to generate the cipher keys."
  ]
cit_help =
  [ "Controls the default number of iterations used in the PBKDF2"
  , "function used to generate cipher keys."
  ]
cna_help =
  [ "Controls the default width (in bytes) of the salt generated for the PBKDF2"
  , "function used to generate cipher keys."
  ]
