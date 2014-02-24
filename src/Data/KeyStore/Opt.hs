{-# LANGUAGE ExistentialQuantification  #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE OverloadedStrings          #-}

module Data.KeyStore.Opt
    ( Opt
    , getSettingsOpt
    , setSettingsOpt
    , opt__debug_enabled
    , opt__verify_enabled
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
    ) where

import           Data.KeyStore.Types
import           Data.Aeson
import qualified Data.Vector                    as V
import qualified Data.Map                       as Map
import qualified Data.HashMap.Strict            as HM
import           Data.Attoparsec.Number
import qualified Data.Text                      as T
import           Data.Maybe
import           Data.Char


data Opt a
    = Opt
        { opt_enum    :: OptEnum
        , opt_default :: a
        , opt_from    :: Value -> a
        , opt_to      :: a -> Value
        }


getSettingsOpt :: Opt a -> Settings -> a
getSettingsOpt Opt{..} (Settings hm) =
                maybe opt_default opt_from $ HM.lookup (opt_name opt_enum) hm

setSettingsOpt :: Opt a -> a -> Settings -> Settings
setSettingsOpt Opt{..} x (Settings hm) =
                  Settings $ HM.insert (opt_name opt_enum) (opt_to x) hm


opt__debug_enabled        :: Opt Bool
opt__debug_enabled        = bool_opt                            False       Debug__enabled

opt__verify_enabled       :: Opt Bool
opt__verify_enabled       = bool_opt                            False       Verify__enabled

opt__backup_keys          :: Opt [Name]
opt__backup_keys          = backup_opt                                      Backup__keys

opt__hash_comment         :: Opt Comment
opt__hash_comment         = text_opt (Comment   ,_Comment)      ""          Hash__comment

opt__hash_prf             :: Opt HashPRF
opt__hash_prf             = enum_opt  _text_HashPRF             PRF_sha512  Hash__prf

opt__hash_iterations      :: Opt Iterations
opt__hash_iterations      = intg_opt (Iterations,_Iterations)   5000        Hash__iterations

opt__hash_width_octets    :: Opt Octets
opt__hash_width_octets    = intg_opt (Octets    ,_Octets    )   64          Hash__width_octets

opt__hash_salt_octets     :: Opt Octets
opt__hash_salt_octets     = intg_opt (Octets    ,_Octets    )   16          Hash__salt_octets

opt__crypt_cipher         :: Opt Cipher
opt__crypt_cipher         = enum_opt  _text_Cipher              CPH_aes256  Crypt__cipher

opt__crypt_prf            :: Opt HashPRF
opt__crypt_prf            = enum_opt  _text_HashPRF             PRF_sha512  Crypt__prf

opt__crypt_iterations     :: Opt Iterations
opt__crypt_iterations     = intg_opt (Iterations,_Iterations)   5000        Crypt__iterations

opt__crypt_salt_octets    :: Opt Octets
opt__crypt_salt_octets    = intg_opt (Octets    ,_Octets    )   16          Crypt__salt_octets


data OptEnum
    = Debug__enabled
    | Verify__enabled
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
      Debug__enabled        -> Opt_ $ opt__debug_enabled
      Verify__enabled       -> Opt_ $ opt__verify_enabled
      Backup__keys          -> Opt_ $ opt__backup_keys
      Hash__comment         -> Opt_ $ opt__hash_comment
      Hash__prf             -> Opt_ $ opt__hash_prf
      Hash__iterations      -> Opt_ $ opt__hash_iterations
      Hash__width_octets    -> Opt_ $ opt__hash_width_octets
      Hash__salt_octets     -> Opt_ $ opt__hash_salt_octets
      Crypt__cipher         -> Opt_ $ opt__crypt_cipher
      Crypt__prf            -> Opt_ $ opt__crypt_prf
      Crypt__iterations     -> Opt_ $ opt__crypt_iterations
      Crypt__salt_octets    -> Opt_ $ opt__crypt_salt_octets


opt_name :: OptEnum -> T.Text
opt_name opt = T.pack $ map toLower grp ++ "." ++ drop 2 __nme
  where
    (grp,__nme) = splitAt (f (-1) ' ' so) so
      where
        f i _   []      = i+1
        f i '_' ('_':_) = i
        f i _    (h:t)  = f (i+1) h t

        so              = show opt

backup_opt :: OptEnum -> Opt [Name]
backup_opt ce =
    Opt
        { opt_enum    = ce
        , opt_default = []
        , opt_from    = frm
        , opt_to      = Array . V.fromList . map (String . T.pack . _name)
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

bool_opt ::     Bool -> OptEnum -> Opt Bool
bool_opt x0 ce =
    Opt
        { opt_enum    = ce
        , opt_default = x0
        , opt_from    = frm
        , opt_to      = Bool
        }
  where
    frm v =
        case v of
          Bool b -> b
          _      -> x0

intg_opt :: (Int->a,a->Int) -> a -> OptEnum -> Opt a
intg_opt (inj,prj) x0 ce =
    Opt
        { opt_enum    = ce
        , opt_default = x0
        , opt_from    = frm
        , opt_to      = Number . I . toInteger . prj
        }
  where
    frm v =
        case v of
          Number (I i) -> inj $ fromInteger i
          _            -> x0

text_opt :: (T.Text->a,a->T.Text) -> a -> OptEnum -> Opt a
text_opt (inj,prj) x0 ce =
    Opt
        { opt_enum    = ce
        , opt_default = x0
        , opt_from    = frm
        , opt_to      = String . prj
        }
  where
    frm v =
        case v of
          String t -> inj t
          _        -> x0

enum_opt :: (Bounded a,Enum a) => (a->T.Text) -> a -> OptEnum -> Opt a
enum_opt shw x0 ce =
    Opt
        { opt_enum    = ce
        , opt_default = x0
        , opt_from    = frm
        , opt_to      = String . shw
        }
  where
    frm v =
        case v of
          String s | Just x <- Map.lookup s mp -> x
          _                                    -> x0

    mp = Map.fromList [ (shw v,v) | v<-[minBound..maxBound] ]
