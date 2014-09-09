{-# LANGUAGE RecordWildCards            #-}

module Data.KeyStore.CLI
  ( cli
  , cli'
  , paramsParser
  , runParse
  ) where

import           Data.KeyStore.IO
import           Data.KeyStore.KS.Opt
import           Data.KeyStore.CLI.Command
import           Data.KeyStore.Version
import qualified Data.Text.IO                   as T
import qualified Data.ByteString.Char8          as B
import           Control.Applicative
import           Control.Monad
import           System.Exit


cli :: IO ()
cli = parseCLI >>= command Nothing

cli' :: Maybe CtxParams -> [String] -> IO ()
cli' mb args = parseCLI' args >>= command mb

command :: Maybe CtxParams -> CLI -> IO ()
command mb_cp CLI{..} =
 do ic <-
      case cli_command of
        Version      -> return oops
        Initialise _ -> return oops
        _            -> instanceCtx cp
    let ic_ro = ro ic
    case cli_command of
      Version                                   ->      putStrLn     version
      Keystore                                  ->      putStrLn =<< store ic
      Initialise               fp               ->      newKeyStore                     fp defaultSettings
      UpdateSettings           fp               ->      updateSettings   ic             fp
      ListSettings                              ->      listSettings     ic
      ListSettingOpts          mb               -> pt $ listSettingsOpts       mb
      AddTrigger         ti re fp               ->      addTrigger       ic       ti re fp
      RmvTrigger         ti                     ->      rmvTrigger       ic       ti
      ListTriggers                              ->      listTriggers     ic
      Create             nm cmt ide mbe mbf sgs ->      create           ic       nm cmt ide mbe mbf sgs
      CreateKeyPair      nm cmt ide         sgs ->      createRSAKeyPair ic       nm cmt ide         sgs
      Secure             nm             mbf sgs ->      secure           ic       nm         mbf sgs
      List                                      ->      list             ic_ro
      Info               nms                    ->      info             ic_ro    nms
      ShowIdentity    aa nm                     -> pr $ showIdentity     ic_ro aa nm
      ShowComment     aa nm                     -> pr $ showComment      ic_ro aa nm
      ShowDate        aa nm                     -> pr $ showDate         ic_ro aa nm
      ShowHash        aa nm                     -> pr $ showHash         ic_ro aa nm
      ShowHashComment aa nm                     -> pr $ showHashComment  ic_ro aa nm
      ShowHashSalt    aa nm                     -> pr $ showHashSalt     ic_ro aa nm
      ShowPublic aa nm                          -> pr $ showPublic       ic_ro aa nm
      ShowSecret aa nm                          -> pr $ showSecret       ic_ro aa nm
      Encrypt       nm  sfp dfp                 ->      encrypt          ic_ro    nm sfp dfp
      Decrypt           sfp dfp                 ->      decrypt          ic_ro       sfp dfp
      Sign          nm  sfp dfp                 ->      sign             ic       nm sfp dfp
      Verify            sfp dfp                 ->      verify_cli       ic_ro       sfp dfp
      Delete        nms                         ->      deleteKeys       ic       nms
  where
    pr p  = p >>= B.putStrLn
    pt    = T.putStrLn

    ro ic = ic { ic_ctx_params =
                    cli_params { cp_readonly = cp_readonly cp <|> Just True } }

    cp   =
      CtxParams
        { cp_store    = cp_store    cp_ <|> cp_store    cli_params
        , cp_debug    = cp_debug    cp_ <|> cp_debug    cli_params
        , cp_readonly = cp_readonly cp_ <|> cp_readonly cli_params
        }
      where
        cp_ = maybe defaultCtxParams id mb_cp



    oops  = error "command: this ic should not be used"

create :: IC
       -> Name
       -> Comment
       -> Identity
       -> Maybe EnvVar
       -> Maybe FilePath
       -> [Safeguard]
       -> IO ()
create ic nm cmt ide mbe mbf secs =
 do createKey ic nm cmt ide mbe Nothing
    secure ic nm mbf secs

secure :: IC -> Name -> Maybe FilePath -> [Safeguard] -> IO ()
secure ic nm mbf secs =
 do case mbf of
      Nothing -> const () <$> loadKey ic nm
      Just fp -> rememberKey ic nm fp
    mapM_ (secureKey ic nm) secs

info :: IC -> [Name] -> IO ()
info ic = mapM_ $ keyInfo ic

verify_cli :: IC -> FilePath -> FilePath -> IO ()
verify_cli ic m_fp s_fp =
 do ok <- verify ic m_fp s_fp
    when (not ok) exitFailure
