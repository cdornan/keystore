{-# LANGUAGE RecordWildCards            #-}

module Data.KeyStore.CLI (cli) where

import           Data.KeyStore.Command
import           Data.KeyStore
import qualified Data.ByteString.Char8          as B
import           Control.Applicative
import           Control.Monad
import           System.Exit


version :: String
version = "0.1.0.0"

cli :: IO ()
cli = parseCommand >>= command

command :: Command -> IO ()
command Command{..} =
 do ic <-
      case cmd_sub of
        Version     ->
             return $ instanceCtx_ cp
        Initialise _ ->
             return $ instanceCtx_ cp
        _ -> instanceCtx cp
    case cmd_sub of
      Version                                   ->      putStrLn version
      Initialise               fp               ->      newKeyStore                  fp defaultSettings
      UpdateSettings           fp               ->      updateSettings   ic          fp
      AddTrigger         ti pt fp               ->      addTrigger       ic    ti pt fp
      RmvTrigger         ti                     ->      rmvTrigger       ic    ti
      Create             nm cmt ide mbe mbf sgs ->      create           ic    nm cmt ide mbe mbf sgs
      CreateKeyPair      nm cmt ide         sgs ->      createRSAKeyPair ic    nm cmt ide         sgs
      Secure             nm             mbf sgs ->      secure           ic    nm         mbf sgs
      List                                      ->      list             ic
      Info               nms                    ->      info_cli         ic    nms
      ShowIdentity    aa nm                     -> pr $ showIdentity     ic aa nm
      ShowComment     aa nm                     -> pr $ showComment      ic aa nm
      ShowDate        aa nm                     -> pr $ showDate         ic aa nm
      ShowHash        aa nm                     -> pr $ showHash         ic aa nm
      ShowHashComment aa nm                     -> pr $ showHashComment  ic aa nm
      ShowHashSalt    aa nm                     -> pr $ showHashSalt     ic aa nm
      ShowPublic aa nm                          -> pr $ showPublic       ic aa nm
      ShowSecret aa nm                          -> pr $ showSecret       ic aa nm
      Encrypt       nm  sfp dfp                 ->      encrypt          ic    nm sfp dfp
      Decrypt           sfp dfp                 ->      decrypt          ic       sfp dfp
      Sign          nm  sfp dfp                 ->      sign             ic    nm sfp dfp
      Verify            sfp dfp                 ->      verify_cli       ic       sfp dfp
      Delete        nms                         ->      deleteKeys       ic    nms
  where
    pr p = p >>= B.putStrLn
    cp   = CtxParams
                { cp_store  = cmd_store
                , cp_debug  = cmd_debug
                }

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

info_cli :: IC -> [Name] -> IO ()
info_cli ic = mapM_ $ info ic

verify_cli :: IC -> FilePath -> FilePath -> IO ()
verify_cli ic m_fp s_fp =
 do ok <- verify ic m_fp s_fp
    when (not ok) exitFailure
