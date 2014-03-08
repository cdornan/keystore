{-# LANGUAGE RecordWildCards            #-}

module Data.KeyStore.CLI (cli) where

import           Data.KeyStore.Command
import qualified Data.KeyStore.Interactive      as I
import           Data.KeyStore.Types
import qualified Data.ByteString.Char8          as B
import           Control.Applicative
import           Control.Monad
import           System.Exit


cli :: IO ()
cli = parseCommand >>= command

command :: Command -> IO ()
command Command{..} =
 do ic <-
      case cmd_sub of
        Initialise _ ->
             return $ I.instanceCtx_ cp
        _ -> I.instanceCtx cp
    case cmd_sub of
      Initialise               fp               ->      I.newKeyStore                  fp defaultSettings
      UpdateSettings           fp               ->      I.updateSettings   ic          fp
      AddTrigger         ti pt fp               ->      I.addTrigger       ic    ti pt fp
      RmvTrigger         ti                     ->      I.rmvTrigger       ic    ti
      Create             nm cmt ide mbe mbf sgs ->        create           ic    nm cmt ide mbe mbf sgs
      CreateKeyPair      nm cmt ide         sgs ->      I.createRSAKeyPair ic    nm cmt ide         sgs
      Secure             nm             mbf sgs ->        secure           ic    nm         mbf sgs
      List                                      ->      I.list             ic
      Info               nms                    ->        info             ic    nms
      ShowIdentity    aa nm                     -> pr $ I.showIdentity     ic aa nm
      ShowComment     aa nm                     -> pr $ I.showComment      ic aa nm
      ShowDate        aa nm                     -> pr $ I.showDate         ic aa nm
      ShowHash        aa nm                     -> pr $ I.showHash         ic aa nm
      ShowHashComment aa nm                     -> pr $ I.showHashComment  ic aa nm
      ShowHashSalt    aa nm                     -> pr $ I.showHashSalt     ic aa nm
      ShowPublic aa nm                          -> pr $ I.showPublic       ic aa nm
      ShowSecret aa nm                          -> pr $ I.showSecret       ic aa nm
      Encrypt       nm  sfp dfp                 ->      I.encrypt          ic    nm sfp dfp
      Decrypt           sfp dfp                 ->      I.decrypt          ic       sfp dfp
      Sign          nm  sfp dfp                 ->      I.sign             ic    nm sfp dfp
      Verify            sfp dfp                 ->        verify           ic       sfp dfp
      Delete        nms                         ->      I.deleteKeys       ic    nms
  where
    pr p = p >>= B.putStrLn
    cp   = I.CtxParams
                { cp_store  = cmd_store
                , cp_debug  = cmd_debug
                }

create :: I.IC
       -> Name
       -> Comment
       -> Identity
       -> Maybe EnvVar
       -> Maybe FilePath
       -> [Safeguard]
       -> IO ()
create ic nm cmt ide mbe mbf secs =
 do I.createKey ic nm cmt ide mbe Nothing
    secure ic nm mbf secs

secure :: I.IC -> Name -> Maybe FilePath -> [Safeguard] -> IO ()
secure ic nm mbf secs =
 do case mbf of
      Nothing -> const () <$> I.loadKey ic nm
      Just fp -> I.rememberKey ic nm fp
    mapM_ (I.secureKey ic nm) secs

info :: I.IC -> [Name] -> IO ()
info ic = mapM_ $ I.info ic

verify :: I.IC -> FilePath -> FilePath -> IO ()
verify ic m_fp s_fp =
 do ok <- I.verify ic m_fp s_fp
    when (not ok) exitFailure
