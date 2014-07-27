{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}

module Main (main) where

import           Deploy.Deploy
import           Deploy.Command
import           Deploy.HostSectionKey
import           Data.KeyStore
import           Data.KeyStore                  as KS
import qualified Data.ByteString.Char8          as B
import qualified Data.ByteString.Lazy.Char8     as LBS
import qualified Data.Text.IO                   as T
import           System.IO
import           Control.Applicative
import           Control.Exception


ks_fp, ks_mac_fp :: FilePath
ks_fp     = "deploy-keystore.json"
ks_mac_fp = "deploy-keystore.hash"

main :: IO ()
main =
 do CLI{..} <- parseCLI
    let cp0 = cli_params
        cp  = cp0 { cp_store = cp_store cp0 <|> Just ks_fp }
    case cli_command of
      Create       -> initialise cp no_keys
      ListHosts    -> mapM_ (putStrLn . encode) $ [minBound..maxBound :: HostID]
      SampleScript -> mapM_  sample_ln            [minBound..maxBound]
      KS args      -> KS.cli' (Just cp) args
      _            ->
         do ic <- instanceCtx cp
            let ic_ro = ic { ic_ctx_params = cp {cp_readonly = cp_readonly cp <|> Just True} }
            case cli_command of
              Sign -> return ()
              _    -> verify_ks True ic_ro
            case cli_command of
              Create                      -> error "main: Initialise"
              Rotate          mbh mbs mbk -> rotate  ic    $ key_prededicate mbh mbs mbk
              Deploy          mb hst      -> deploy  ic_ro hst                        >>= write mb
              Sign                        -> sign_ks ic_ro
              Verify                      -> T.putStrLn "the keystore matches the signature"
              ListHosts                   -> error "main: ListHosts"
              InfoKey         mbk         -> T.putStr $ keyHelp mbk
              InfoSection     mbs         -> sectionHelp mbs                          >>= T.putStr
              SecretScript                -> secretKeySummary ic sections             >>= T.putStr
              PublicScript                -> publicKeySummary ic sections ks_mac_fp   >>= T.putStr
              SampleScript                -> error "main: SampleScript"
              KS              _           -> error "main: KS"
            verify_ks False ic_ro

sign_ks :: IC -> IO ()
sign_ks ic = signKeystore ic sections >>= B.writeFile ks_mac_fp

verify_ks :: Bool -> IC -> IO ()
verify_ks fatal ic = chk =<< catch (B.readFile ks_mac_fp >>= verifyKeystore ic) hdl
  where
    chk True              = return ()
    chk False | fatal     = error msg
              | otherwise = hPutStrLn stderr msg

    hdl (se :: SomeException) =
                error $ "failure during keystore verification: " ++ show se

    msg = "the signature does not match the keystore"

no_keys :: KeyPredicate HostID SectionID KeyID
no_keys = noKeys

key_prededicate :: Maybe HostID -> Maybe SectionID -> Maybe KeyID -> KeyPredicate HostID SectionID KeyID
key_prededicate = keyPrededicate

sample_ln :: SectionID -> IO ()
sample_ln s = putStrLn $ "export " ++ "KEY_pw_" ++ s_ ++ "=pw_" ++ s_ ++ ";"
  where
    s_ = encode s

write :: Maybe FilePath -> LBS.ByteString -> IO ()
write = maybe LBS.putStrLn LBS.writeFile
