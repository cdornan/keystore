{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}

module Main (main) where

import           Deploy.Deploy
import           Deploy.Command
import           Deploy.HostSectionKey
import           Data.KeyStore
import           Data.API.Types
import           Data.KeyStore                  as KS
import qualified Data.ByteString.Char8          as B
import qualified Data.ByteString.Lazy.Char8     as LBS
import qualified Data.Text                      as T
import qualified Data.Text.IO                   as T
import           Data.List
import           System.IO
import           System.Environment
import           System.SetEnv
import           System.Process
import           Control.Applicative
import           Control.Exception


ks_fp, ks_mac_fp :: FilePath
ks_fp     = "deploy-keystore.json"
ks_mac_fp = "deploy-keystore.hash"

pmc :: PMConfig SectionID
pmc =
  PMConfig
    { _pmc_location       = "pwstore.dat"
    , _pmc_env_var        = "DEPLOY_MASTER"
    , _pmc_keystore_msg   = "keystore not found (use 'deploy pm setup' to set one up)"
    , _pmc_password_msg   = "not logged into the password manager (use 'deploy pm login')"
    , _pmc_shell          = interactive_shell
    , _pmc_hash_descr     = defaultHashDescription $ Salt $ Binary "MX#0YoSCt8RcWm&E"
    , _pmc_allow_dumps    = True
    , _pmc_dump_prefix    = dump_pfx
    , _pmc_sample_script  = Just $ defaultSampleScript (PW_ :: PW_ SectionID) dump_pfx
    , _pmc_plus_env_var   = \(PasswordName nm) -> Just $ EnvVar $ T.concat ["DEPLOY_PW_",nm]
    }
  where
    dump_pfx = "deploy pm"

main :: IO ()
main =
 do CLI{..} <- parseCLI
    let cp0 = cli_params
        cp  = cp0 { cp_store = cp_store cp0 <|> Just ks_fp }
    case cli_command of
      Create                -> collect pmc create_cc >> initialise cp no_keys
      ListHosts             -> mapM_ (putStrLn . encode) $ [minBound..maxBound :: HostID]
      SampleScript          -> mapM_  sample_ln            [minBound..maxBound]
      KS args               -> collect pmc deploy_cc >> KS.cli' (Just cp) args
      PM args               -> passwordManager pmc args
      _                     ->
         do case cli_command of
              Client -> collect pmc client_cc
              _      -> collect pmc deploy_cc
            ic <- instanceCtx cp
            let ic_ro = ic { ic_ctx_params = cp {cp_readonly = cp_readonly cp <|> Just True} }
            case cli_command of
              Sign -> return ()
              _    -> verify_ks True ic_ro
            case cli_command of
              Create                      -> error "main: Initialise"
              Rotate          mbh mbs mbk -> rotate          ic $ key_prededicate mbh mbs mbk
              RotateSmart     mbh mbs mbk -> rotateIfChanged ic $ key_prededicate mbh mbs mbk
              Deploy    False mb hst      -> deploy ic_ro hst           >>= write mb
              Deploy    True  _  _        -> interactive_shell
              Client                      -> lookupEnv "KEY_pw_session" >>= putStrLn . ("session-token=>" ++) . maybe "NONE" id
              Sign                        -> sign_ks ic_ro
              Verify                      -> T.putStrLn "the keystore matches the signature"
              ListHosts                   -> error "main: ListHosts"
              InfoKey         mbk         -> T.putStr $ keyHelp mbk
              InfoSection     mbs         -> sectionHelp mbs                          >>= T.putStr
              SecretScript                -> secretKeySummary ic sections             >>= T.putStr
              PublicScript                -> publicKeySummary ic sections ks_mac_fp   >>= T.putStr
              SampleScript                -> error "main: SampleScript"
              KS              _           -> error "main: KS"
              PM              _           -> error "main: PM"
            verify_ks False ic_ro

create_cc, deploy_cc, client_cc :: CollectConfig SectionID
create_cc = CollectConfig True                         [minBound..maxBound]
deploy_cc = CollectConfig True  $ filter (/=S_session) [minBound..maxBound]
client_cc = CollectConfig False                        [S_session]

sign_ks :: IC -> IO ()
sign_ks ic = signKeystore ic sections >>= B.writeFile ks_mac_fp

verify_ks :: Bool -> IC -> IO ()
verify_ks fatal ic = chk =<< catch (B.readFile ks_mac_fp >>= verifyKeystore ic sections) hdl
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
sample_ln s = putStrLn $ "export " ++ v_ ++ "=secret-" ++ s_ ++ ";"
  where
    v_ = T.unpack $ _EnvVar $ enVar s
    s_ = encode s

interactive_shell :: IO ()
interactive_shell = do
  sh <- maybe "/bin/bash" id <$> lookupEnv "SHELL"
  putStrLn $ "launching password-manager shell => " ++ sh
  case "zsh" `isInfixOf` sh of
    True  -> do
      setEnv "ZDOTDIR" "examples/deploy/zshenv"
      callProcess sh ["-i"]
    False -> callProcess sh ["-i"]
  putStrLn "password-manager shell done"

write :: Maybe FilePath -> LBS.ByteString -> IO ()
write = maybe LBS.putStrLn LBS.writeFile
