{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}

module Main (main) where

import           Deploy.Deploy
import           Deploy.Cmd

import           Deploy.HostSectionKey
import           Control.Applicative
import           Control.Exception
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
import           System.Process
import qualified System.SetEnv                  as SE


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
main = do
    CtxCmd{..} <- parseCLI pmc
    let cp0 = cc_params
        cp  = cp0 { cp_store = cp_store cp0 <|> Just ks_fp }
    case cc_cmd of
      C_create              -> collect pmc create_cc >> initialise cp no_keys
      C_list_hosts          -> mapM_ (putStrLn . encode) $ [minBound..maxBound :: HostID]
      C_sample_script       -> mapM_  sample_ln            [minBound..maxBound]
      C_ks ks_cmd           -> collect pmc deploy_cc >> KS.execute (Just cp) ks_cmd
      C_pm pm_cmd           -> passwordManager' pmc pm_cmd
      _                     ->
         do case cc_cmd of
              C_client -> collect pmc client_cc
              _        -> collect pmc deploy_cc
            ic <- instanceCtx cp
            let ic_ro = ic { ic_ctx_params = cp {cp_readonly = cp_readonly cp <|> Just True} }
            case cc_cmd of
              C_sign -> return ()
              _      -> verify_ks True ic_ro
            case cc_cmd of
              C_create                      -> error "main: Initialise"
              C_rotate          mbh mbs mbk -> rotate          ic $ key_prededicate mbh mbs mbk
              C_rotate_smart    mbh mbs mbk -> rotateIfChanged ic $ key_prededicate mbh mbs mbk
              C_deploy    False mb hst      -> deploy ic_ro hst           >>= write mb
              C_deploy    True  _  _        -> interactive_shell
              C_client                      -> lookupEnv "KEY_pw_session" >>= putStrLn . ("session-token=>" ++) . maybe "NONE" id
              C_sign                        -> sign_ks ic_ro
              C_verify                      -> T.putStrLn "the keystore matches the signature"
              C_list_hosts                  -> error "main: ListHosts"
              C_info_key        mbk         -> T.putStr $ keyHelp mbk
              C_info_section    mbs         -> sectionHelp mbs                          >>= T.putStr
              C_secret_script               -> secretKeySummary ic sections             >>= T.putStr
              C_public_script               -> publicKeySummary ic sections ks_mac_fp   >>= T.putStr
              C_sample_script               -> error "main: SampleScript"
              C_ks              _           -> error "main: KS"
              C_pm              _           -> error "main: PM"
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
      SE.setEnv "ZDOTDIR" "examples/deploy/zshenv"
      callProcess sh ["-i"]
    False -> callProcess sh ["-i"]
  putStrLn "password-manager shell done"

write :: Maybe FilePath -> LBS.ByteString -> IO ()
write = maybe LBS.putStrLn LBS.writeFile
