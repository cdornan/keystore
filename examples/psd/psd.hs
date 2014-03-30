{-# LANGUAGE OverloadedStrings          #-}

module Main where

import           Data.KeyStore
import qualified Data.Text                      as T
import qualified Data.ByteString.Char8          as B
import           System.Directory
import           System.FilePath
import           Control.Applicative


ic :: IC
ic = instanceCtx_ $ CtxParams (Just ex_ks) True

ex_dir :: FilePath
ex_dir = "examples/psd"

ex_ini_stgs :: FilePath
ex_ini_stgs = ex_dir </> defaultSettingsFilePath

ex_ks :: FilePath
ex_ks = ex_dir </> defaultKeyStoreFilePath



{---------------------------
export KEY_pw_devel=pw_devel
export KEY_pw_stage=pw_stage
export KEY_pw_prodn=pw_prodn
---------------------------}


main :: IO ()
main =
 do ok <- doesFileExist ex_ks
    case ok of
      True  ->
            putStrLn "keystore present.\n"
      False ->
         do putStrLn "creating keystore.\n"
            stgs <- readSettings ex_ini_stgs
            newKeyStore ex_ks stgs
            mk_level production_level  Nothing
            mk_level staging_level     (Just production_level)
            mk_level development_level (Just staging_level)
    map _key_name <$> keys ic >>= mapM_ (info ic)


rm_psd :: IO ()
rm_psd = removeFile ex_ks


production_level, staging_level, development_level :: Level
production_level  = Level "production"  "prodn"
staging_level     = Level "staging"     "stage"
development_level = Level "development" "devel"

data Level
    = Level
        { lvl_name         :: String
        , lvl_kname_prefix :: String
        }
    deriving (Show)

lvl_config :: Level -> FilePath
lvl_config lvl = ex_dir </> lvl_kname_prefix lvl </> defaultSettingsFilePath

add_secrets :: String -> FilePath -> IO ()
add_secrets nm_s fp =
 do add_secret production_level  nm_s fp
    add_secret staging_level     nm_s fp
    add_secret development_level nm_s fp

add_dvl_secret :: String -> FilePath -> IO ()
add_dvl_secret = add_secret development_level

add_dvl_secret_ :: String -> B.ByteString -> IO ()
add_dvl_secret_ = add_secret_ development_level

add_secret :: Level -> String -> FilePath -> IO ()
add_secret lvl nm_s fp = B.readFile fp >>= add_secret_ lvl nm_s

add_secret_ :: Level -> String -> B.ByteString -> IO ()
add_secret_ lvl nm_s bs = createKey ic nm cmt ide Nothing (Just bs)
  where
    nm  = kname lvl nm_s
    cmt = Comment  $ T.pack $ "secret " ++ nm_s ++ " for " ++ lvl_name lvl
    ide = ""

mk_level :: Level -> (Maybe Level) -> IO ()
mk_level lvl mb =
 do add_password lvl
    add_save_key lvl
    add_trigger  lvl
    maybe (return ()) (backup_password lvl) mb

add_password :: Level -> IO ()
add_password lvl = createKey ic nm cmt ide (Just ev) Nothing
  where
    cmt = Comment  $ T.pack $ "password for " ++ lvl_name lvl
    ide = ""
    ev  = env_var nm

    nm  = pw_kname lvl

add_save_key :: Level -> IO ()
add_save_key lvl = createRSAKeyPair ic nm cmt ide [pw_sg]
  where
    nm    = save_kname lvl
    cmt   = Comment  $ T.pack $ "save key for " ++ lvl_name lvl
    ide   = ""
    pw_sg = safeguard [pw_kname lvl]

add_trigger :: Level -> IO ()
add_trigger lvl = addTrigger ic tid pat fp
  where
    tid = TriggerID $ T.pack $ lvl_name lvl
    pat = kpattern lvl
    fp  = lvl_config lvl

backup_password :: Level -> Level -> IO ()
backup_password lvl lvl' = secureKey ic (pw_kname lvl) sg
  where
    sg = safeguard [save_kname lvl']

pw_kname :: Level -> Name
pw_kname lvl = name' $ "pw_" ++ lvl_kname_prefix lvl

save_kname :: Level -> Name
save_kname lvl = name' $ "save_" ++ lvl_kname_prefix lvl

kname :: Level -> String -> Name
kname lvl nm_s = name' $ lvl_kname_prefix lvl ++ "_" ++ nm_s

kpattern :: Level -> Pattern
kpattern lvl = pattern $ "^" ++ lvl_kname_prefix lvl ++ "_.*"

env_var :: Name -> EnvVar
env_var = EnvVar . T.pack . ("KEY_" ++) . _name

subdir :: Level -> FilePath -> FilePath
subdir lvl fp = lvl_kname_prefix lvl </> fp

name' :: String -> Name
name' = either (error.show) id . name
