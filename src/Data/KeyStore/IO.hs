{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}

module Data.KeyStore.IO
    ( readSettings
    , CtxParams(..)
    , defaultCtxParams
    , defaultSettingsFilePath
    , settingsFilePath
    , defaultKeyStoreFilePath
    , determineCtx
    , establishState
    , newGenerator
    , readKeyStore
    , scanEnv
    , errorIO
    , logit
    ) where

import           Data.KeyStore.KeyStore
import           Data.KeyStore.Configuration
import           Data.KeyStore.KS
import           Data.KeyStore.Opt
import           Data.KeyStore.Types
import           Data.KeyStore.CPRNG
import           Data.API.Types
import           Data.Aeson
import           Data.Text                      as T
import qualified Data.Map                       as Map
import qualified Data.ByteString.Base64         as B64
import qualified Data.ByteString.Char8          as B
import qualified Data.ByteString.Lazy.Char8     as LBS
import           Data.Maybe
import           Data.Time
import qualified Control.Exception              as X
import           Control.Applicative
import           System.Environment
import           System.Directory
import           System.FilePath
import           System.IO
import           Safe


data CtxParams
    = CtxParams
        { cp_store  :: Maybe FilePath
        , cp_debug  :: Bool
        }

defaultCtxParams :: CtxParams
defaultCtxParams =
    CtxParams
        { cp_store  = Nothing
        , cp_debug  = False
        }

defaultSettingsFilePath :: FilePath
defaultSettingsFilePath = settingsFilePath "settings"

settingsFilePath :: String -> FilePath
settingsFilePath base = base ++ ".json"

defaultKeyStoreFilePath :: FilePath
defaultKeyStoreFilePath = "keystore.json"

determineCtx :: CtxParams -> IO (Ctx,State)
determineCtx CtxParams{..} =
 do str_fp_ <-
        case cp_store of
          Nothing ->
             do mb_ev_pth  <- lookupEnv "KEYSTORE"
                case mb_ev_pth of
                  Nothing ->
                     do pth <- mk_path
                        lu_path defaultKeyStoreFilePath pth $
                                                errorIO "keystore not found"
                  Just str_fp -> return str_fp
          Just str_fp -> return str_fp
    cwd <- getCurrentDirectory
    now <- getCurrentTime
    let str_fp = cwd </> str_fp_
        ctx0   = Ctx
                    { ctx_now      = now
                    , ctx_store    = str_fp
                    , ctx_settings = defaultSettings
                    }
    ks  <- readKeyStore ctx0
    g   <- newGenerator
    let st =
            State
                { st_keystore = ks
                , st_cprng    = g
                }
        sdbg = setSettingsOpt opt__debug_enabled cp_debug
        stg  = sdbg $ configurationSettings $ _ks_config ks
        ctx  = ctx0 { ctx_settings = stg }
    return (ctx,st)

establishState :: Ctx -> IO State
establishState ctx =
 do ks  <- readKeyStore ctx
    g   <- newGenerator
    return
        State
            { st_keystore = ks
            , st_cprng    = g
            }

newGenerator :: IO CPRNG
newGenerator = newCPRNG

readKeyStore :: Ctx -> IO KeyStore
readKeyStore ctx = ioE $ keyStoreFromBytes <$> LBS.readFile (ctx_store ctx)

scanEnv :: KeyStore -> IO (KeyStore,[LogEntry])
scanEnv ks = getCurrentTime >>= \now -> scanEnv' now ks

scanEnv' :: UTCTime -> KeyStore -> IO (KeyStore,[LogEntry])
scanEnv' now ks = s_e <$> mapM lu k_evs
  where
    lu (key,EnvVar enm) = fmap ((,) key) <$> lookupEnv (T.unpack enm)

    s_e mbs =
        case e of
          Left  _ -> error "scanEnv: unexpected error"
          Right _ -> (st_keystore st',les)
      where
        (e,st',les) = run_ ctx st0 $ mapM_ s_e' $ catMaybes mbs

    s_e' (key,sv) =
        case _key_is_binary key of
          False -> s_e'' key $ B.pack sv
          True  ->
            case B64.decode $ B.pack sv of
              Left  _  -> putStrKS $ _name(_key_name key) ++ ": " ++ T.unpack enm ++ ": base-64 decode failure"
              Right bs -> s_e'' key bs
      where
        EnvVar enm = fromJustNote "scan_env" $ _key_env_var key

    s_e'' Key{..} bs =
         do btw $ _name _key_name ++ " loaded\n"
            _ <- rememberKey _key_name (ClearText $ Binary bs)
            return ()

    k_evs = [ (key,ev) | key<-Map.elems mp, Just ev<-[_key_env_var key],
                                                isNothing(_key_clear_text key) ]

    mp    = _ks_keymap ks

    ctx   =
        Ctx
            { ctx_now      = now
            , ctx_store    = ""
            , ctx_settings = defaultSettings
            }

    st0   =
        State
            { st_cprng    = testCPRNG
            , st_keystore = ks
            }

readSettings :: FilePath -> IO Settings
readSettings fp =
 do lbs <- LBS.readFile fp
    case eitherDecode lbs of
      Left  msg -> errorIO msg
      Right val ->
        case val of
          Object hm -> return $ Settings hm
          _         -> errorIO "JSON object expected in the configuration file"

errorIO :: String -> IO a
errorIO msg = e2io $ Left $ strMsg msg

ioE :: IO (E a) -> IO a
ioE p = p >>= either X.throw return

logit :: Ctx -> LogEntry -> IO ()
logit ctx LogEntry{..} =
    case dbg || not le_debug of
      True  -> hPutStr h $ pfx ++ le_message
      False -> return ()
  where
    dbg = getSettingsOpt opt__debug_enabled $ ctx_settings ctx
    pfx = if le_debug then "(debug) " else ""
    h   = if le_debug then stderr     else stdout

lu_path :: FilePath -> [FilePath] -> IO FilePath -> IO FilePath
lu_path _  []       nope = nope
lu_path fp (dp:dps) nope =
 do fps <- getDirectoryContents dp `X.catch` \(_::X.SomeException) -> return []
    case fp `elem` fps of
      True  -> return $ dp </> fp
      False -> lu_path fp dps nope

mk_path :: IO [FilePath]
mk_path =
 do mb <- lookupEnv "HOME"
    return $
        [ "."                                ] ++
        [ hd </> ".keystore" | Just hd<-[mb] ] ++
        [ "/var/lib/keystore" ]
