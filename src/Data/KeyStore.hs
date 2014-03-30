{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE ScopedTypeVariables        #-}

module Data.KeyStore
    ( readSettings
    , CtxParams(..)
    , IC
    , module Data.KeyStore.Types
    , defaultSettingsFilePath
    , settingsFilePath
    , defaultKeyStoreFilePath
    , defaultCtxParams
    , instanceCtx
    , instanceCtx_
    , newKeyStore
    , listSettings
    , settings
    , updateSettings
    , listTriggers
    , triggers
    , addTrigger
    , rmvTrigger
    , createRSAKeyPair
    , createKey
    , adjustKey
    , rememberKey
    , rememberKey_
    , secureKey
    , loadKey
    , showIdentity
    , showComment
    , showDate
    , showHash
    , showHashComment
    , showHashSalt
    , showPublic
    , showSecret
    , keys
    , list
    , info
    , deleteKeys
    , encrypt
    , encrypt_
    , encrypt__
    , decrypt
    , decrypt_
    , decrypt__
    , sign
    , sign_
    , verify
    , verify_
    , run
    ) where

import           Data.KeyStore.IO
import qualified Data.KeyStore.KeyStore         as KS
import qualified Data.KeyStore.Crypto           as C
import           Data.KeyStore.KS
import           Data.KeyStore.Types
import           Data.API.Types
import           Data.IORef
import           Data.Aeson
import qualified Data.Text                      as T
import qualified Data.ByteString.Char8          as B
import qualified Data.ByteString.Lazy.Char8     as LBS
import qualified Data.ByteString.Base64         as B64
import qualified Data.Map                       as Map
import           Data.Time
import           Text.Printf
import           Control.Applicative
import qualified Control.Exception              as X
import           Control.Lens
import           System.IO
import           System.Locale


-- |

instanceCtx :: CtxParams -> IO IC
instanceCtx cp =
 do ctx_st <- get $ instanceCtx_ cp
    IC cp . Just <$> newIORef ctx_st

instanceCtx_ :: CtxParams -> IC
instanceCtx_ cp = IC cp Nothing

newKeyStore :: FilePath -> Settings -> IO ()
newKeyStore str_fp stgs =
 do ei <- X.try $ B.readFile str_fp :: IO (Either X.SomeException B.ByteString)
    either (const $ return ()) (const $ errorIO "keystore file exists") ei
    g  <- newGenerator
    let state =
            State
                { st_keystore = emptyKeyStore $ defaultConfiguration stgs
                , st_cprng    = g
                }
    LBS.writeFile str_fp $ KS.keyStoreBytes $ st_keystore state

listSettings :: IC -> IO ()
listSettings ic = settings ic >>= LBS.putStrLn . encode

settings :: IC -> IO Settings
settings ic = run ic $ _cfg_settings <$> getConfig

updateSettings :: IC -> FilePath -> IO ()
updateSettings ic fp =
 do bs   <- LBS.readFile fp
    stgs <- e2io $ KS.settingsFromBytes bs
    run ic $ modConfig $ over cfg_settings $ const stgs

listTriggers :: IC -> IO ()
listTriggers ic = triggers ic >>= putStr . unlines . map fmt
  where
    fmt Trigger{..} = printf "%-12s : %12s => %s" id_s pat_s stgs_s
      where
        id_s   = T.unpack   $ _TriggerID                  _trg_id
        pat_s  = _pat_string                              _trg_pattern
        stgs_s = LBS.unpack $ encode $ Object $ _Settings _trg_settings

triggers :: IC -> IO [Trigger]
triggers ic = run ic $ Map.elems . _cfg_triggers <$> getConfig

addTrigger :: IC -> TriggerID -> Pattern -> FilePath -> IO ()
addTrigger ic tid pat fp =
 do bs   <- LBS.readFile fp
    stgs <- e2io $ KS.settingsFromBytes bs
    run ic $ modConfig $ over cfg_triggers $ Map.insert tid $ Trigger tid pat stgs

rmvTrigger :: IC -> TriggerID -> IO ()
rmvTrigger ic tid = run ic $ modConfig $ over cfg_triggers $ Map.delete tid

createRSAKeyPair :: IC -> Name -> Comment -> Identity -> [Safeguard] -> IO ()
createRSAKeyPair ic nm cmt ide sgs = run ic $ KS.createRSAKeyPair nm cmt ide sgs

createKey :: IC
          -> Name
          -> Comment
          -> Identity
          -> Maybe EnvVar
          -> Maybe B.ByteString
          -> IO ()
createKey ic nm cmt ide mb_ev mb_bs =
            run ic $ KS.createKey nm cmt ide mb_ev (ClearText . Binary <$> mb_bs)

adjustKey :: IC -> Name -> (Key->Key) -> IO ()
adjustKey ic nm adj = run ic $ adjustKeyKS nm adj

rememberKey :: IC -> Name -> FilePath -> IO ()
rememberKey ic nm fp = B.readFile fp >>= rememberKey_ ic nm

rememberKey_ :: IC -> Name -> B.ByteString -> IO ()
rememberKey_ ic nm bs = run ic $ KS.rememberKey nm $ ClearText $ Binary bs

secureKey :: IC -> Name -> Safeguard -> IO ()
secureKey ic nm nms = run ic $ KS.secureKey nm nms

loadKey :: IC -> Name -> IO Key
loadKey ic nm = run ic $ KS.loadKey nm

showIdentity :: IC -> Bool -> Name -> IO B.ByteString
showIdentity ic = show_it' ic "identity" (Just . _key_identity) (B.pack . T.unpack . _Identity)

showComment :: IC -> Bool -> Name -> IO B.ByteString
showComment ic = show_it' ic "comment"  (Just . _key_comment)  (B.pack . T.unpack . _Comment )

showDate :: IC -> Bool -> Name -> IO B.ByteString
showDate ic = show_it' ic "date" (Just . _key_created_at) (B.pack . formatTime defaultTimeLocale fmt)
  where
    fmt = "%F-%TZ"

showHash :: IC -> Bool -> Name -> IO B.ByteString
showHash ic = show_it ic "hash" (fmap _hash_hash . _key_hash) _HashData

showHashComment :: IC -> Bool -> Name -> IO B.ByteString
showHashComment ic = show_it' ic "hash" _key_hash cmt
  where
    cmt = B.pack . T.unpack . _Comment . _hashd_comment . _hash_description

showHashSalt :: IC -> Bool -> Name -> IO B.ByteString
showHashSalt ic = show_it ic "hash" (fmap (_hashd_salt . _hash_description) . _key_hash) _Salt

showPublic  :: IC -> Bool -> Name -> IO B.ByteString
showPublic ic = show_it ic "public" (fmap C.encodePublicKeyDER . _key_public) _ClearText

showSecret :: IC -> Bool -> Name -> IO B.ByteString
showSecret ic = show_it ic "secret" _key_clear_text _ClearText

show_it :: IC
        -> String
        -> (Key->Maybe a)
        -> (a->Binary)
        -> Bool
        -> Name
        -> IO B.ByteString
show_it ic lbl prj_1 prj_2 aa nm = show_it' ic lbl prj_1 (_Binary . prj_2) aa nm

show_it' :: IC
         -> String
         -> (Key->Maybe a)
         -> (a->B.ByteString)
         -> Bool
         -> Name
         -> IO B.ByteString
show_it' ic lbl prj_1 prj_2 aa nm =
 do key <- loadKey ic nm
    case prj_2 <$> prj_1 key of
      Nothing -> errorIO $ printf "%s: %s not present" (_name nm) lbl
      Just bs -> return $ armr bs
  where
    armr = if aa then B64.encode else id

keys :: IC -> IO [Key]
keys ic = Map.elems . _ks_keymap <$> get_keystore ic

list :: IC -> IO ()
list ic = run ic $ KS.list

info :: IC -> Name -> IO ()
info ic nm = run ic $ KS.info nm

deleteKeys :: IC -> [Name] -> IO ()
deleteKeys ic nms = run ic $ deleteKeysKS nms

encrypt :: IC -> Name -> FilePath -> FilePath -> IO ()
encrypt ic nm s_fp d_fp =
 do bs <- B.readFile s_fp
    bs' <- encrypt_ ic nm bs
    B.writeFile d_fp bs'

encrypt_ :: IC -> Name -> B.ByteString -> IO B.ByteString
encrypt_ ic nm bs = _Binary . _EncryptionPacket <$>
                    (run ic $ KS.encryptWithRSAKey nm $ ClearText $ Binary bs)

encrypt__ :: IC -> Name -> B.ByteString -> IO RSASecretData
encrypt__ ic nm bs = run ic $ KS.encryptWithRSAKey_ nm $ ClearText $ Binary bs

decrypt :: IC -> FilePath -> FilePath -> IO ()
decrypt ic s_fp d_fp =
 do bs <- B.readFile s_fp
    bs' <- decrypt_ ic bs
    B.writeFile d_fp bs'

decrypt_ :: IC -> B.ByteString -> IO B.ByteString
decrypt_ ic bs = _Binary . _ClearText <$>
                    (run ic $ KS.decryptWithRSAKey $ EncryptionPacket $ Binary bs)

decrypt__ :: IC -> Name -> RSASecretData -> IO B.ByteString
decrypt__ ic nm rsd = _Binary . _ClearText <$> (run ic $ KS.decryptWithRSAKey_ nm rsd)

sign :: IC -> Name -> FilePath -> FilePath -> IO ()
sign ic nm s_fp d_fp =
 do bs <- B.readFile s_fp
    bs' <- sign_ ic nm bs
    B.writeFile d_fp bs'

sign_ :: IC -> Name -> B.ByteString -> IO B.ByteString
sign_ ic nm m_bs = _Binary . _SignaturePacket <$>
                    (run ic $ KS.signWithRSAKey nm $ ClearText $ Binary m_bs)

verify :: IC -> FilePath -> FilePath -> IO Bool
verify ic m_fp s_fp =
 do m_bs <- B.readFile m_fp
    s_bs <- B.readFile s_fp
    ok <- verify_ ic m_bs s_bs
    case ok of
      True  -> return ()
      False -> report "signature does not match the data"
    return ok

verify_ :: IC -> B.ByteString -> B.ByteString -> IO Bool
verify_ ic m_bs s_bs =
    run ic $ KS.verifyWithRSAKey (ClearText       $ Binary m_bs)
                                 (SignaturePacket $ Binary s_bs)

run :: IC -> KS a -> IO a
run ic p =
 do (ctx,st0) <- get ic
    st1 <- scan_env ctx st0
    let (e,st2,les) = run_ ctx st1 p
    r <- e2io e
    mapM_ (logit ctx) les
    st' <- backup_env ctx st2
    put ic ctx st'
    return r

scan_env :: Ctx -> State -> IO State
scan_env ctx st0 =
 do (ks,les) <- scanEnv ks0
    mapM_ (logit ctx) les
    return st0 { st_keystore = ks }
  where
    ks0 = st_keystore st0

backup_env :: Ctx -> State -> IO State
backup_env ctx st0 =
 do mapM_ (logit ctx) les'
    e2io e
    return st'
  where
    (e,st',les') = run_ ctx st0 KS.backupKeys

data IC =
    IC  { ic_ctx_params :: CtxParams
        , ic_cache      :: Maybe (IORef (Ctx,State))
        }

get_keystore :: IC -> IO KeyStore
get_keystore ic = st_keystore <$> get_state ic

get_state :: IC -> IO State
get_state ic = snd <$> get ic

get :: IC -> IO (Ctx,State)
get IC{..} =
    case ic_cache of
      Nothing -> determineCtx ic_ctx_params
      Just rf -> readIORef rf

put :: IC -> Ctx -> State -> IO ()
put IC{..} ctx st =
 do maybe (return ()) (flip writeIORef (ctx,st)) ic_cache
    LBS.writeFile (ctx_store ctx) $ KS.keyStoreBytes $ st_keystore st

report :: String -> IO ()
report = hPutStrLn stderr
















