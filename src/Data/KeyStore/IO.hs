{-# LANGUAGE CPP                        #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE ScopedTypeVariables        #-}

-- | This module provide an IO-based API. The /ks/ executable provides
-- some keystore management functions that can be used from the shell
-- and "Data.KeyStore.KeyStore" provides the underlying functional model.

module Data.KeyStore.IO
    ( readSettings
    , CtxParams(..)
    , IC(..)
    , module Data.KeyStore.Types
    , module Data.KeyStore.KS.KS
    , keyStoreBytes
    , keyStoreFromBytes
    , settingsFromBytes
    , defaultSettingsFilePath
    , settingsFilePath
    , defaultKeyStoreFilePath
    , defaultCtxParams
    , instanceCtx
    , instanceCtx_
    , newKeyStore
    , store
    , listSettings
    , settings
    , updateSettings
    , listTriggers
    , triggers
    , addTrigger
    , addTrigger'
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
    , keyInfo
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
    , getKeystore
    , getState
    , getCtxState
    , putCtxState
    ) where

import           Data.KeyStore.IO.IC
import           Data.KeyStore.KS
import           Data.KeyStore.KS.KS
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
import qualified Control.Exception              as X
import qualified Control.Lens                   as L
import           Control.Monad
import           System.IO

#if MIN_VERSION_time(1,5,0)
#else
import           System.Locale (defaultTimeLocale)
#endif

-- | Generate a new keystore located in the given file with the given global
-- settings.
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
    LBS.writeFile str_fp $ keyStoreBytes $ st_keystore state

-- | Given 'CtxParams' describing the location of the keystore, etc., generate
-- an IC for use in the following keystore access functions that will allow
-- context to be cached between calls to these access functions.
instanceCtx :: CtxParams -> IO IC
instanceCtx cp =
 do ctx_st <- getCtxState $ instanceCtx_ cp
    IC cp . Just <$> newIORef ctx_st

-- | This functional method will generate an IC that will not cache any
-- state between calls.
instanceCtx_ :: CtxParams -> IC
instanceCtx_ cp = IC cp Nothing

-- | the filepath of the loaded store
store :: IC -> IO FilePath
store ic = run ic storeKS

-- | List the JSON settings on stdout.
listSettings :: IC -> IO ()
listSettings ic = settings ic >>= LBS.putStrLn . encode . _Settings

-- | Return the settings associated with the keystore.
settings :: IC -> IO Settings
settings ic = run ic $ _cfg_settings <$> getConfig

-- | Update the global settings of a keystore from the given JSON settings.
updateSettings :: IC -> FilePath -> IO ()
updateSettings ic fp =
 do bs   <- LBS.readFile fp
    stgs <- e2io $ settingsFromBytes bs
    run ic $ modConfig $ L.over cfg_settings $ const stgs

-- | List the triggers set up in the keystore on stdout.
listTriggers :: IC -> IO ()
listTriggers ic = triggers ic >>= putStr . unlines . map fmt
  where
    fmt Trigger{..} = printf "%-12s : %12s => %s" id_s pat_s stgs_s
      where
        id_s   = T.unpack   $ _TriggerID                  _trg_id
        pat_s  = _pat_string                              _trg_pattern
        stgs_s = LBS.unpack $ encode $ Object $ _Settings _trg_settings

-- | Returns the striggers setup on the keystore.
triggers :: IC -> IO [Trigger]
triggers ic = run ic $ Map.elems . _cfg_triggers <$> getConfig

-- | addTrigger' cariant that erads the setting from a file.
addTrigger :: IC -> TriggerID -> Pattern -> FilePath -> IO ()
addTrigger ic tid pat fp =
 do bs   <- LBS.readFile fp
    stgs <- e2io $ settingsFromBytes bs
    addTrigger' ic tid pat stgs

-- | Set up a named trigger on a keystore that will fire when a key matches the
-- given pattern establishing the settings.
addTrigger' :: IC -> TriggerID -> Pattern -> Settings -> IO ()
addTrigger' ic tid pat stgs =
    run ic $ modConfig $ L.over cfg_triggers $ Map.insert tid $ Trigger tid pat stgs

-- | Remove the named trigger from the keystore.
rmvTrigger :: IC -> TriggerID -> IO ()
rmvTrigger ic tid = run ic $ modConfig $ L.over cfg_triggers $ Map.delete tid

-- | Create an RSA key pair, encoding the private key in the named Safeguards.
createRSAKeyPair :: IC -> Name -> Comment -> Identity -> [Safeguard] -> IO ()
createRSAKeyPair ic nm cmt ide sgs = run ic $ createRSAKeyPairKS nm cmt ide sgs

-- | Create a symmetric key, possibly auto-loaded from an environment variable.
createKey :: IC
          -> Name
          -> Comment
          -> Identity
          -> Maybe EnvVar
          -> Maybe B.ByteString
          -> IO ()
createKey ic nm cmt ide mb_ev mb_bs =
            run ic $ createKeyKS nm cmt ide mb_ev (ClearText . Binary <$> mb_bs)

-- | Adjust a named key.
adjustKey :: IC -> Name -> (Key->Key) -> IO ()
adjustKey ic nm adj = run ic $ adjustKeyKS nm adj

-- | Load a named key from the named file.
rememberKey :: IC -> Name -> FilePath -> IO ()
rememberKey ic nm fp = B.readFile fp >>= rememberKey_ ic nm

-- | Load the named key.
rememberKey_ :: IC -> Name -> B.ByteString -> IO ()
rememberKey_ ic nm bs = run ic $ rememberKeyKS nm $ ClearText $ Binary bs

-- | Encrypt and store the key with the named safeguard.
secureKey :: IC -> Name -> Safeguard -> IO ()
secureKey ic nm nms = run ic $ secureKeyKS nm nms

-- | Try and retrieve the secret text for a given key.
loadKey :: IC -> Name -> IO Key
loadKey ic nm = run ic $ loadKeyKS nm

-- | Return the identity of a key.
showIdentity :: IC -> Bool -> Name -> IO B.ByteString
showIdentity ic = show_it' ic "identity" (Just . _key_identity) (B.pack . T.unpack . _Identity)

-- | Return the comment associated with a key.
showComment :: IC -> Bool -> Name -> IO B.ByteString
showComment ic = show_it' ic "comment"  (Just . _key_comment)  (B.pack . T.unpack . _Comment )

-- | Return the creation UTC of a key.
showDate :: IC -> Bool -> Name -> IO B.ByteString
showDate ic = show_it' ic "date" (Just . _key_created_at) (B.pack . formatTime defaultTimeLocale fmt)
  where
    fmt = "%F-%TZ"

-- | Return the hash of a key.
showHash :: IC -> Bool -> Name -> IO B.ByteString
showHash ic = show_it ic "hash" (fmap _hash_hash . _key_hash) _HashData

-- | Return the hash comment of a key/
showHashComment :: IC -> Bool -> Name -> IO B.ByteString
showHashComment ic = show_it' ic "hash" _key_hash cmt
  where
    cmt = B.pack . T.unpack . _Comment . _hashd_comment . _hash_description

-- | Retuen the hash salt of a key.
showHashSalt :: IC -> Bool -> Name -> IO B.ByteString
showHashSalt ic = show_it ic "hash" (fmap (_hashd_salt . _hash_description) . _key_hash) _Salt

-- | (For public key pairs only) return the public key.
showPublic  :: IC -> Bool -> Name -> IO B.ByteString
showPublic ic = show_it ic "public" (fmap encodePublicKeyDER . _key_public) _ClearText

-- | Return the secret text of a key (will be the private key for a public key pair).
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

-- | List a summary of all of the keys on stdout.
list :: IC -> IO ()
list ic = run ic $ listKS

-- Summarize a single key on stdout.
keyInfo :: IC -> Name -> IO ()
keyInfo ic nm = run ic $ keyInfoKS nm

-- | Return all of the keys in the keystore.
keys :: IC -> IO [Key]
keys ic = Map.elems . _ks_keymap <$> getKeystore ic

-- | Delete a list of keys from the keystore.
deleteKeys :: IC -> [Name] -> IO ()
deleteKeys ic nms = run ic $ deleteKeysKS nms

-- Encrypt a file with a named key.
encrypt :: IC -> Name -> FilePath -> FilePath -> IO ()
encrypt ic nm s_fp d_fp =
 do bs <- B.readFile s_fp
    bs' <- encrypt_ ic nm bs
    B.writeFile d_fp bs'

-- | Encrypt a 'B.ByteString' with a named key.
encrypt_ :: IC -> Name -> B.ByteString -> IO B.ByteString
encrypt_ ic nm bs = _Binary . _EncryptionPacket <$>
                    (run ic $ encryptWithRSAKeyKS nm $ ClearText $ Binary bs)

-- | Encrypt a 'B.ByteString' with a named key to produce a 'RSASecretData'.

encrypt__ :: IC -> Name -> B.ByteString -> IO RSASecretData
encrypt__ ic nm bs = run ic $ encryptWithRSAKeyKS_ nm $ ClearText $ Binary bs


-- | Decrypt a file with the named key (whose secret text must be accessible).
decrypt :: IC -> FilePath -> FilePath -> IO ()
decrypt ic s_fp d_fp =
 do bs <- B.readFile s_fp
    bs' <- decrypt_ ic bs
    B.writeFile d_fp bs'

-- | Decrypt a 'B.ByteString' with the named key
-- (whose secret text must be accessible).
decrypt_ :: IC -> B.ByteString -> IO B.ByteString
decrypt_ ic bs = _Binary . _ClearText <$>
                    (run ic $ decryptWithRSAKeyKS $ EncryptionPacket $ Binary bs)

-- | Decrypt a 'B.ByteString' from a 'RSASecretData' with the named key
-- (whose secret text must be accessible).
decrypt__ :: IC -> Name -> RSASecretData -> IO B.ByteString
decrypt__ ic nm rsd = _Binary . _ClearText <$> (run ic $ decryptWithRSAKeyKS_ nm rsd)

-- | Sign a file with the named key (whose secret text must be accessible)
-- to produce a detached signature in the named file.
sign :: IC -> Name -> FilePath -> FilePath -> IO ()
sign ic nm s_fp d_fp =
 do bs <- B.readFile s_fp
    bs' <- sign_ ic nm bs
    B.writeFile d_fp bs'

-- | Sign a 'B.ByteString' with the named key (whose secret text must be accessible)
-- to produce a detached signature.
sign_ :: IC -> Name -> B.ByteString -> IO B.ByteString
sign_ ic nm m_bs = _Binary . _SignaturePacket <$>
                    (run ic $ signWithRSAKeyKS nm $ ClearText $ Binary m_bs)

-- | Verify that a signature for a file via the named public key.
verify :: IC -> FilePath -> FilePath -> IO Bool
verify ic m_fp s_fp =
 do m_bs <- B.readFile m_fp
    s_bs <- B.readFile s_fp
    ok <- verify_ ic m_bs s_bs
    case ok of
      True  -> return ()
      False -> report "signature does not match the data"
    return ok

-- | Verify that a signature for a 'B.ByteString' via the named public key.
verify_ :: IC -> B.ByteString -> B.ByteString -> IO Bool
verify_ ic m_bs s_bs =
    run ic $ verifyWithRSAKeyKS (ClearText       $ Binary m_bs)
                                (SignaturePacket $ Binary s_bs)

-- | Run a KS function in an IO context, dealing with keystore updates, output,
-- debug logging and errors.
run :: IC -> KS a -> IO a
run ic p =
 do (ctx,st0) <- getCtxState ic
    st1 <- scan_env ctx st0
    let msg         = "[Keystore: " ++ ctx_store ctx ++"]\n"
        (e,st2,les) = run_ ctx st1 $ debugLog msg >> p
    r <- e2io e
    mapM_ (logit ctx) les
    st' <- backup_env ctx st2
    putCtxState ic ctx st'
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
    (e,st',les') = run_ ctx st0 backupKeysKS

getKeystore :: IC -> IO KeyStore
getKeystore ic = st_keystore <$> getState ic

getState :: IC -> IO State
getState ic = snd <$> getCtxState ic

getCtxState :: IC -> IO (Ctx,State)
getCtxState IC{..} =
    case ic_cache of
      Nothing -> determineCtx ic_ctx_params
      Just rf -> readIORef rf

putCtxState :: IC -> Ctx -> State -> IO ()
putCtxState IC{..} ctx st =
 do maybe (return ()) (flip writeIORef (ctx,st)) ic_cache
    when (not $ maybe False id $ cp_readonly ic_ctx_params) $
      LBS.writeFile (ctx_store ctx) $ keyStoreBytes $ st_keystore st

report :: String -> IO ()
report = hPutStrLn stderr
