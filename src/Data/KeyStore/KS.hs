{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE BangPatterns               #-}

module Data.KeyStore.KS
    ( keyStoreBytes
    , keyStoreFromBytes
    , settingsFromBytes
    , createRSAKeyPairKS
    , encryptWithRSAKeyKS
    , encryptWithRSAKeyKS_
    , decryptWithRSAKeyKS
    , decryptWithRSAKeyKS_
    , signWithRSAKeyKS
    , verifyWithRSAKeyKS
    , encryptWithKeysKS
    , decryptWithKeysKS
    , createKeyKS
    , backupKeysKS
    , rememberKeyKS
    , secureKeyKS
    , getKeysKS
    , listKS
    , keyInfoKS
    , loadKeyKS
    , loadEncryptionKeyKS
    , module Data.KeyStore.KS.Crypto
    , module Data.KeyStore.KS.KS
    , module Data.KeyStore.KS.Opt
    , module Data.KeyStore.KS.Configuration
    , module Data.KeyStore.KS.CPRNG
    ) where

import           Data.KeyStore.KS.Packet
import           Data.KeyStore.KS.Crypto
import           Data.KeyStore.KS.KS
import           Data.KeyStore.KS.Opt
import           Data.KeyStore.KS.Configuration
import           Data.KeyStore.KS.CPRNG
import           Data.KeyStore.Types
import           Data.API.JSON
import           Data.Aeson
import qualified Data.ByteString.Lazy           as LBS
import qualified Data.Map                       as Map
import qualified Data.Text                      as T
import           Data.Maybe
import           Data.List
import           Data.Time
import           Text.Printf
import qualified Control.Lens                   as L
import           Control.Monad


-------------------------------------------------------------------------------
-- | Encode a key store as a JSON ByteString (discarding any cached cleartext
-- copies of secrets it may have)
keyStoreBytes :: KeyStore -> LBS.ByteString
keyStoreBytes = encode . cln
  where
    cln ks =
        ks  { _ks_keymap = cleanKeyMap $ _ks_keymap ks
            }


-------------------------------------------------------------------------------
-- Parse a key store from a JSON ByteString.
keyStoreFromBytes :: LBS.ByteString -> E KeyStore
keyStoreFromBytes = chk . either (const Nothing) Just . decodeWithErrs
  where
    chk Nothing   = Left $ strMsg "failed to decode keystore file"
    chk (Just ks) = Right ks


-------------------------------------------------------------------------------
-- Parse key store settings from a JSON ByteString.
settingsFromBytes :: LBS.ByteString -> E Settings
settingsFromBytes = chk . either (const Nothing) Just . decodeWithErrs
  where
    chk (Just(Object fm)) = Right $ Settings fm
    chk _                 = Left  $ strMsg "failed to decode JSON settings"


-------------------------------------------------------------------------------
-- Create a random RSA key pair under a name in the key store,
-- safeguarding it zero, one or more times.
createRSAKeyPairKS :: Name -> Comment -> Identity -> [Safeguard] -> KS ()
createRSAKeyPairKS nm cmt ide nmz =
 do _ <- createKeyKS nm cmt ide Nothing Nothing
    (puk,prk) <- generateKeysKS
    adjustKeyKS nm (add_puk puk)
    rememberKeyKS nm $ encodePrivateKeyDER prk
    mapM_ (secureKeyKS nm) nmz
  where
    add_puk puk key = key { _key_public = Just puk }


-------------------------------------------------------------------------------
-- | Encrypt a clear text message with a name RSA key pair.
encryptWithRSAKeyKS :: Name -> ClearText -> KS EncryptionPacket
encryptWithRSAKeyKS nm ct =
    encocdeEncryptionPacket (safeguard [nm]) .
                encodeRSASecretData <$> encryptWithRSAKeyKS_ nm ct

encryptWithRSAKeyKS_ :: Name -> ClearText -> KS RSASecretData
encryptWithRSAKeyKS_ nm ct =
 do scd <- _ec_secret_data <$> encryptWithKeysKS (safeguard [nm]) ct
    case scd of
      ECD_rsa rsd -> return rsd
      _           -> errorKS "RSA key expected"


-------------------------------------------------------------------------------
-- | Decrypt an RSA-encrypted message (the RSA secret key named in the message
-- must be available.)
decryptWithRSAKeyKS :: EncryptionPacket -> KS ClearText
decryptWithRSAKeyKS ep =
 do (sg,rsb) <- e2ks $ decocdeEncryptionPacketE ep
    nm  <- case safeguardKeys sg of
             [nm] -> return nm
             _    -> errorKS "expected a single (RSA) key in the safeguard"
    rsd <- decodeRSASecretData rsb
    decryptWithRSAKeyKS_ nm rsd

decryptWithRSAKeyKS_ :: Name -> RSASecretData -> KS ClearText
decryptWithRSAKeyKS_ nm rsd =
 do key <- loadKeyKS nm
    case _key_clear_private key of
      Nothing  -> errorKS "could not load private key"
      Just prk -> decryptKS prk rsd


-------------------------------------------------------------------------------
-- | Sign a message with a named RSA secret key (which must be available).
signWithRSAKeyKS :: Name -> ClearText -> KS SignaturePacket
signWithRSAKeyKS nm ct =
 do key <- loadKeyKS nm
    case _key_clear_private key of
      Nothing  -> errorKS "could not load private key"
      Just prk -> encocdeSignaturePacket (safeguard [nm]) <$> signKS prk ct


-------------------------------------------------------------------------------
-- | Verify that an RSA signature of a message is correct.
verifyWithRSAKeyKS :: ClearText -> SignaturePacket -> KS Bool
verifyWithRSAKeyKS ct sp =
 do (sg,rs) <- e2ks $ decocdeSignaturePacketE sp
    nm  <- case safeguardKeys sg of
             [nm] -> return nm
             _    -> errorKS "expected a single (RSA) key in the safeguard"
    key <- lookupKey nm
    case _key_public key of
      Nothing  -> errorKS "not an RSA key pair"
      Just puk -> return $ verifyKS puk ct rs


-------------------------------------------------------------------------------
-- | Symetrically encrypt a message with a Safeguard (list of names private
-- keys).
encryptWithKeysKS :: Safeguard -> ClearText -> KS EncrypedCopy
encryptWithKeysKS nms ct =
 do ec  <- defaultEncryptedCopyKS nms
    mb  <- loadEncryptionKeyKS Encrypting ec
    ek  <- case mb of
             Nothing -> errorKS "could not load keys"
             Just ek -> return ek
    ecd <- saveKS ek ct
    return ec { _ec_secret_data = ecd }


-------------------------------------------------------------------------------
-- | Symetrically encrypt a message with a Safeguard (list of names private
-- keys).
decryptWithKeysKS :: EncrypedCopy -> KS ClearText
decryptWithKeysKS ec =
 do mb <- loadEncryptionKeyKS Decrypting ec
    ek <- case mb of
            Nothing -> errorKS "could not load keys"
            Just ek -> return ek
    restoreKS (_ec_secret_data ec) ek


-------------------------------------------------------------------------------
-- | Create a private key.
createKeyKS :: Name             -- ^ (unique) name of the new key
          -> Comment          -- ^ the comment string
          -> Identity         -- ^ the identity string
          -> Maybe EnvVar     -- ^ the environment variable used to hold a clear text copy
          -> Maybe ClearText  -- ^ (optionally) the clear test copy
          -> KS ()
createKeyKS nm cmt ide mb_ev mb_ct = withKey nm $
 do now <- currentTime
    insertNewKey
        Key
            { _key_name          = nm
            , _key_comment       = cmt
            , _key_identity      = ide
            , _key_is_binary     = False
            , _key_env_var       = mb_ev
            , _key_hash          = Nothing
            , _key_public        = Nothing
            , _key_secret_copies = Map.empty
            , _key_clear_text    = Nothing
            , _key_clear_private = Nothing
            , _key_created_at    = now
            }
    maybe (return ()) (rememberKeyKS nm) mb_ct


-------------------------------------------------------------------------------
-- | Remember the secret text for a key -- will record the hash and encrypt
-- it with the configured safeguards, generating an error if any of the
-- safeguards are not available.
rememberKeyKS :: Name -> ClearText -> KS ()
rememberKeyKS nm ct =
 do btw $ "remembering " ++ show nm ++ "\n"
    key0 <- lookupKey nm
    let key1 = key0 { _key_clear_text = Just ct }
    vfy  <- lookupOpt opt__verify_enabled
    key2 <- case vfy of
      True  -> verify_key key1 ct
      False -> return key1
    key  <-
        case _key_hash key2 of
          Nothing  | isNothing $ _key_public key2 -> upd key2 <$> hashKS ct
          _                                       -> return key2
    insertKey key
    backupKeyKS nm
  where
    upd key hsh =
        key { _key_hash = Just hsh
            }


-------------------------------------------------------------------------------
-- | Backup all of the keys in the store with their configured backup keys.
backupKeysKS :: KS ()
backupKeysKS = getKeysKS >>= mapM_ (backupKeyKS . _key_name)


-------------------------------------------------------------------------------
-- | Backup a named key with its configured backup key.
backupKeyKS :: Name -> KS ()
backupKeyKS nm = withKey nm $
 do nms <- lookupOpt opt__backup_keys
    mapM_ backup nms
  where
    backup nm' = secure_key nm $ safeguard [nm']


-------------------------------------------------------------------------------
-- | Primitive to make a cryptographic copy (i.e., a safeguard) of the
-- secret text of a key, storing it in the key (and doing nothing if the
-- that safeguard is already present).
secureKeyKS :: Name -> Safeguard -> KS ()
secureKeyKS nm sg = withKey nm $ secure_key nm sg

secure_key :: Name -> Safeguard -> KS ()
secure_key nm sg =
 do btw $ "securing " ++ show nm ++ " with " ++ show sg ++ "\n"
    key <- loadKeyKS nm
    when (isNothing $ Map.lookup sg $ _key_secret_copies key) $
     do ct  <- case _key_clear_text key of
                 Nothing -> errorKS $ _name nm ++ ": cannot load key"
                 Just ct -> return ct
        ec0 <- defaultEncryptedCopyKS sg
        mbk <- loadEncryptionKeyKS Encrypting ec0
        ek  <- case mbk of
                 Nothing -> errorKS $
                            printSafeguard sg ++ ": cannot load encryption keys"
                 Just ek -> return ek
        ecd <- saveKS ek ct
        let ec = ec0 { _ec_secret_data = ecd }
        insertKey $ L.over key_secret_copies (Map.insert sg ec) key


-------------------------------------------------------------------------------
-- | List all of the keys in the store, one per line, on the output.
listKS :: KS ()
listKS =
 do nms <- map _key_name <$> getKeysKS
    keys <- mapM loadKeyKS $ sort nms
    putStrKS $ concat $ map (list_key False) keys

-- | Print out the information of a particular key.
keyInfoKS :: Name -> KS ()
keyInfoKS nm =
 do key <- loadKeyKS nm
    putStrKS $ list_key True key

data Line
    = LnHeader        String
    | LnDate          UTCTime
    | LnHash          String
    | LnCopiesHeader
    | LnCopy          String
    deriving Show

list_key :: Bool -> Key -> String
list_key True  key@Key{..} =
    unlines $ map fmt $
        [ LnHeader hdr                                     ] ++
        [ LnDate   _key_created_at                         ] ++
        [ LnHash   hsh             | Just hsh<-[mb_hsh]    ] ++
        [ LnCopiesHeader                                   ] ++
        [ LnCopy $ fmt_ec ec       | ec<-Map.elems $ _key_secret_copies ]
  where
    fmt ln =
        case ln of
          LnHeader             s -> s
          LnDate               u -> fmt_ln  2 "Date:"   $ show u
          LnHash               s -> fmt_ln  2 "Hash:"          s
          LnCopiesHeader         -> fmt_ln  2 "Copies:"        ""
          LnCopy               s -> fmt_ln_ 4                  s

    hdr     = printf "%s: %s%s -- %s" nm sts ev cmt
        where
          nm    = _name                                           _key_name
          sts   = status key
          ev    = maybe "" (printf " ($%s)" . T.unpack . _EnvVar) _key_env_var
          cmt   = T.unpack $ _Comment                             _key_comment
    mb_hsh  = fmt_hsh <$> _key_hash

    fmt_ec EncrypedCopy{..} = printf "%s(%d*%s[%s])" ci is pf sg
        where
          ci            = show _ec_cipher
          Iterations is = _ec_iterations
          pf            = show _ec_prf
          sg            = printSafeguard _ec_safeguard

    fmt_hsh Hash{_hash_description=HashDescription{..}} = printf "%d*%s(%d):%d" is pf sw wd
        where
          Iterations is = _hashd_iterations
          pf            = show _hashd_prf
          Octets sw     = _hashd_salt_octets
          Octets wd     = _hashd_width_octets

    fmt_ln  i s s'   = fmt_ln_ i $ printf "%-8s %s" s s'
    fmt_ln_ i s      = replicate i ' ' ++ s
list_key False key@Key{..} = printf "%-40s : %s%s (%s)\n" nm sts ev ecs
  where
    nm  = _name  _key_name
    sts = status key
    ev  = maybe "" (printf " ($%s)" . T.unpack . _EnvVar) _key_env_var
    ecs = intercalate "," $ map (printSafeguard . _ec_safeguard) $
                                                  Map.elems _key_secret_copies

status :: Key -> String
status Key{..} = [sts_t,sts_p]
  where
    sts_t = maybe '-' (const 'T')                _key_clear_text
    sts_p = maybe '-' (const 'P')                _key_public


-------------------------------------------------------------------------------
-- | Return all of the keys in the keystore.
getKeysKS :: KS [Key]
getKeysKS = Map.elems <$> getKeymap


-------------------------------------------------------------------------------
-- | Try to load the secret copy into the key and return it. (No error is
-- raised if it failed to recover the secret.)
loadKeyKS :: Name -> KS Key
loadKeyKS = load_key []

load_key :: [Name] -> Name -> KS Key
load_key nm_s nm =
 do key <- lookupKey nm
    maybe (load_key' nm_s nm) (const $ return key) $ _key_clear_text key

load_key' :: [Name] -> Name -> KS Key
load_key' nm_s nm =
 do key0 <- lookupKey nm
    let ld []        = return key0
        ld (sc:scs)  =
             do key <- load_key'' nm_s nm key0 sc
                case _key_clear_text key of
                  Nothing -> ld scs
                  Just _  -> return key
    ld $ Map.elems $ _key_secret_copies key0

load_key'' :: [Name]
           -> Name
           -> Key
           -> EncrypedCopy
           -> KS Key
load_key'' nm_s nm key@Key{..} ec =
    case nm `elem` nm_s of
      True  -> return key
      False ->
         do mbk <- loadEncryptionKeyKS_ Decrypting (nm:nm_s) ec
            case mbk of
              Nothing -> return key
              Just ek ->
                 do ct <- restoreKS (_ec_secret_data ec) ek
                    rememberKeyKS nm ct
                    lookupKey nm


-------------------------------------------------------------------------------
-- | Try to load an encryption or decryption key for an encrypted message.
loadEncryptionKeyKS :: Dirctn -> EncrypedCopy -> KS (Maybe EncryptionKey)
loadEncryptionKeyKS dir sc = loadEncryptionKeyKS_ dir [] sc

loadEncryptionKeyKS_ :: Dirctn -> [Name] -> EncrypedCopy -> KS (Maybe EncryptionKey)
loadEncryptionKeyKS_ dir nms_s sc =
    case nms of
      []   -> return $ Just $ EK_none void_
      [nm] ->
         do key <- lookupKey nm
            maybe sym (asm dir nm) $ _key_public key
      _    -> sym
  where
    sym =
     do keys <- mapM (load_key nms_s) nms
        case all (isJust._key_clear_text) keys of
          True  -> Just . EK_symmetric <$>
                            (mkAESKeyKS sc $ catMaybes $ map _key_clear_text keys)
          False -> return Nothing

    asm Encrypting _  puk = return $ Just $ EK_public puk
    asm Decrypting nm _   =
     do key <- load_key nms_s nm
        case _key_clear_private key of
          Nothing  -> return Nothing
          Just prk -> return $ Just $ EK_private prk

    nms = safeguardKeys $ _ec_safeguard sc


-------------------------------------------------------------------------------
verify_key :: Key -> ClearText -> KS Key
verify_key key@Key{..} ct =
    case (_key_hash,_key_public) of
      (Just hsh,_       ) ->
        case verify_key_ hsh ct of
          True  -> return key { _key_clear_text = Just ct }
          False -> errorKS "key failed to match hash"
      (Nothing ,Just puk) ->
         do prk <- e2ks $ verify_private_key_ puk ct
            return
                key { _key_clear_text    = Just ct
                    , _key_clear_private = Just prk
                    }
      _ -> return
                key { _key_clear_text    = Just ct
                    }

verify_key_ :: Hash -> ClearText -> Bool
verify_key_ hsh ct =
            _hash_hash(hashKS_ (_hash_description hsh) ct) == _hash_hash hsh

verify_private_key_ :: PublicKey -> ClearText -> E PrivateKey
verify_private_key_ puk ct =
 do prk <- decodePrivateKeyDERE ct
    case puk==private_pub prk of
      True  -> return prk
      False -> Left $ strMsg "private key mismatches public key"


-------------------------------------------------------------------------------
cleanKeyMap :: KeyMap -> KeyMap
cleanKeyMap mp = Map.map cln mp
  where
    cln key =
        key { _key_clear_text    = Nothing
            , _key_clear_private = Nothing
            }
