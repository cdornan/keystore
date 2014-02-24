{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE BangPatterns               #-}

module Data.KeyStore.KeyStore
    ( keyStoreBytes
    , keyStoreFromBytes
    , settingsFromBytes
    , createRSAKeyPair
    , encryptWithRSAKey
    , encryptWithRSAKey_
    , decryptWithRSAKey
    , decryptWithRSAKey_
    , signWithRSAKey
    , verifyWithRSAKey
    , encryptWithKeys
    , decryptWithKeys
    , createKey
    , backupKeys
    , rememberKey
    , secureKey
    , getKeys
    , list
    , info
    , loadKey
    , loadEncryptionKey
    ) where

import           Data.KeyStore.Opt
import           Data.KeyStore.Packet
import           Data.KeyStore.Crypto
import           Data.KeyStore.KS
import           Data.KeyStore.Types
import           Data.API.JSON
import           Data.Aeson
import qualified Data.ByteString.Lazy           as LBS
import qualified Data.Map                       as Map
import qualified Data.Text                      as T
import           Data.Maybe
import           Data.List
import           Text.Printf
import           Crypto.PubKey.RSA
import           Control.Applicative
import           Control.Lens
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
createRSAKeyPair :: Name -> Comment -> Identity -> [Safeguard] -> KS ()
createRSAKeyPair nm cmt ide nmz =
 do _ <- createKey nm cmt ide Nothing Nothing
    (puk,prk) <- generateKeys
    adjustKeyKS nm (add_puk puk)
    rememberKey nm $ encodePrivateKeyDER prk
    mapM_ (secureKey nm) nmz
  where
    add_puk puk key = key { _key_public = Just puk }


-------------------------------------------------------------------------------
-- | Encrypt a clear text message with a name RSA key pair.
encryptWithRSAKey :: Name -> ClearText -> KS EncryptionPacket
encryptWithRSAKey nm ct =
    encocdeEncryptionPacket (safeguard [nm]) .
                encodeRSASecretData <$> encryptWithRSAKey_ nm ct

encryptWithRSAKey_ :: Name -> ClearText -> KS RSASecretData
encryptWithRSAKey_ nm ct =
 do scd <- _ec_secret_data <$> encryptWithKeys (safeguard [nm]) ct
    case scd of
      ECD_rsa rsd -> return rsd
      _           -> errorKS "RSA key expected"


-------------------------------------------------------------------------------
-- | Decrypt an RSA-encrypted message (the RSA secret key named in the message
-- must be available.)
decryptWithRSAKey :: EncryptionPacket -> KS ClearText
decryptWithRSAKey ep =
 do (sg,rsb) <- e2ks $ decocdeEncryptionPacket ep
    nm  <- case safeguardKeys sg of
             [nm] -> return nm
             _    -> errorKS "expected a single (RSA) key in the safeguard"
    rsd <- decodeRSASecretData rsb
    decryptWithRSAKey_ nm rsd

decryptWithRSAKey_ :: Name -> RSASecretData -> KS ClearText
decryptWithRSAKey_ nm rsd =
 do key <- loadKey nm
    case _key_clear_private key of
      Nothing  -> errorKS "could not load private key"
      Just prk -> decrypt prk rsd


-------------------------------------------------------------------------------
-- | Sign a message with a named RSA secret key (which must be available).
signWithRSAKey :: Name -> ClearText -> KS SignaturePacket
signWithRSAKey nm ct =
 do key <- loadKey nm
    case _key_clear_private key of
      Nothing  -> errorKS "could not load private key"
      Just prk -> encocdeSignaturePacket (safeguard [nm]) <$> sign prk ct


-------------------------------------------------------------------------------
-- | Verify that an RSA signature of a message is correct.
verifyWithRSAKey :: ClearText -> SignaturePacket -> KS Bool
verifyWithRSAKey ct sp =
 do (sg,rs) <- e2ks $ decocdeSignaturePacket sp
    nm  <- case safeguardKeys sg of
             [nm] -> return nm
             _    -> errorKS "expected a single (RSA) key in the safeguard"
    key <- lookupKey nm
    case _key_public key of
      Nothing  -> errorKS "not an RSA key pair"
      Just puk -> return $ verify puk ct rs


-------------------------------------------------------------------------------
-- | Symetrically encrypt a message with a Safeguard (list of names private
-- keys).
encryptWithKeys :: Safeguard -> ClearText -> KS EncrypedCopy
encryptWithKeys nms ct =
 do ec  <- defaultEncryptedCopy nms
    mb  <- loadEncryptionKey Encrypting ec
    ek  <- case mb of
             Nothing -> errorKS "could not load keys"
             Just ek -> return ek
    ecd <- save ek ct
    return ec { _ec_secret_data = ecd }


-------------------------------------------------------------------------------
-- | Symetrically encrypt a message with a Safeguard (list of names private
-- keys).
decryptWithKeys :: EncrypedCopy -> KS ClearText
decryptWithKeys ec =
 do mb <- loadEncryptionKey Decrypting ec
    ek <- case mb of
            Nothing -> errorKS "could not load keys"
            Just ek -> return ek
    restore (_ec_secret_data ec) ek


-------------------------------------------------------------------------------
-- | Create a private key.
createKey :: Name             -- ^ (unique) name of the new key
          -> Comment          -- ^ the comment string
          -> Identity         -- ^ the identity string
          -> Maybe EnvVar     -- ^ the environment variable used to hold a clear text copy
          -> Maybe ClearText  -- ^ (optionally) the clear test copy
          -> KS ()
createKey nm cmt ide mb_ev mb_ct = withKey nm $
 do insertNewKey
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
            }
    maybe (return ()) (rememberKey nm) mb_ct


-------------------------------------------------------------------------------
-- | Remember the secret text for a key -- will record the hash and encrypt
-- it with the configured safeguards, generating an error if any of the
-- safeguards are not available.
rememberKey :: Name -> ClearText -> KS ()
rememberKey nm ct =
 do key0 <- lookupKey nm
    let key1 = key0 { _key_clear_text = Just ct }
    vfy  <- lookupOpt opt__verify_enabled
    key2 <- case vfy of
      True  -> verify_key key1 ct
      False -> return key1
    key  <-
        case _key_hash key2 of
          Nothing  | isNothing $ _key_public key2 -> upd key2 <$> hash ct
          _                                       -> return key2
    insertKey key
    backupKey nm
  where
    upd key hsh =
        key { _key_hash = Just hsh
            }


-------------------------------------------------------------------------------
-- | Backup all of the keys in the store with their configured backup keys.
backupKeys :: KS ()
backupKeys = getKeys >>= mapM_ (backupKey . _key_name)


-------------------------------------------------------------------------------
-- | Backup a named key with its configured backup key.
backupKey :: Name -> KS ()
backupKey nm = withKey nm $
 do nms <- lookupOpt opt__backup_keys
    mapM_ backup nms
  where
    backup nm' = secure_key nm $ safeguard [nm']


-------------------------------------------------------------------------------
-- | Primitive to make a cryptographic copy (i.e., a safeguard) of the
-- secret text of a key, storing it in the key (and doing nothing if the
-- that safeguard is already present).
secureKey :: Name -> Safeguard -> KS ()
secureKey nm sg = withKey nm $ secure_key nm sg

secure_key :: Name -> Safeguard -> KS ()
secure_key nm sg =
 do key <- loadKey nm
    when (isNothing $ Map.lookup sg $ _key_secret_copies key) $
     do ct  <- case _key_clear_text key of
                 Nothing -> errorKS $ _name nm ++ ": cannot load key"
                 Just ct -> return ct
        ec0 <- defaultEncryptedCopy sg
        mbk <- loadEncryptionKey Encrypting ec0
        ek  <- case mbk of
                 Nothing -> errorKS $
                            printSafeguard sg ++ ": cannot load encryption keys"
                 Just ek -> return ek
        ecd <- save ek ct
        let ec = ec0 { _ec_secret_data = ecd }
        insertKey $ over key_secret_copies (Map.insert sg ec) key


-------------------------------------------------------------------------------
-- | List all of the keys in the store, one per line, on the output.
list :: KS ()
list =
 do nms <- map _key_name <$> getKeys
    keys <- mapM loadKey $ sort nms
    fyi $ concat $ map (list_key False) keys

-- | Print out the information of a particular key.
info :: Name -> KS ()
info nm =
 do key <- loadKey nm
    fyi $ list_key True key

data Line
    = LnHeader        String
    | LnHash          String
    | LnCopiesHeader
    | LnCopy          String
    deriving Show

list_key :: Bool -> Key -> String
list_key True  key@Key{..} =
    unlines $ map fmt $
        [ LnHeader hdr                               ] ++
        [ LnHash   hsh       | Just hsh<-[mb_hsh]    ] ++
        [ LnCopiesHeader                             ] ++
        [ LnCopy $ fmt_ec ec | ec<-Map.elems $ _key_secret_copies ]
  where
    fmt ln =
        case ln of
          LnHeader             s -> s
          LnHash               s -> fmt_ln  2 "Hash:"   s
          LnCopiesHeader         -> fmt_ln  2 "Copies:" ""
          LnCopy               s -> fmt_ln_ 4           s

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
getKeys :: KS [Key]
getKeys = Map.elems <$> getKeymap


-------------------------------------------------------------------------------
-- | Try to load the secret copy into the key and return it. (No error is
-- raised if it failed to recover the secret.)
loadKey :: Name -> KS Key
loadKey = loadKey' []

loadKey' :: [Name] -> Name -> KS Key
loadKey' nm_s nm =
 do key <- lookupKey nm
    maybe (loadKey'' nm_s nm) (const $ return key) $ _key_clear_text key

loadKey'' :: [Name] -> Name -> KS Key
loadKey'' nm_s nm =
 do key0 <- lookupKey nm
    let ld []        = return key0
        ld (sc:scs)  =
             do key <- loadKey''' nm_s nm key0 sc
                case _key_clear_text key of
                  Nothing -> ld scs
                  Just _  -> return key
    ld $ Map.elems $ _key_secret_copies key0

loadKey''' :: [Name]
           -> Name
           -> Key
           -> EncrypedCopy
           -> KS Key
loadKey''' nm_s nm key@Key{..} ec =
    case nm `elem` nm_s of
      True  -> return key
      False ->
         do mbk <- loadEncryptionKey_ Decrypting (nm:nm_s) ec
            case mbk of
              Nothing -> return key
              Just ek ->
                 do ct <- restore (_ec_secret_data ec) ek
                    rememberKey nm ct
                    lookupKey nm


-------------------------------------------------------------------------------
-- | Try to load an encryption or decryption key for an encrypted message.
loadEncryptionKey :: Dirctn -> EncrypedCopy -> KS (Maybe EncryptionKey)
loadEncryptionKey dir sc = loadEncryptionKey_ dir [] sc

loadEncryptionKey_ :: Dirctn -> [Name] -> EncrypedCopy -> KS (Maybe EncryptionKey)
loadEncryptionKey_ dir nms_s sc =
    case nms of
      []   -> return $ Just $ EK_none void_
      [nm] ->
         do key <- lookupKey nm
            maybe sym (asm dir nm) $ _key_public key
      _    -> sym
  where
    sym =
     do keys <- mapM (loadKey' nms_s) nms
        case all (isJust._key_clear_text) keys of
          True  -> Just . EK_symmetric <$>
                            (mkAESKey sc $ catMaybes $ map _key_clear_text keys)
          False -> return Nothing

    asm Encrypting _  puk = return $ Just $ EK_public puk
    asm Decrypting nm _   =
     do key <- loadKey' nms_s nm
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
            _hash_hash(hash_ (_hash_description hsh) ct) == _hash_hash hsh

verify_private_key_ :: PublicKey -> ClearText -> E PrivateKey
verify_private_key_ puk ct =
 do prk <- decodePrivateKeyDER ct
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
