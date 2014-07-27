{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FunctionalDependencies     #-}
{-# LANGUAGE ScopedTypeVariables        #-}

module Data.KeyStore.Sections
  ( SECTIONS(..)
  , Code(..)
  , Sections(..)
  , SectionType(..)
  , KeyData(..)
  , KeyPredicate
  , RetrieveDg(..)
  , initialise
  , rotate
  , retrieve
  , signKeystore
  , verifyKeystore
  , noKeys
  , allKeys
  , keyPrededicate
  , keyHelp
  , sectionHelp
  , secretKeySummary
  , publicKeySummary
  , locateKeys
  , keyName
  , passwordName
  )
  where

import           Data.KeyStore.IO
import qualified Data.Text                      as T
import qualified Data.ByteString.Char8          as B
import qualified Data.ByteString.Lazy.Char8     as LBS
import qualified Data.Aeson                     as A
import qualified Data.HashMap.Strict            as HM
import qualified Data.Vector                    as V
import           Data.Maybe
import           Data.List
import           Data.Ord
import           Data.Monoid
import           Control.Applicative
import           Text.Printf
import           System.FilePath
import           Safe


data SECTIONS h s k = SECTIONS


class (Bounded a,Enum a,Eq a, Ord a,Show a) => Code a where
    encode :: a -> String

    decode :: String -> Maybe a
    decode s = listToMaybe [ k | k<-[minBound..maxBound], encode k==s ]


-- | This class describes the relationship between the host-id, section-id
-- and key-id types used to build a hierarchical deployment model for a
-- keystore. A minimal instance would have to define hostDeploySection.
-- The deploy example program contains a fairly thorough example of this
-- class being used to implement a quite realitic deploymrnt scenario.
class (Code h, Code s, Code k) => Sections h s k
    | s -> h, k -> h
    , h -> s, k -> s
    , s -> k, h -> k
    where
  hostDeploySection :: h -> s                           -- ^ the deployment section: for a given host,
                                                        -- the starting section for locating the keys
                                                        -- during a deployment ('higher'/closer sections
                                                        -- taking priority)
  sectionType       :: s -> SectionType                 -- ^ whether the section holds the top key for the
                                                        -- keystore (i.e., keystore master key), the signing key
                                                        -- for the keystore or is a normal section containing
                                                        -- deployment keys
  superSections     :: s -> [s]                         -- ^ the sections that get a copy of the master
                                                        -- for this section (making all of its keys
                                                        -- available to them); N.B., the graph formed by this
                                                        -- this relationship over the sections must be acyclic
  keyIsHostIndexed  :: k -> Maybe (h->Bool)             -- ^ if the key is host-indexed then the predicate
                                                        -- specifies the hosts that use this key
  keyIsInSection    :: k -> s -> Bool                   -- ^ specifies which sections a key is resident in
  getKeyData        :: Maybe h -> s -> k -> IO KeyData  -- ^ loads the data for a particular key
  sectionSettings   :: Maybe s -> IO Settings           -- ^ loads the setting for a given settings
  describeKey       :: k -> String                      -- ^ describes the key (for the ks help command)
  describeSection   :: s -> String                      -- ^ describes the section (for the ks help command)
  sectionPWEnvVar   :: s -> EnvVar                      -- ^ secifies the environment variable containing the
                                                        -- ^ master password/provate key for for the given section

  sectionType           = const ST_keys

  superSections         = const []

  keyIsHostIndexed      = const Nothing

  keyIsInSection        = const $ const True

  getKeyData Nothing  s = get_kd $ encode s
  getKeyData (Just h) _ = get_kd $ encode h

  sectionSettings       = const $ return mempty

  describeKey         k = "The '" ++ encode k ++ "' key."

  describeSection     s = "The '" ++ encode s ++ "' Section."

  sectionPWEnvVar       = EnvVar . T.pack . ("KEY_" ++) . _name . passwordName


-- | Sections are used to hold the top (master) key for the keystore,
-- its signing key, or deployment keys
data SectionType
  = ST_top
  | ST_signing
  | ST_keys
  deriving (Show,Eq,Ord)

-- | A key is  triple containing some (plain-text) identity information for the
-- key, some comment text and the secret text to be encrypted. Note that
-- the keystore doesn't rely on this information but merely stores it. (They
-- can be empty.) The identity field will often be used to storte the key's
-- identity within the system that generates and uses it, ofor example.
data KeyData =
  KeyData
    { kd_identity :: Identity
    , kd_comment  :: Comment
    , kd_secret   :: B.ByteString
    }

-- | One, many or all of the keys in a store may be rotated at a time.
-- we use one of these to specify which keys are to be rotated.
type KeyPredicate h s k = Maybe h -> s -> k -> Bool

-- | Requests to retrieve a key from the staor can fail for various reasons.

type Retrieve a = Either RetrieveDg a

-- | This type specifies the reasons that an attempt to access a key from the
-- store has failed. This kind of failure suggests an inconsistent model
-- and will be raised regardless of which keys have been stored in the store.
data RetrieveDg
  = RDG_key_not_reachable
  | RDG_no_such_host_key
  deriving (Show,Eq,Ord)

-- | Here we create the store and rotate in a buch of keys. N.B. All of the
-- section passwords must be bound in the process environment before calling
-- procedure.
initialise :: Sections h s k => CtxParams -> KeyPredicate h s k -> IO ()
initialise cp kp = do
    stgs <- scs kp Nothing
    newKeyStore (the_keystore cp) stgs
    ic <- instanceCtx cp
    mapM_ (mks kp ic) [minBound..maxBound]
    rotate ic kp
    map _key_name <$> keys ic >>= mapM_ (keyInfo ic)
  where
    scs :: Sections h s k => KeyPredicate h s k -> Maybe s -> IO Settings
    scs = const sectionSettings

    mks :: Sections h s k => KeyPredicate h s k -> IC -> s -> IO ()
    mks = const mk_section

-- | Rotate in a set of keys spwecified by the predicate.
rotate :: Sections h s k => IC -> KeyPredicate h s k -> IO ()
rotate ic kp = sequence_ [ rotate' ic mb_h s k | (mb_h,s,k)<-host_keys++non_host_keys, kp mb_h s k ]
  where
    host_keys     = [ (Just h ,s,k) | k<-[minBound..maxBound], Just isp<-[keyIsHostIndexed k], h<-[minBound..maxBound], isp h, let s = key_section h k ]
    non_host_keys = [ (Nothing,s,k) | k<-[minBound..maxBound], Nothing <-[keyIsHostIndexed k], s<-[minBound..maxBound], keyIsInSection k s             ]

-- | Retrieve the keys for a given host from the store. Note that the whole history for the given key is returned.
-- Note also that the secret text may not be present if it si not accessible (depnding upon hwich section passwords
-- are correctly bound in the process environment). Note also that the 'Retrieve' diagnostic should not fail if a
-- coherent model has been ddefined for 'Sections'.
retrieve :: Sections h s k => IC -> h -> k -> IO (Retrieve [Key])
retrieve ic h k = either (return . Left) (\nm->Right <$> locateKeys ic nm) $ keyName h k

-- | Sign the keystore. (Requites the password for the signing section to be correctly
-- bound in the environment)
signKeystore :: Sections h s k => IC -> SECTIONS h s k -> IO B.ByteString
signKeystore ic scn = B.readFile (the_keystore $ ic_ctx_params ic) >>= sign_ ic (sgn_nme $ signing_key scn)

-- Verify that the signature for a keystore matches the keystore.
verifyKeystore :: IC -> B.ByteString -> IO Bool
verifyKeystore ic sig = B.readFile (the_keystore $ ic_ctx_params ic) >>= flip (verify_ ic) sig

-- | A predicate specifying all of the keys in the store.
noKeys :: KeyPredicate h s k
noKeys _ _ _ = False

-- | A predicate specifying none of the keys in the keystore.
allKeys :: KeyPredicate h s k
allKeys _ _ _ = True

-- | A utility for specifing a slice of the keys in the store, optionally specifying
-- host section and key that should belong to the slice. (If the host is specified then
-- the resulting predicate will only include host-indexed keys belonging to the
-- given host.)
keyPrededicate :: Sections h s k => Maybe h -> Maybe s -> Maybe k -> KeyPredicate h s k
keyPrededicate mbh mbs mbk mbh_ s k = h_ok && s_ok && k_ok
  where
    h_ok = maybe True (\h->maybe False (h==) mbh_) mbh
    s_ok = maybe True                  (s==)       mbs
    k_ok = maybe True                  (k==)       mbk

-- Generate some help text for the keys. If no key is specified then they are
-- merely listed, otherwise the help for the given key is listed.
keyHelp :: Sections h s k => Maybe k -> T.Text
keyHelp x@Nothing  = T.unlines $ map (T.pack . encode) [minBound..maxBound `asTypeOf` fromJust x ]
keyHelp   (Just k) = T.unlines $ map T.pack $ (map f $ concat
    [ [ (,) (encode k)    ""                         ]
    , [ (,) "  hosts:"    hln | Just hln <- [mb_hln] ]
    , [ (,) "  sections:" sln | Nothing  <- [mb_hln] ]
    ]) ++ "" : map ("  "++) (lines $ describeKey k) ++ [""]
  where
    mb_hln = fmt <$> keyIsHostIndexed k
    sln    = fmt  $  keyIsInSection   k

    f      = uncurry $ printf "%-10s %s"

-- Generate some help text for the sectionss. If no section is specified then they are
-- merely listed, otherwise the help for the given section is listed.
sectionHelp :: Sections h s k => Maybe s -> IO T.Text
sectionHelp x@Nothing  = return $ T.unlines $ map (T.pack . encode) [minBound..maxBound  `asTypeOf` fromJust x ]
sectionHelp   (Just s) = do
  stgs <- sectionSettings $ Just s
  return $ T.unlines $ map T.pack $ (map f $ concat
    [ [ (,) (encode s)          typ  ]
    , [ (,) "  p/w env var:"    env  ]
    , [ (,) "  hosts:"          hln  ]
    , [ (,) "  super sections:" sln  ]
    , [ (,) "  under sections:" uln  ]
    , [ (,) "  keys:"           kln  ]
    , [ (,) "  settings"        ""   ]
    ]) ++ fmt_s stgs ++ "" : map ("  "++) (lines $ describeSection s) ++ [""]
  where
    typ = case sectionType s of
        ST_top     -> "(top)"
        ST_signing -> "(signing)"
        ST_keys    -> "(keys)"
    env = "$" ++ T.unpack (_EnvVar $ sectionPWEnvVar s)
    hln = unwords $ nub [ encode h | h<-[minBound..maxBound], hostDeploySection h==s ]
    sln = unwords $ map encode $ superSections s
    uln = unwords $ map encode $ [ s_ | s_<-[minBound..maxBound], s `elem` superSections s_ ]
    kln = fmt $ flip keyIsInSection s

    f   = uncurry $ printf "%-20s %s"

    fmt_s stgs = map ("    "++) $ lines $ LBS.unpack $ A.encode $ A.Object $ _Settings stgs

-- | List a shell script for establishing all of the keys in the environment. NB For this
-- to work the password for the top section (or the passwords for all of the sections
-- must be bound if the store does not maintain a top key).
secretKeySummary :: Sections h s k => IC -> SECTIONS h s k -> IO T.Text
secretKeySummary ic scn = T.unlines <$> mapM f (sections scn)
  where
    f s = do
      sec <- T.pack . B.unpack <$> (showSecret ic False $ passwordName s)
      return $ T.concat ["export ",_EnvVar $ sectionPWEnvVar s,"=",sec]

-- | List a shell script for storing the public signing key for the store.
publicKeySummary :: Sections h s k => IC -> SECTIONS h s k -> FilePath -> IO T.Text
publicKeySummary ic scn fp = f <$> showPublic ic True (sgn_nme $ signing_key scn)
  where
    f b = T.pack $ "echo '" ++ B.unpack b ++ "' >" ++ fp ++ "\n"

-- | List all of the keys that have the given name as their prefix. If the
-- generic name of a key is given then it will list the complete history for
-- the key, the current (or most recent) entry first.
locateKeys :: IC -> Name -> IO [Key]
locateKeys ic nm = sortBy (flip $ comparing _key_name) . filter yup <$> keys ic
  where
    yup     = isp . _key_name
    isp nm' = nm_s `isPrefixOf` _name nm'

    nm_s    = _name nm

-- | Return the genertic name for a given key thst is used by the specified
-- host, returning a failure diagnostic if the host does not have such a key
-- on the given Section model.
keyName :: Sections h s k => h -> k -> Retrieve Name
keyName h k = do
  mb_h <- case keyIsHostIndexed k of
            Nothing             -> return Nothing
            Just hp | hp h      -> return $ Just h
                    | otherwise -> Left RDG_no_such_host_key
  s <- keySection h k
  return $ key_nme mb_h s k

-- a wrapper on keySection used internally in functional contezxtx
key_section :: Sections h s k => h -> k -> s
key_section h k = either oops id $ keySection h k
  where
    oops = error "key_section"

-- | Rerurn the section that a host sores a given key in, returning a
-- failure diagnostic if the host does not keep such a key in the given
-- 'Section' model.
keySection :: Sections h s k => h -> k -> Retrieve s
keySection h k = maybe (Left RDG_key_not_reachable) return $ listToMaybe $
  filter (keyIsInSection k) $ lower_sections $ hostDeploySection h

-- | The name of the key that stores the password for a given sections.
passwordName :: Sections h s k => s -> Name
passwordName s = name' $ "pw_"   ++ encode s

fmt :: Code a => (a->Bool) -> String
fmt p  = unwords [ encode h | h<-[minBound..maxBound], p h ]

rotate' :: Sections h s k => IC -> Maybe h -> s -> k -> IO ()
rotate' ic mb_h s k = do
  KeyData{..} <- getKeyData mb_h s k
  nm <- unique_nme ic $ key_nme mb_h s k
  createKey ic nm kd_comment kd_identity Nothing (Just kd_secret)

lower_sections :: Sections h s k => s -> [s]
lower_sections s0 =
  s0 : concat
    [ s:lower_sections s | s<-[minBound..maxBound], s0 `elem` superSections s ]

mk_section :: Sections h s k => IC -> s -> IO ()
mk_section ic s = do
  mk_section' ic s
  case sectionType s of
    ST_top     -> return ()
    ST_signing -> add_signing ic s
    ST_keys    -> return ()

mk_section' :: Sections h s k => IC -> s -> IO ()
mk_section' ic s =
 do add_password ic s
    add_save_key ic s
    add_trigger  ic s
    mapM_ (backup_password ic s) $ superSections s

add_signing :: Sections h s k => IC -> s -> IO ()
add_signing ic s = createRSAKeyPair ic (sgn_nme s) cmt "" [pw_sg]
  where
    cmt   = Comment  $ T.pack $ "signing key"
    pw_sg = safeguard [passwordName s]

add_password :: Sections h s k => IC -> s -> IO ()
add_password ic s = createKey ic nm cmt ide (Just ev) Nothing
  where
    cmt = Comment  $ T.pack $ "password for " ++ encode s
    ide = ""
    ev  = sectionPWEnvVar s

    nm  = passwordName s

add_save_key :: Sections h s k => IC -> s -> IO ()
add_save_key ic s = createRSAKeyPair ic nm cmt ide [pw_sg]
  where
    nm    = sve_nme s
    cmt   = Comment  $ T.pack $ "save key for " ++ encode s
    ide   = ""
    pw_sg = safeguard [passwordName s]

add_trigger :: Sections h s k => IC -> s -> IO ()
add_trigger ic s = do
    stgs <- (bu_settings s <>) <$> sectionSettings (Just s)
    addTrigger' ic tid pat stgs
  where
    tid    = TriggerID $ T.pack $ encode s
    pat    = scn_pattern s

bu_settings :: Sections h s k => s -> Settings
bu_settings s = Settings $ HM.fromList
    [ ("backup.keys"
      , A.Array $ V.singleton $ A.String $ T.pack $ _name $ sve_nme s
      )
    ]

signing_key :: Sections h s k => SECTIONS h s k -> s
signing_key _ = maybe oops id $ listToMaybe [ s_ | s_<-[minBound..maxBound], sectionType s_ == ST_signing ]
  where
    oops = error "signing_key: there is no signing key!"

sections :: Sections h s k => SECTIONS h s k -> [s]
sections _ = [minBound..maxBound]

backup_password :: Sections h s k => IC -> s -> s -> IO ()
backup_password ic s sv_s = secureKey ic (passwordName s) $ safeguard [sve_nme sv_s]

key_nme :: Sections h s k => Maybe h -> s -> k -> Name
key_nme mb_h s k = name' $ encode s ++ "_" ++ encode k ++ hst_sfx
  where
    hst_sfx = maybe "" (\h -> "_" ++ encode h) mb_h

sgn_nme :: Sections h s k => s -> Name
sgn_nme s = name' $ encode s ++ "_keystore_signing_key"

sve_nme :: Sections h s k => s -> Name
sve_nme s = name' $ "save_" ++ encode s

scn_pattern :: Sections h s k => s -> Pattern
scn_pattern s = pattern $ "^" ++ encode s ++ "_.*"

unique_nme :: IC -> Name -> IO Name
unique_nme ic nm =
 do nms <- filter isp . map _key_name <$> keys ic
    return $ unique_nme' nms nm
  where
    isp nm' = _name nm `isPrefixOf` _name nm'

unique_nme' :: [Name] -> Name -> Name
unique_nme' nms nm0 = headNote "unique_name'" c_nms
  where
    c_nms = [ nm | i<-[length nms+1..], let nm=nname i nm0, nm `notElem` nms ]

    nname :: Int -> Name -> Name
    nname i nm_ = name' $ _name nm_ ++ printf "_%03d" i

name' :: String -> Name
name' = either (error.show) id . name

the_keystore :: CtxParams -> FilePath
the_keystore = maybe "keystore.json" id . cp_store

get_kd :: Sections h s k => String -> k -> IO KeyData
get_kd sd k = do
  ide <- B.readFile $ fp "_id"
  cmt <- B.readFile $ fp "_cmt"
  sec <- B.readFile $ fp ""
  return
    KeyData
      { kd_identity = Identity $ T.pack $ B.unpack ide
      , kd_comment  = Comment  $ T.pack $ B.unpack cmt
      , kd_secret   = sec
      }
  where
    fp sfx = sd </> encode k ++ sfx
