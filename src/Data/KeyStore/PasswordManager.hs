{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}

module Data.KeyStore.PasswordManager
    ( PMConfig(..)
    , PW(..)
    , PW_(..)
    , SessionDescriptor(..)
    , CollectConfig(..)
    , defaultCollectConfig
    , Password(..)
    , PasswordName(..)
    , PasswordText(..)
    , SessionName(..)
    , EnvVar(..)
    , passwordManager
    , defaultHashDescription
    , defaultSampleScript
    , hashMasterPassword
    , bindMasterPassword
    , setup
    , passwordValid
    , isStorePresent
    , amLoggedIn
    , isBound
    , load
    , psComment
    , collect
    , prime
    , select
    , deletePassword
    , deleteSession
    , status
    , passwords
    , sessions
    , infoPassword
    , infoPassword_
    , dump
    , collectShell
    ) where

import           Data.KeyStore.Types.PasswordStoreModel
import           Data.KeyStore.Types
import           Data.KeyStore.KS.Crypto
import           Data.KeyStore.KS.CPRNG
import           Data.KeyStore.Version
import qualified Data.Aeson                               as A
import qualified Data.ByteString.Char8                    as B
import qualified Data.ByteString.Lazy                     as BL
import qualified Data.ByteString.Base64                   as B64
import qualified Data.Text                                as T
import qualified Data.Map                                 as Map
import           Data.Time
import           Data.Monoid
import           Data.API.Types
import           Data.API.JSON
import           Data.Maybe
import qualified Text.PrettyPrint.ANSI.Leijen             as P
import           Text.Printf
import qualified Control.Lens                             as L
import           Control.Applicative
import           Control.Exception
import           Control.Monad
import           System.Directory
import           System.Environment
import           System.Exit
import           System.IO
import           System.Locale
import qualified Options.Applicative                      as O
import           Options.Applicative


-- | The password manager is used for storing locally the passwords and session
-- tokens of a single user.  The password used to encode the store is stored in
-- an environment variable and the passwords and tokens are stored in a file.
-- The file and and environment cariable are specified in the 'PWConfig' record.
-- (The attributes of each password and session list, including the environment
-- variables that they are communicated through, is statically specified
-- with the PW class below.)

data PMConfig p =
  PMConfig
    { _pmc_location       :: FilePath     -- ^ file in which to store the encrypted passords
    , _pmc_env_var        :: EnvVar       -- ^ the environmant variable containing the master password used to secure the store
    , _pmc_keystore_msg   :: String       -- ^ error message to be used on failure to locate the keystore
    , _pmc_password_msg   :: String       -- ^ error message to be used on failure to locate the master password
    , _pmc_shell          :: IO ()        -- ^ for firing up an interactive shell on successful login
    , _pmc_hash_descr     :: HashDescription
                                          -- ^ for generating has descriptions (can use 'defaultHashDescription' here)
    , _pmc_allow_dumps    :: Bool         -- ^ must be true to enable 'dump' commands
    , _pmc_dump_prefix    :: String       -- ^ the prefix string to be used in making up the commands from dump scripts
    , _pmc_sample_script  :: Maybe String -- ^ the sample script
    }

-- | The PW class provides all of the information on the bounded enumeration type used to identify the passwords
class (Bounded p,Enum p,Eq p, Ord p,Show p) => PW p where
  -- | the name by which the password is known
  pwName       :: p -> PasswordName
  pwName       = PasswordName . T.pack . show
  -- | parse a PasswordName into a p
  parsePwName  :: PasswordName -> Maybe p
  parsePwName  = \pnm -> listToMaybe [ p | p<-[minBound..maxBound], pwName p == pnm ]
  -- | whether the passwords is a session and if so a function for extracting the session name from the secret password text
  isSession    :: p -> Maybe (PasswordText -> Either String SessionDescriptor)
  isSession    = const Nothing
  -- | whether the password is a one-shot password, needing to be primed to be used
  isOneShot    :: p -> Bool
  isOneShot    = const False
  -- | the environment variable where the password is expected to be found by the client/deployment scripts
  enVar        :: p -> EnvVar
  enVar        = EnvVar . (T.append "KEY_pw_") . _PasswordName . pwName
  -- | a brief description of the password in a few words
  summarize     :: p -> String
  summarize  _  = ""
  -- | a description of the password
  describe     :: p -> String
  describe  p  = (T.unpack $ _PasswordName $ pwName p) ++ ": description to follow"

-- | we resort to phantom types when we have no other way of passing PW into a
-- function (see 'defaultSampleScript')
data PW_ p = PW_

cast_pmc :: PMConfig p -> p -> p
cast_pmc _ p = p

cast_pw :: PW_ p -> p -> p
cast_pw _ p = p

-- each session is named and may be a one-shot session
data SessionDescriptor =
  SessionDescriptor
    { _sd_name      :: SessionName
    , _sd_isOneShot :: Bool
    }
  deriving (Show)

-- | the client calls 'collect' to bind the passwords into the environment
data CollectConfig p =
  CollectConfig
    { _cc_optional :: Bool  -- ^ if True , collect will not report an error if the master password is missing
    , _cc_active   :: [p]   -- ^ the list of active passwords for this collection
    }

-- | raise an error if not logged in and collect all of the passwords
defaultCollectConfig :: PW p => CollectConfig p
defaultCollectConfig =
  CollectConfig
    { _cc_optional = True
    , _cc_active   = [minBound..maxBound]
    }

-- | the password manager CLI: it just needs the config and command line
passwordManager :: PW p => PMConfig p -> [String] -> IO ()
passwordManager pmc args = do
  pmcd <- parse_command pmc args
  case pmcd of
    PMCD_version                -> putStrLn version
    PMCD_setup          nl mb_t -> setup          pmc nl mb_t
    PMCD_login        y    mb_t -> login          pmc y  mb_t
    PMCD_load            p mb_t -> load           pmc p  mb_t
    PMCD_comment            cmt -> psComment      pmc cmt
    PMCD_prime        u  p      -> prime          pmc u $ Just p
    PMCD_prime_all    u         -> prime          pmc u Nothing
    PMCD_select          mb snm -> select         pmc mb snm
    PMCD_delete_password p      -> deletePassword pmc p
    PMCD_delete_session  mb snm -> deleteSession  pmc mb snm
    PMCD_status      q          -> status         pmc q
    PMCD_passwords   b          -> passwords      pmc b
    PMCD_sessions    a b mb     -> sessions       pmc a b mb
    PMCD_info        s   p      -> infoPassword   pmc s p
    PMCD_dump        s          -> dump           pmc s
    PMCD_collect                -> collectShell   pmc
    PMCD_sample_script          -> putStr $ maybe "" id $ _pmc_sample_script pmc

-- | a sample 'HashDescription' generator to help with setting up 'PMConfig'
defaultHashDescription :: Salt -> HashDescription
defaultHashDescription st =
    HashDescription
        { _hashd_comment      = "PM master password"
        , _hashd_prf          = PRF_sha512
        , _hashd_iterations   = 5000
        , _hashd_width_octets = 32
        , _hashd_salt_octets  = Octets $ B.length $ _Binary $ _Salt st
        , _hashd_salt         = st
        }

-- | sample sample-script generator to help with setting up 'PMConfig'
defaultSampleScript :: PW p => PW_ p -> String -> String
defaultSampleScript pw_ pfx = format_dump pfx cmt (map f [minBound..maxBound]) []
  where
    f p = (,) p $ PasswordText $ "secret-" `T.append` _PasswordName (pwName $ cast_pw pw_ p)

    cmt = PasswordStoreComment $ T.pack "loaded by the sample script"

-- | hashing the master password to create the private key for securing the store
hashMasterPassword :: PW p => PMConfig p -> String -> PasswordText
hashMasterPassword PMConfig{..} pw =
    PasswordText $ T.pack $ B.unpack $
      B64.encode $ _Binary $ _HashData $ _hash_hash $
        hashKS_ _pmc_hash_descr $ ClearText $ Binary $ B.pack pw

-- | bind the master password in the environment
bindMasterPassword :: PW p => PMConfig p -> PasswordText -> IO ()
bindMasterPassword PMConfig{..} = set_env _pmc_env_var

-- | create an empty passowrd store; if the boolean flag is False then
-- an interactive shell is fired up with access to the new store;
-- if no password is specified then one is read from stdin
setup :: PW p
      => PMConfig p
      -> Bool                       -- ^ => don't fire up an interactive shell with access to the new store
      -> Maybe PasswordText         -- ^ the master password
      -> IO ()
setup pmc no_li mb_pwt = do
    -- check there isn't a store there already
    ex <- doesFileExist _pmc_location
    when ex $ error $ "password store already exists in: " ++ _pmc_location
    -- get a password from stdin if we have not been passed one
    pwt <- maybe (get_pw pmc) return mb_pwt
    -- need creation time and comment
    now <- getCurrentTime
    let ps =
          PasswordStore
            { _ps_comment = PasswordStoreComment $ T.pack $ "Created at " ++ show now
            , _ps_map     = Map.empty
            , _ps_setup   = now
          }
    -- write out the new store
    save_ps pmc (mk_aek pwt) ps
    when (not no_li) $ login pmc False $ Just pwt
  where
    PMConfig{..} = pmc

-- | launch an interactive shell with access to the password store; if the bool
-- boolean flag is True then it will loop asking for the passwoord until the
-- correct password is typed (or an error ocurrs, possibly from a SIGint);
-- if no 'PasswordText' is specified then one will be read from stdin
login :: PW p => PMConfig p -> Bool -> Maybe PasswordText -> IO ()
login pmc y mb = do
  pwt <- maybe (get_pw pmc) return mb
  ok  <- passwordValid pmc pwt
  case ok of
    True  -> bindMasterPassword pmc pwt >> good >> _pmc_shell pmc
    False ->                               bad  >> login pmc y Nothing
  where
    good  = putStr "*** Login Successful ***\n"
    bad   = bad_f  "*** Password Invalid ***\n"
    bad_f = if y then putStr else error

-- | is this the correct master password?
passwordValid :: PW p => PMConfig p -> PasswordText -> IO Bool
passwordValid pmc = password_valid pmc . mk_aek

-- | is the password store there?
isStorePresent :: PW p => PMConfig p -> IO Bool
isStorePresent PMConfig{..} = doesFileExist _pmc_location

-- | are we currently logged in?
amLoggedIn :: PW p => PMConfig p -> IO Bool
amLoggedIn pmc = get_key pmc >>= password_valid pmc

-- | is the password/session bound to a value in the store?
isBound :: PW p => PMConfig p -> p -> Maybe SessionName -> IO Bool
isBound pmc p mb = enquire pmc $ \ps -> return $
  case Map.lookup (pwName p) $ _ps_map ps of
    Nothing           -> False
    Just Password{..} -> maybe True (\snm->Map.member snm $ _pw_sessions) mb

-- | loads a password into the store; if this is a session password and the
-- boolean ss is True then the session will be reset to this password also;
-- if no 'PasswordText' is specified then one will be read from stdin
load :: PW p => PMConfig p -> p -> Maybe PasswordText -> IO ()
load pmc p mb = wrap pmc $ \ps -> do
  pwt <- maybe (get_pw pmc) return mb
  now <- getCurrentTime
  case isSession p of
    Nothing  -> load_pwd ps
      Password
        { _pw_name      = pnm
        , _pw_text      = pwt
        , _pw_sessions  = Map.empty
        , _pw_isOneShot = isOneShot p
        , _pw_primed    = False
        , _pw_setup     = now
        }
    Just ext ->
      case ext pwt of
        Left  err -> ssn_error $ "failed to load session: " ++ err
        Right sd  -> load_ssn now ps pwt sd
  where
    load_ssn now ps pwt SessionDescriptor{..} =
        load_pwd ps $
          L.set  pw_text       pwt                        $
          L.over pw_sessions  (Map.insert _sd_name ssn)   $
          L.set  pw_isOneShot  ios                        $
            pw
      where
        pw  = maybe pw0 id $ Map.lookup pnm $ _ps_map ps
        pw0 =
          Password
            { _pw_name      = pnm
            , _pw_text      = pwt
            , _pw_sessions  = Map.empty
            , _pw_isOneShot = ios
            , _pw_primed    = False
            , _pw_setup     = now
            }

        ssn =
          Session
            { _ssn_name      = _sd_name
            , _ssn_password  = pwt
            , _ssn_isOneShot = ios
            , _ssn_setup     = now
            }

        ios         = _sd_isOneShot

    load_pwd ps pw  = return $ Just $ L.over ps_map (Map.insert pnm pw) ps

    pnm             = pwName p

-- | set the comment for the password store
psComment :: PW p => PMConfig p -> PasswordStoreComment -> IO ()
psComment pmc cmt = wrap pmc $ \ps -> return $ Just $ L.set ps_comment cmt ps

-- | collect the available passwords listed in 'CollectConfig' from the store
-- and bind them in their designated environmants variables
collect :: PW p => PMConfig p -> CollectConfig p -> IO ()
collect pmc CollectConfig{..} = wrap_ pmc $ \ps -> do
    -- set up the environment
    mapM_ (clct pmc ps) _cc_active
    -- now clear down all of the primed passwords
    return $ Just $ L.over ps_map (Map.map (L.set pw_primed False)) ps
  where
    clct :: PW p => PMConfig p -> PasswordStore -> p -> IO ()
    clct _ ps p = case Map.lookup (pwName p) $ _ps_map ps of
      Just pw | is_primed pw -> set_env (enVar p) (_pw_text pw)
      _                      -> return ()

    wrap_ = if _cc_optional then wrap_def else wrap

-- | prime a one-shot password so that it will be availabe on the next collection (probably for a deployment);
-- if no password is specified then they are all primed
prime :: PW p => PMConfig p -> Bool -> Maybe p -> IO ()
prime pmc u Nothing  = wrap pmc $ \ps -> return $ Just $ L.over ps_map (Map.map    (L.set pw_primed $ not u)           ) ps
prime pmc u (Just p) = wrap pmc $ \ps -> return $ Just $ L.over ps_map (Map.adjust (L.set pw_primed $ not u) (pwName p)) ps

-- | select a different session for use
select :: PW p => PMConfig p -> Maybe p -> SessionName -> IO ()
select pmc mb snm = wrap pmc $ \ps -> f ps <$> lookup_session mb snm ps
  where
    f ps (p,pw,ssn) =  Just $ L.over ps_map (Map.insert (pwName p) (upd pw ssn)) ps

    upd pw Session{..} =
      L.set pw_text      _ssn_password  $
      L.set pw_isOneShot _ssn_isOneShot $
      L.set pw_primed     False         $
        pw

-- | delete a password from the store
deletePassword :: PW p => PMConfig p -> p -> IO ()
deletePassword pmc p = wrap pmc $ \ps -> return $ Just $ L.over ps_map (Map.delete (pwName p)) ps

-- | delete a session from the store
deleteSession :: PW p => PMConfig p -> Maybe p -> SessionName -> IO ()
deleteSession pmc mb snm = wrap pmc $ \ps -> do
  trp <- lookup_session mb snm ps
  chk trp
  return $ f ps trp
  where
    chk (p,pw,ssn)
      | Just ext <- isSession p
      , Right sd <- ext $ _pw_text pw
      , _sd_name sd /= _ssn_name ssn
                  = return ()
      | otherwise = error "cannot delete this session (is it selected?)"

    f   ps (p,pw,_) = Just $ L.over ps_map (Map.insert (pwName p) (L.over pw_sessions (Map.delete snm) pw)) ps


-- | print a status line; if @q@ is @True@ then don't output anything and exit
-- with fail code 1 if not logged in
status :: PW p => PMConfig p -> Bool -> IO ()
status pmc q = (if q then flip catch hdl else id) $ enquire pmc line
  where
    line ps = putStrLn $
      "Logged in ["                         ++
          unwords sns' ++ "/" ++ unwords pps' ++ "] ("    ++
          (T.unpack $ _PasswordStoreComment $ _ps_comment ps) ++ ")"
      where
        sns' = sns ++ ["+" ++ show (len pmc (lookup_sessions Nothing (const True) ps) - length sns)]
        pps' = pps ++ ["+" ++ show (Map.size (_ps_map ps)                             - length pps)]

        sns =
          [ T.unpack $ _SessionName $ _sd_name sd
            | pw <- Map.elems $ _ps_map ps
            , let Password{..} = pw
            , Just  p   <- [parsePwName _pw_name]
            , Just  prs <- [isSession $ cast_pmc pmc p]
            , Right sd  <- [prs _pw_text]
            , is_primed pw
            ]

        pps =
          [ T.unpack $ _PasswordName $ _pw_name pw
            | pw     <- Map.elems $ _ps_map ps
            , _pw_isOneShot pw && is_primed pw
            ]

    len :: PMConfig p -> [(p,Password,Session)] -> Int
    len _ = length

    hdl (_::SomeException) = exitWith $ ExitFailure 1

-- | list the passwords, one per line; if @a@ is set then all passwords will be listed,
-- otherwise just the primed passwords will be listed
passwords :: PW p => PMConfig p -> Bool -> IO ()
passwords pmc br = do
  tz <- getCurrentTimeZone
  enquire pmc $ \ps ->
    putStr $ unlines $ map (fmt tz) $ pws ps
  where
    fmt :: PW p => TimeZone -> (p,Password) -> String
    fmt tz (p,Password{..})
        | br        = nm_s
        | otherwise = printf "%-12s %c %2s $%-18s %s %s" nm_s p_c sn_s ev_s su_s cmt
      where
        nm_s = T.unpack $ _PasswordName _pw_name
        p_c  = if _pw_isOneShot then prime_char _pw_primed else ' '
        sn_s = case Map.size _pw_sessions of
          0 -> ""
          n -> show n
        ev_s = T.unpack $ _EnvVar $ enVar p
        su_s = pretty_setup tz _pw_setup
        cmt  = case summarize p of
          "" -> ""
          cs -> "# " ++ cs

    pws ps =
      [ (cast_pmc pmc p,pwd)
        | p <- [minBound..maxBound]
        , Just pwd <- [Map.lookup (pwName p) $ _ps_map ps]
        ]

-- | list the sessions, one per line; if @p@ is specified then all of the
-- sessions are listed for that password
sessions :: PW p
         => PMConfig p
         -> Bool        -- ^ list active sessions only
         -> Bool        -- ^ list only the session identifiers
         -> Maybe p     -- ^ if specified, then only the sessions on this password
         -> IO ()
sessions pmc a b mb = do
  tz <- getCurrentTimeZone
  enquire pmc $ \ps ->
    let trps  = case a of
          True  -> [ trp | trp@(_,pw,_)<-trps_, active_session trp && is_primed pw]
          False -> trps_
        trps_ = lookup_sessions mb (const True) ps
    in
    putStr $ unlines $ map (fmt tz) trps
  where
    fmt tz trp@(_,Password{..},Session{..}) =
      case b of
        True  -> printf "%s" sn_s
        False ->
          case sgl of
            True  -> printf "%-16s %c %s %s"            sn_s p_c su_s a_s
            False -> printf "%-12s %-16s %c %s %s" pn_s sn_s p_c su_s a_s
      where
        pn_s = T.unpack $ _PasswordName _pw_name
        sn_s = T.unpack $ _SessionName  _ssn_name
        p_c  = if _ssn_isOneShot then prime_char False else ' '
        su_s = pretty_setup tz _ssn_setup
        a_s  = if active_session trp then "[ACTIVE]" else "" :: String

    sgl = length [ () | p<-[minBound..maxBound], isJust $ isSession $ cast_pmc pmc p ] == 1

-- | print the info, including the text descriton, for an individual passowrd
infoPassword :: PW p
             => PMConfig p
             -> Bool          -- ^ True => show the password secret text
             -> p             -- ^ the password to show
             -> IO ()
infoPassword pmc sh_s p = do
  doc <- infoPassword_ pmc sh_s p
  putStr $ P.displayS (P.renderPretty 0.75 120 doc) ""

-- | get the info on a password
infoPassword_ :: PW p => PMConfig p -> Bool -> p -> IO P.Doc
infoPassword_ pmc sh_s p = do
  tz <- getCurrentTimeZone
  enquire pmc $ \ps ->
    return $ maybe P.empty (mk tz) $ Map.lookup pnm $ _ps_map ps
  where
    mk tz pw@Password{..} =
        heading           P.<$$> P.indent 4 (
            sssions       P.<>
            primed        P.<$$>
            evar          P.<$$>
            loaded        P.<$$>
            secret        P.<>
            P.empty       P.<$$>
            descr
          )               P.<$$>
          P.empty
      where
        heading  = P.bold $ P.string $ T.unpack $ _PasswordName pnm
        sssions = case isSession p of
          Nothing -> P.empty
          Just xt -> (line   "sessions" $ fmt_sns xt) P.<$$> P.empty
        primed     =  line   "primed"   $ if is_primed pw then "yes" else "no"
        evar       =  line   "env var"  $ T.unpack $ _EnvVar $ enVar p
        loaded     =  line   "loaded"   $ pretty_setup tz $ _pw_setup
        descr      = P.string $ describe p
        secret = case sh_s of
          True  -> (line   "secret" $ T.unpack $ _PasswordText _pw_text) P.<$$> P.empty
          False -> P.empty

        fmt_sns xt = sn ++ " / " ++ unwords (map (T.unpack . _SessionName) $ filter fl sns)
          where
            sn = either (\s->"<<"++s++">>") (T.unpack . _SessionName . _sd_name ) ei
            fl = either (\_ _->False)       (\sd sn'->_sd_name sd/=sn')           ei
            ei = xt _pw_text

        sns = Map.keys _pw_sessions

        line :: String -> String -> P.Doc
        line nm vl = P.bold(P.string $ ljust 8 nm) P.<> P.string " : " P.<>
                                                        P.hang 8 (P.string vl)

    pnm       = pwName p

    ljust n s = s ++ replicate (max 0 (n-length s)) ' '

-- | dump the store in a s script that can be used to reload it
dump :: PW p => PMConfig p -> Bool -> IO ()
dump pmc inc_ssns = enquire pmc dmp >> prime pmc True Nothing
  where
    dmp ps@PasswordStore{..} = putStr $ format_dump (_pmc_dump_prefix pmc) _ps_comment al_l al_s
      where
        al_l =
            [ (p,_pw_text pw)
              | p <- [minBound..maxBound]
              , Just pw <- [Map.lookup (pwName $ cast_pmc pmc p) _ps_map]
              , isNothing $ isSession p
              , is_primed pw
              ] ++
            [ (p,_ssn_password ssn)
              | inc_ssns
              , (p,_,ssn) <- lookup_sessions Nothing (const True) ps
              ]

        al_s =
            [ (p,_sd_name sd)
              | inc_ssns
              , p <- [minBound..maxBound]
              , Just  pw <- [Map.lookup (pwName $ cast_pmc pmc p) _ps_map]
              , Just ext <- [isSession p]
              , Right sd <- [ext $ _pw_text pw]
              ]

-- | collect the passowrds, bthem into the environmant and launch an interacive shell
collectShell :: PW p => PMConfig p -> IO ()
collectShell pmc = collect pmc defaultCollectConfig >> _pmc_shell pmc

-- | check whether a password is primed for use
is_primed :: Password -> Bool
is_primed Password{..} = not _pw_isOneShot || _pw_primed

-- | lookup a session in a password store, possibly specifying the password it belogs to; exactly
-- one session must be found, otherwise an error is generated
lookup_session :: PW p => Maybe p -> SessionName -> PasswordStore -> IO (p,Password,Session)
lookup_session mb snm ps =
  case lookup_sessions mb (==snm) ps of
    []  -> err "session not loaded"
    [r] -> return r
    _   -> err "matches multiple sessions"
  where
    err msg = ssn_error $ "lookup_session: " ++ T.unpack(_SessionName snm) ++ ": " ++ msg

-- | lookup all of the sessions in a password store
lookup_sessions :: PW p => Maybe p -> (SessionName->Bool) -> PasswordStore -> [(p,Password,Session)]
lookup_sessions mb f ps =
  [ (p,pw,ssn)
    | p <- [minBound..maxBound]
    , maybe True (p==) mb
    , isJust $ isSession p
    , let pnm = pwName p
    , Just pw  <- [Map.lookup pnm $ _ps_map ps]
    , ssn <- filter (f . _ssn_name) $ Map.elems $ _pw_sessions pw
    ]

active_session :: PW p => (p,Password,Session) -> Bool
active_session (p,Password{..},Session{..}) = not $ null
  [ ()
    | Just ext <- [isSession p]
    , Right sd <- [ext _pw_text]
    , _sd_name sd == _ssn_name
    ]

-- | read a passord from stdin and hash it
get_pw :: PW p => PMConfig p -> IO PasswordText
get_pw pmc = do
  hSetEcho stdin False
  putStr "Password: "
  hFlush stdout
  pw <- getLine
  putChar '\n'
  hSetEcho stdin True
  return $ hashMasterPassword pmc pw

-- | use a '+' to represent a primed one-shot password,'-' otherwise
prime_char :: Bool -> Char
prime_char is_p = if is_p then '+' else '-'

-- | make up a script for loading a password store
format_dump :: PW p
            => String               -- ^ the prefix for each script command line
            -> PasswordStoreComment -- ^ the store comment
            -> [(p,PasswordText)]   -- ^ the passwords to load
            -> [(p,SessionName)]    -- ^ the sessions to select
            -> String
format_dump pfx ps_cmt al_l al_s =
  unlines $
    (printf "%s comment %s ;" pfx $ esc $ T.unpack $ _PasswordStoreComment ps_cmt) :
    [ printf "%s load %-12s %-20s %-30s ;" pfx pnm_s ptx_s $ cmt_s p
      | (p,ptx) <- al_l
      , let pnm_s = T.unpack $ _PasswordName $ pwName p
      , let ptx_s = T.unpack $ _PasswordText   ptx
      ] ++
    [ printf "%s select -p %s %s ;" pfx pnm_s snm_s
      | (p,snm) <- al_s
      , let pnm_s = T.unpack $ _PasswordName $ pwName p
      , let snm_s = T.unpack $ _SessionName    snm
      ]
  where
    cmt_s  p = case summarize p of
      "" -> ""
      s  -> "# " ++ esc s

    esc s = '\'' : foldr tr "\'" s
      where
        tr '\'' t = '\\' : '\'' : t
        tr c    t = c           : t

wrap_def :: PW p => PMConfig p -> (PasswordStore -> IO (Maybe PasswordStore)) -> IO ()
wrap_def pmc f = maybe (return ()) (wrap' pmc f) =<< get_key' pmc

wrap :: PW p => PMConfig p -> (PasswordStore -> IO (Maybe PasswordStore)) -> IO ()
wrap pmc f = get_key pmc >>= wrap' pmc f

wrap' :: PW p => PMConfig p -> (PasswordStore -> IO (Maybe PasswordStore)) -> AESKey -> IO ()
wrap' pmc f aek = do
  pws <- load_ps pmc aek
  mb  <- f pws
  maybe (return ()) (save_ps pmc aek) mb

enquire :: PW p => PMConfig p -> (PasswordStore -> IO a) -> IO a
enquire pmc f = do
  aek <- get_key pmc
  load_ps pmc aek >>= f

password_valid :: PW p => PMConfig p -> AESKey -> IO Bool
password_valid pmc aek = catch ld hd
  where
    ld                    = const True <$> load_ps pmc aek
    hd (_::SomeException) = return False

load_ps :: PW p => PMConfig p -> AESKey -> IO PasswordStore
load_ps pmc aek = do
  aed <- load_ps' pmc
  case decodeWithErrs $ BL.fromChunks [_Binary $ _ClearText $ decryptAES aek aed] of
    Right pws -> return pws
    Left  ers -> error $ prettyJSONErrorPositions ers

save_ps :: PW p => PMConfig p -> AESKey -> PasswordStore -> IO ()
save_ps pmc aek pws = do
  iv <- random_bytes sizeAesIV IV
  save_ps' pmc $ encryptAES aek iv $ ClearText $ Binary $ BL.toStrict $ A.encode pws

load_ps' :: PW p => PMConfig p -> IO AESSecretData
load_ps' PMConfig{..} = flip catch hdl $ do
  (iv,ct) <- B.splitAt (_Octets sizeAesIV) <$> B.readFile _pmc_location
  return
    AESSecretData
      { _asd_iv          = IV         $ Binary iv
      , _asd_secret_data = SecretData $ Binary ct
      }
  where
    hdl (_::SomeException) = error _pmc_keystore_msg

random_bytes :: Octets -> (Binary->a) -> IO a
random_bytes sz f = f . Binary . fst . generateCPRNG (_Octets sz) <$> newCPRNG

save_ps' :: PW p => PMConfig p -> AESSecretData -> IO ()
save_ps' PMConfig{..} AESSecretData{..} = B.writeFile _pmc_location $ B.concat [iv_bs,ct_bs]
  where
    iv_bs = _Binary $ _IV         _asd_iv
    ct_bs = _Binary $ _SecretData _asd_secret_data

get_key :: PW p => PMConfig p -> IO AESKey
get_key pmc@PMConfig{..} = get_key' pmc >>= maybe (not_logged_in_err pmc) return

not_logged_in_err :: PW p => PMConfig p -> IO a
not_logged_in_err pmc@PMConfig{..} = do
  ex <- isStorePresent pmc
  error $ if ex then _pmc_password_msg else _pmc_keystore_msg

get_key' :: PW p => PMConfig p -> IO (Maybe AESKey)
get_key' PMConfig{..} = fmap mk_aek' <$> lookupEnv var
  where
    var = T.unpack $ _EnvVar _pmc_env_var

mk_aek :: PasswordText -> AESKey
mk_aek = mk_aek' . T.unpack . _PasswordText

mk_aek' :: String -> AESKey
mk_aek' = AESKey . Binary . either err id . B64.decode . B.pack
  where
    err = error "bad format for the master password"

pretty_setup :: TimeZone -> UTCTime -> String
pretty_setup tz = formatTime defaultTimeLocale "%F %H:%M" . utcToZonedTime tz

set_env :: EnvVar -> PasswordText -> IO ()
set_env (EnvVar ev) (PasswordText pt) = setEnv (T.unpack ev) (T.unpack pt)

ssn_error :: String -> a
ssn_error msg = error $ "session manager error: " ++ msg


--
-- The Command Line Parser
--


data PMCommand p
    = PMCD_version
    | PMCD_setup  Bool   (Maybe PasswordText)
    | PMCD_login  Bool   (Maybe PasswordText)
    | PMCD_load        p (Maybe PasswordText)
    | PMCD_comment       PasswordStoreComment
    | PMCD_prime     Bool p
    | PMCD_prime_all Bool
    | PMCD_select          (Maybe p) SessionName
    | PMCD_delete_password        p
    | PMCD_delete_session  (Maybe p) SessionName
    | PMCD_status    Bool
    | PMCD_passwords Bool
    | PMCD_sessions  Bool Bool (Maybe p)
    | PMCD_info      Bool         p
    | PMCD_dump      Bool
    | PMCD_collect
    | PMCD_sample_script
    deriving (Show)

parse_command :: PW p => PMConfig p -> [String] -> IO (PMCommand p)
parse_command pmc = run_parse $ command_info pmc

command_info :: PW p => PMConfig p -> ParserInfo (PMCommand p)
command_info pmc =
    O.info (helper <*> command_parser pmc)
        (   fullDesc
         <> progDesc "a simple password manager"
         <> header "pm - sub-command for managing the password store"
         <> footer "'ks COMMAND --help' to get help on each command")

command_parser :: PW p => PMConfig p -> Parser (PMCommand p)
command_parser pmc =
    subparser $ f $ g
     $  command "version"             pi_version
     <> command "setup"               pi_setup
     <> command "login"               pi_login
     <> command "load"                pi_load
     <> command "comment"             pi_comment
     <> command "prime"               pi_prime
     <> command "prime-all"           pi_prime_all
     <> command "select"              pi_select
     <> command "delete-password"     pi_delete_password
     <> command "delete-session"      pi_delete_session
     <> command "status"              pi_status
     <> command "passwords"           pi_passwords
     <> command "sessions"            pi_sessions
     <> command "info"                pi_info
     <> command "collect"             pi_collect
  where
    s = command "sample-load-script"  pi_sample_script
    d = command "dump"                pi_dump

    f = case _pmc_sample_script pmc of
          Nothing -> id
          Just _  -> (<> s)

    g = case _pmc_allow_dumps pmc of
          True    -> (<> d)
          False   -> id

pi_version :: ParserInfo (PMCommand p)
pi_version =
    h_info
        (helper <*> pure PMCD_version)
        (progDesc "report the version of this package")

pi_setup :: ParserInfo (PMCommand p)
pi_setup =
    h_info
        (helper <*> (PMCD_setup <$> p_no_login_sw <*> optional p_password_text))
        (progDesc "setup the password store")

pi_login :: ParserInfo (PMCommand p)
pi_login =
    h_info
        (helper <*> (PMCD_login <$> p_loop_sw <*> optional p_password_text))
        (progDesc "login to the password manager")

pi_load :: PW p => ParserInfo (PMCommand p)
pi_load =
    h_info
        (helper <*> (PMCD_load <$> p_pw_id <*> optional p_password_text) <* optional p_load_comment)
        (progDesc "load a password into the store")

pi_comment :: PW p => ParserInfo (PMCommand p)
pi_comment =
    h_info
        (helper <*> (PMCD_comment <$> p_ps_comment))
        (progDesc "load a password into the store")

pi_prime :: PW p => ParserInfo (PMCommand p)
pi_prime =
    h_info
        (helper <*> (PMCD_prime <$> p_unprime_sw <*> p_pw_id))
        (progDesc "(un) prime a password for use")

pi_prime_all :: ParserInfo (PMCommand p)
pi_prime_all =
    h_info
        (helper <*> (PMCD_prime_all <$> p_unprime_sw))
        (progDesc "(un)prime all of the passwords")

pi_select :: PW p => ParserInfo (PMCommand p)
pi_select =
     h_info
        (helper <*> (PMCD_select <$> optional p_pw_id_opt <*> p_session_name))
        (progDesc "select a client session")

pi_delete_password :: PW p => ParserInfo (PMCommand p)
pi_delete_password =
     h_info
        (helper <*> (PMCD_delete_password <$> p_pw_id))
        (progDesc "select a client session")

pi_delete_session :: PW p => ParserInfo (PMCommand p)
pi_delete_session =
     h_info
        (helper <*> (PMCD_delete_session <$> optional p_pw_id_opt <*> p_session_name))
        (progDesc "delete a client session")

pi_status :: ParserInfo (PMCommand p)
pi_status =
    h_info
        (helper <*> (PMCD_status <$> p_quiet_sw))
        (progDesc "report the status of the password manager")

pi_passwords :: ParserInfo (PMCommand p)
pi_passwords =
    h_info
        (helper <*> (PMCD_passwords <$> p_brief_sw))
        (progDesc "list the passwords")

pi_sessions :: PW p => ParserInfo (PMCommand p)
pi_sessions =
    h_info
        (helper <*> (PMCD_sessions <$> p_active_sw <*> p_brief_sw <*> optional p_pw_id))
        (progDesc "list the sessions")

pi_info :: PW p => ParserInfo (PMCommand p)
pi_info =
    h_info
        (helper <*> (PMCD_info <$> p_secret_sw <*> p_pw_id))
        (progDesc "print out the info on a password, including desriptive text")

pi_dump :: PW p => ParserInfo (PMCommand p)
pi_dump =
    h_info
        (helper <*> (PMCD_dump <$> p_sessions_sw))
        (progDesc "dump the passwords on the output as a load script")

pi_collect :: PW p => ParserInfo (PMCommand p)
pi_collect =
    h_info
        (helper <*> (pure PMCD_collect))
        (progDesc "collect the passwords and launch an interacive shell")


pi_sample_script :: ParserInfo (PMCommand p)
pi_sample_script =
    h_info
        (helper <*> (pure PMCD_sample_script))
        (progDesc "print a sample script to define keystore passwords in the environment (PM edition)")

p_no_login_sw :: Parser Bool
p_no_login_sw =
    switch
        (short  'n'            <>
         long    "no-login"    <>
         help    "do not launch an interactive shell")

p_loop_sw :: Parser Bool
p_loop_sw =
    switch
        (short  'l'            <>
         long    "loop"        <>
         help    "on failure prompt for a new password and try again")

p_quiet_sw :: Parser Bool
p_quiet_sw =
    switch
        (short  'q'            <>
         long    "quiet"        <>
         help    "don't print anything but report with error codes (0=>logged in)")

p_brief_sw :: Parser Bool
p_brief_sw =
    switch
        (short  'b'            <>
         long    "brief"        <>
         help    "list the identifiers only")

p_active_sw :: Parser Bool
p_active_sw =
    switch
        (short  'a'            <>
         long    "active"      <>
         help    "list the active sessions only")

p_unprime_sw :: Parser Bool
p_unprime_sw =
    switch
        (short  'u'            <>
         long    "unprime"     <>
         help    "clear the prime status")

p_secret_sw :: Parser Bool
p_secret_sw =
    switch
        (short  's'            <>
         long    "secret"      <>
         help    "show the secret password")

p_sessions_sw :: Parser Bool
p_sessions_sw =
    switch
        (long    "sessions"      <>
         help    "include the sessions")

p_pw_id :: PW p => Parser p
p_pw_id =
    argument (parsePwName . PasswordName . T.pack)
        $  metavar "PASSWORD-ID"
        <> help    "a password ID"

p_pw_id_opt :: PW p => Parser p
p_pw_id_opt =
    nullOption
        $  long    "id"
        <> short   'p'
        <> metavar "PASSWORD-ID"
        <> reader  (maybe (fail "password-id not recognised") return . parsePwName . PasswordName . T.pack)
        <> help    "a password ID"

p_password_text :: Parser PasswordText
p_password_text =
    argument (Just . PasswordText . T.pack)
        $  metavar "PASSWORD-TEXT"
        <> help    "the text of the password"

p_session_name :: Parser SessionName
p_session_name =
    argument (Just . SessionName . T.pack)
        $  metavar "SESSION"
        <> help    "a session name"

p_load_comment :: Parser ()
p_load_comment = const () <$> optional (p_hash <* p_comment)

p_ps_comment :: Parser PasswordStoreComment
p_ps_comment = PasswordStoreComment . T.pack <$> p_comment

p_hash :: Parser ()
p_hash = argument (\s->if s=="#" then Just () else Nothing) $ metavar "#"

p_comment :: Parser String
p_comment = unwords <$> many p_word

p_word :: Parser String
p_word = argument Just $ metavar "WORD"

h_info :: Parser a -> InfoMod a -> ParserInfo a
h_info pr = O.info (helper <*> pr)

run_parse :: ParserInfo a -> [String] -> IO a
run_parse pinfo args =
  case execParserPure (prefs idm) pinfo args of
    Success a -> return a
    Failure failure -> do
      progn <- getProgName
      let (msg, exit) = execFailure failure progn
      case exit of
        ExitSuccess -> putStrLn msg
        _           -> hPutStrLn stderr msg
      exitWith exit
    CompletionInvoked compl -> do
      progn <- getProgName
      msg   <- execCompletion compl progn
      putStr msg
      exitWith ExitSuccess
