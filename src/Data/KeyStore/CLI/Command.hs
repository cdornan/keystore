{-# LANGUAGE OverloadedStrings          #-}
{-# OPTIONS_GHC -fno-warn-unused-imports#-}

module Data.KeyStore.CLI.Command
    ( CLI(..)
    , Command(..)
    , parseCLI
    , parseCLI'
    , cliInfo
    , cliParser
    , paramsParser
    , runParse
    )
    where

import           Data.KeyStore.KS.Opt
import           Data.KeyStore.Types
import           Data.KeyStore.IO.IC
import           Data.Monoid
import           Data.String
import           Text.Regex
import qualified Data.Text              as T
import           Options.Applicative
import           System.Environment
import           System.Exit
import           System.IO


data CLI =
    CLI
        { cli_params    :: CtxParams
        , cli_command   :: Command
        }
    deriving (Show)

data Command
    = Version
    | Keystore
    | Initialise        FilePath
    | UpdateSettings    FilePath
    | ListSettings
    | ListSettingOpts  (Maybe OptEnum)
    | AddTrigger        TriggerID Pattern FilePath
    | RmvTrigger        TriggerID
    | ListTriggers
    | Create            Name Comment Identity (Maybe EnvVar) (Maybe FilePath) [Safeguard]
    | CreateKeyPair     Name Comment Identity                                 [Safeguard]
    | Secure            Name                                 (Maybe FilePath) [Safeguard]
    | List
    | Info             [Name]
    | ShowIdentity      Bool Name
    | ShowComment       Bool Name
    | ShowDate          Bool Name
    | ShowHash          Bool Name
    | ShowHashComment   Bool Name
    | ShowHashSalt      Bool Name
    | ShowPublic        Bool Name
    | ShowSecret   Bool Name
    | Encrypt           Name    FilePath FilePath
    | Decrypt                   FilePath FilePath
    | Sign              Name    FilePath FilePath
    | Verify                    FilePath FilePath
    | Delete           [Name]
    deriving (Show)

parseCLI :: IO CLI
parseCLI = getArgs >>= parseCLI'

parseCLI' :: [String] -> IO CLI
parseCLI' = runParse cliInfo

cliInfo :: ParserInfo CLI
cliInfo =
    info (helper <*> cliParser)
        (   fullDesc
         <> progDesc "for storing secret things"
         <> header "ks - key store management"
         <> footer "'ks COMMAND --help' to get help on each command")

cliParser :: Parser CLI
cliParser =
    CLI
      <$> paramsParser
      <*> p_command

paramsParser :: Parser CtxParams
paramsParser =
    CtxParams
      <$> optional p_store
      <*> optional (p_debug_flg    <|> p_no_debug_flg )
      <*> optional (p_readonly_flg <|> p_writeback_flg)

p_store :: Parser FilePath
p_store =
    strOption
      $  long "store"
      <> metavar "FILE"
      <> help "the file containing the key store"

p_debug_flg :: Parser Bool
p_debug_flg =
    flag' True
      $  long  "debug"
      <> short 'd'
      <> help  "enable debug logging"

p_no_debug_flg :: Parser Bool
p_no_debug_flg =
    flag' False
      $  long  "no-debug"
      <> short 'q'
      <> help  "disable debug logging"

p_readonly_flg :: Parser Bool
p_readonly_flg =
    flag' True
      $  long  "readonly"
      <> short 'r'
      <> help  "disable updating of keystore"

p_writeback_flg :: Parser Bool
p_writeback_flg =
    flag' False
      $  long  "writeback"
      <> short 'w'
      <> help  "write back the keystore"

p_command :: Parser Command
p_command =
    subparser
     $  command "version"           pi_version
     <> command "keystore"          pi_keystore
     <> command "initialise"        pi_initialise
     <> command "update-settings"   pi_update_settings
     <> command "list-settings"     pi_list_settings
     <> command "list-setting-opts" pi_list_setting_opts
     <> command "add-trigger"       pi_add_trigger
     <> command "rmv-trigger"       pi_rmv_trigger
     <> command "list-triggers"     pi_list_triggers
     <> command "create"            pi_create
     <> command "create-key-pair"   pi_create_key_pair
     <> command "secure"            pi_secure
     <> command "list"              pi_list
     <> command "info"              pi_info
     <> command "show-identity"     pi_show_identity
     <> command "show-comment"      pi_show_comment
     <> command "show-date"         pi_show_date
     <> command "show-hash"         pi_show_hash
     <> command "show-hash-comment" pi_show_hash_comment
     <> command "show-hash-salt"    pi_show_hash_salt
     <> command "show-public"       pi_show_public
     <> command "show-secret"       pi_show_secret
     <> command "encrypt"           pi_encrypt
     <> command "decrypt"           pi_decrypt
     <> command "sign"              pi_sign
     <> command "verify"            pi_verify
     <> command "delete"            pi_delete

pi_version
    , pi_keystore
    , pi_initialise
    , pi_update_settings
    , pi_list_settings
    , pi_list_setting_opts
    , pi_add_trigger
    , pi_rmv_trigger
    , pi_list_triggers
    , pi_create
    , pi_create_key_pair
    , pi_secure
    , pi_list
    , pi_info
    , pi_show_identity
    , pi_show_comment
    , pi_show_date
    , pi_show_hash
    , pi_show_hash_comment
    , pi_show_hash_salt
    , pi_show_public
    , pi_show_secret
    , pi_encrypt
    , pi_decrypt
    , pi_sign
    , pi_verify
    , pi_delete :: ParserInfo Command

pi_version =
    h_info
        (helper <*> pure Version)
        (progDesc "report the version of this package")

pi_keystore =
    h_info
        (helper <*> pure Keystore)
        (progDesc "list the details of the keystore")

pi_initialise =
    h_info
        (helper <*>
            (Initialise
                <$> p_file "FILE" "home of the new keystore"))
        (progDesc "initialise a new key store")

pi_update_settings =
    h_info
        (helper <*>
            (UpdateSettings
                <$> p_file "JSON-SETTINGS-FILE"  "new settings"))
        (progDesc "update the keystore settings")

pi_list_settings =
    h_info
        (helper <*>
            (pure ListSettings))
        (progDesc "dump the keystore settings on stdout")

pi_list_setting_opts =
    h_info
        (helper <*>
            (ListSettingOpts
                <$> optional p_opt))
        (progDesc "list the settings options")

pi_add_trigger =
    h_info
        (helper <*>
            (AddTrigger
                <$> p_trigger_id
                <*> p_pattern
                <*> p_file "JSON-SETTINGS-FILE"  "conditional settings"))
        (progDesc "add trigger")

pi_rmv_trigger =
    h_info
        (helper <*>
            (RmvTrigger
                <$> p_trigger_id))
        (progDesc "remove trigger")

pi_list_triggers =
    h_info
        (helper <*>
            (pure ListTriggers))
        (progDesc "remove trigger")

pi_create =
    h_info
        (helper <*>
            (Create
                <$> p_name
                <*> p_comment
                <*> p_identity
                <*> optional p_env_var
                <*> optional p_key_text
                <*> many p_safeguard))
        (progDesc "create a key")

pi_create_key_pair =
    h_info
        (CreateKeyPair
            <$> p_name
            <*> p_comment
            <*> p_identity
            <*> many p_safeguard)
        (progDesc "create an RSA key pair")

pi_secure =
    h_info
        (Secure
            <$> p_name
            <*> optional p_key_text
            <*> many p_safeguard)
        (progDesc "insert an encrypted copy of the named secret key")

pi_list =
    h_info
        (pure List)
        (progDesc "list individual keys or all keys in the store")

pi_info =
    h_info
        (Info
            <$> many p_name)
        (progDesc "list individual keys or all keys in the store")

pi_show_identity =
    h_info
        (ShowIdentity
            <$> p_armour
            <*> p_name)
        (progDesc "show the hash of the secret text")

pi_show_comment =
    h_info
        (ShowComment
            <$> p_armour
            <*> p_name)
        (progDesc "show the hash of the secret text")

pi_show_date =
    h_info
        (ShowDate
            <$> p_armour
            <*> p_name)
        (progDesc "show the hash of the secret text")

pi_show_hash =
    h_info
        (ShowHash
            <$> p_armour
            <*> p_name)
        (progDesc "show the hash of the secret text")

pi_show_hash_comment =
    h_info
        (ShowHashComment
            <$> p_armour
            <*> p_name)
        (progDesc "show the hash of the secret text")

pi_show_hash_salt =
    h_info
        (ShowHashSalt
            <$> p_armour
            <*> p_name)
        (progDesc "show the hash of the secret text")

pi_show_public =
    h_info
        (ShowPublic
            <$> p_armour
            <*> p_name)
        (progDesc "show the public key (DER format)")

pi_show_secret =
    h_info
        (ShowSecret
            <$> p_armour
            <*> p_name)
        (progDesc "show the secret text")

pi_encrypt =
    h_info
        (Encrypt
            <$> p_name
            <*> p_file "INPUT-FILE"  "file to encrypt"
            <*> p_file "OUTPUT-FILE" "encrypted file")
        (progDesc "encrypt a file with a named public key")

pi_decrypt =
    h_info
        (Decrypt
            <$> p_file "INPUT-FILE"  "file to decrypt"
            <*> p_file "OUTPUT-FILE" "decrypted file")
        (progDesc "decrypt a file with the private key")

pi_sign =
    h_info
        (Sign
            <$> p_name
            <*> p_file "INPUT-FILE"  "file to sign"
            <*> p_file "OUTPUT-FILE" "file to place the signature")
        (progDesc "sign a file with a named private key")

pi_verify =
    h_info
        (Verify
            <$> p_file "INPUT-FILE"     "file that was signed"
            <*> p_file "SIGNATURE-FILE" "signature to verify")
        (progDesc "verify a file with the public key")

pi_delete =
    h_info
        (Delete
            <$> many p_name)
        (progDesc "delete one or more (unused) keys")

p_trigger_id  :: Parser TriggerID
p_trigger_id =
    argument (eitherReader $ Right . TriggerID . T.pack)
        $  metavar "TRIGGER"
        <> help    "name of the triggered settings"

p_pattern :: Parser Pattern
p_pattern =
    argument (eitherReader $ Right . mk)
        $  metavar "REGEX"
        <> help    "POSIX regular expression for selecting matching keys"
  where
    mk s = Pattern s $ mkRegex s

p_name :: Parser Name
p_name =
    argument (eitherReader $ either (Left . showReason) Right . name)
        $  metavar "NAME"
        <> help    "name of the key"

p_comment :: Parser Comment
p_comment =
    argument (eitherReader $ Right . Comment . T.pack)
        $  metavar "COMMENT"
        <> help    "comment text"

p_identity :: Parser Identity
p_identity = fmap (maybe "" id) $ optional $
    argument (eitherReader $ Right . Identity . T.pack)
        $  metavar "KEY-IDENTITY"
        <> help    "identity of the key"

p_env_var :: Parser EnvVar
p_env_var =
    argument (eitherReader $ Right . fromString)
        $  metavar "ENV-VAR"
        <> help    "environment variable to hold the key's value"

p_safeguard :: Parser Safeguard
p_safeguard =
    option (eitherReader $ either (Left . showReason) Right . parseSafeguard)
        $  long "safeguard"
        <> metavar "SAFEGUARD"
        <> help "keys used to encrypt the secret key"

p_key_text :: Parser FilePath
p_key_text =
    strOption
        $  long    "key-file"
        <> metavar "FILE"
        <> help    "secret key file"

p_file :: String -> String -> Parser FilePath
p_file mtv hlp =
    argument str
        $  metavar mtv
        <> help    hlp

p_armour :: Parser Bool
p_armour =
    switch
        $ long "base-64"
        <> help "base-64 encode the result"

p_opt :: Parser OptEnum
p_opt =
    argument (eitherReader $ maybe (Left "bad SETTING-OPT") Right . parseOpt . T.pack)
        $  metavar "SETTING-OPT"
        <> help    "name of a keystore setting option"

h_info :: Parser a -> InfoMod a -> ParserInfo a
h_info pr = info (helper <*> pr)

runParse :: ParserInfo a -> [String] -> IO a
runParse pinfo args =
  case execParserPure (prefs idm) pinfo args of
    Success a -> return a
    Failure failure -> do
      progn <- getProgName
      let (msg, exit, _) = execFailure failure progn
      case exit of
        ExitSuccess -> putStrLn $ show msg
        _           -> hPutStrLn stderr $ show msg
      exitWith exit
    CompletionInvoked compl -> do
      progn <- getProgName
      msg   <- execCompletion compl progn
      putStr msg
      exitWith ExitSuccess
