{-# LANGUAGE OverloadedStrings          #-}

module Data.KeyStore.Command
    ( Command(..)
    , SubCommand(..)
    , parseCommand
    )
    where

import           Options.Applicative
import           Data.KeyStore.Types
import           Data.String
import           Text.Regex
import qualified Data.Text              as T


data Command =
    Command
        { cmd_store   :: Maybe FilePath
        , cmd_debug   :: Bool
        , cmd_sub     :: SubCommand
        }

data SubCommand
    = Version
    | Initialise      FilePath
    | UpdateSettings  FilePath
    | AddTrigger      TriggerID Pattern FilePath
    | RmvTrigger      TriggerID
    | Create          Name Comment Identity (Maybe EnvVar) (Maybe FilePath) [Safeguard]
    | CreateKeyPair   Name Comment Identity                                 [Safeguard]
    | Secure          Name                                 (Maybe FilePath) [Safeguard]
    | List
    | Info           [Name]
    | ShowIdentity    Bool Name
    | ShowComment     Bool Name
    | ShowDate        Bool Name
    | ShowHash        Bool Name
    | ShowHashComment Bool Name
    | ShowHashSalt    Bool Name
    | ShowPublic      Bool Name
    | ShowSecret Bool Name
    | Encrypt         Name    FilePath FilePath
    | Decrypt                 FilePath FilePath
    | Sign            Name    FilePath FilePath
    | Verify                  FilePath FilePath
    | Delete         [Name]
    deriving (Show)

parseCommand :: IO Command
parseCommand = execParser opts
  where
    opts =
        info (helper <*> (p_version <|> p_command))
            (   fullDesc
             <> progDesc "for storing secret things"
             <> header "ks - key store management"
             <> footer "'ks COMMAND --help' to get help on each command")

p_version :: Parser Command
p_version =
    flag' (Command Nothing False Version)
        $  long "version"
        <> help "display the version"


p_command :: Parser Command
p_command =
    Command
        <$> optional p_store
        <*> p_debug_flg
        <*> p_sub_command

p_store :: Parser FilePath
p_store =
    strOption
        $  long "store"
        <> metavar "FILE"
        <> help "the file containing the key store"

p_debug_flg :: Parser Bool
p_debug_flg =
    switch
        $  long  "debug"
        <> short 'd'
        <> help  "enable debug logging"

p_sub_command :: Parser SubCommand
p_sub_command =
    subparser
     $  command "version"           pi_version
     <> command "initialise"        pi_initialise
     <> command "update-settings"   pi_update_settings
     <> command "add-trigger"       pi_add_trigger
     <> command "rmv-trigger"       pi_rmv_trigger
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
    , pi_initialise
    , pi_update_settings
    , pi_add_trigger
    , pi_rmv_trigger
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
    , pi_delete :: ParserInfo SubCommand

pi_version =
    h_info
        (pure Version)
        (progDesc "initialise a new key store")

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
        (progDesc "update settings")

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
    argument (Just . TriggerID . T.pack)
        $  metavar "TRIGGER"
        <> help    "name of the triggered settings"

p_pattern :: Parser Pattern
p_pattern =
    argument (Just . mk)
        $  metavar "REGEX"
        <> help    "POSIX regular expression for selecting matching keys"
  where
    mk s = Pattern s $ mkRegex s

p_name :: Parser Name
p_name =
    argument (either (const Nothing) Just . name)
        $  metavar "NAME"
        <> help    "name of the key"

p_comment :: Parser Comment
p_comment =
    argument (Just . Comment . T.pack)
        $  metavar "COMMENT"
        <> help    "comment text"

p_identity :: Parser Identity
p_identity = fmap (maybe "" id) $ optional $
    argument (Just . Identity . T.pack)
        $  metavar "KEY-IDENTITY"
        <> help    "identity of the key"

p_env_var :: Parser EnvVar
p_env_var =
    argument (Just . fromString)
        $  metavar "ENV-VAR"
        <> help    "environment variable to hold the key's value"

p_safeguard :: Parser Safeguard
p_safeguard =
    nullOption
        $  long "safeguard"
        <> reader (either (const $ fail msg) return . parseSafeguard)
        <> metavar "SAFEGUARD"
        <> help "keys used to encrypt the secret key"
  where
    msg = "bad safeguard syntax"

p_key_text :: Parser FilePath
p_key_text =
    strOption
        $  long "key-file"
        <> metavar "FILE"
        <> help "secret key file"

p_file :: String -> String -> Parser FilePath
p_file mtv hlp =
    argument Just
        $  metavar mtv
        <> help    hlp

p_armour :: Parser Bool
p_armour =
    switch
        $ long "base-64"
        <> help "base-64 encode the result"

h_info :: Parser a -> InfoMod a -> ParserInfo a
h_info pr = info (helper <*> pr)
