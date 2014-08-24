{-# LANGUAGE OverloadedStrings          #-}

module Deploy.Command
    ( CLI(..)
    , Command(..)
    , parseCLI
    ) where

import           Deploy.HostSectionKey
import           Data.KeyStore
import           Data.Monoid
import           Options.Applicative
import           System.Environment


data CLI =
    CLI
        { cli_params    :: CtxParams
        , cli_command   :: Command
        }
    deriving (Show)

data Command
    = Create
    | Rotate        (Maybe HostID)  (Maybe SectionID)  (Maybe KeyID)
    | RotateSmart   (Maybe HostID)  (Maybe SectionID)  (Maybe KeyID)
    | Deploy        (Maybe FilePath) HostID
    | Sign
    | Verify
    | ListHosts
    | InfoKey       (Maybe KeyID    )
    | InfoSection   (Maybe SectionID)
    | SecretScript
    | PublicScript
    | SampleScript
    | KS            [String]
    deriving (Show)

parseCLI :: IO CLI
parseCLI = do
  args <- getArgs
  case span is_flg args of
    (flgs,"ks":args') -> runParse (pi_cli $ p_ks args') flgs
    _                 -> runParse (pi_cli   p_cli     ) args

pi_cli :: Parser CLI -> ParserInfo CLI
pi_cli psr =
    h_info psr $
        fullDesc   <>
        progDesc "For carrying out deployments from the keystore."

p_ks :: [String] -> Parser CLI
p_ks args = CLI <$> paramsParser <*> pure (KS args)

p_cli :: Parser CLI
p_cli     = CLI <$> paramsParser <*> p_command

p_command :: Parser Command
p_command =
    subparser
     $  command "create"                    pi_create
     <> command "rotate"                   (pi_rotate_key False)
     <> command "rotate-smart"             (pi_rotate_key True )
     <> command "deploy"                    pi_deploy
     <> command "sign"                      pi_sign
     <> command "verify"                    pi_verify
     <> command "list-hosts"                pi_list_hosts
     <> command "info-key"                  pi_info_key
     <> command "info-section"              pi_info_section
     <> command "secret-script"             pi_secret_script
     <> command "public-script"             pi_public_script
     <> command "sample-script"             pi_sample_script
     <> command "ks"                        pi_ks_args

pi_create :: ParserInfo Command
pi_create =
    h_info
        (helper <*> (pure Create))
        (progDesc "create a new keystore")

pi_rotate_key :: Bool -> ParserInfo Command
pi_rotate_key sm =
    h_info
        (helper <*>
            ((if sm then RotateSmart else Rotate)
                <$> optional p_host
                <*> optional p_section
                <*> optional p_key))
        (progDesc $ if sm then "rotate keys, but only if they have changed" else "rotate keys")

pi_deploy :: ParserInfo Command
pi_deploy =
    h_info
        (helper <*> (Deploy <$> optional p_out <*> p_host_arg))
        (progDesc $ "deploy a configuration file for s host " ++
                        "(here merely generating the JSON configuration file)")

pi_sign :: ParserInfo Command
pi_sign =
    h_info
        (helper <*> (pure Sign))
        (progDesc "sign the keystore")

pi_verify :: ParserInfo Command
pi_verify =
    h_info
        (helper <*> (pure Verify))
        (progDesc "verify the keystore")

pi_list_hosts :: ParserInfo Command
pi_list_hosts =
    h_info
        (helper <*> (pure ListHosts))
        (progDesc "list the hosts")

pi_info_key :: ParserInfo Command
pi_info_key =
    h_info
        (helper <*> (InfoKey <$> optional p_key))
        (progDesc "get the gen on the keystore keys")

pi_info_section :: ParserInfo Command
pi_info_section =
    h_info
        (helper <*> (InfoSection <$> optional p_section))
        (progDesc "get the gen on the keystore sections")

pi_secret_script :: ParserInfo Command
pi_secret_script =
    h_info
        (helper <*> (pure SecretScript))
        (progDesc $ "print a script to establish the all section passwords in the environment")

pi_public_script :: ParserInfo Command
pi_public_script =
    h_info
        (helper <*> (pure PublicScript))
        (progDesc "print a script to save the public signing key in a file")

pi_sample_script :: ParserInfo Command
pi_sample_script =
    h_info
        (helper <*> (pure SampleScript))
        (progDesc "print a sample script to define keystore passwords in the environment")

pi_ks_args :: ParserInfo Command
pi_ks_args =
    h_info
        (helper <*> (KS <$> many p_ks_arg))
        (progDesc "run a ks command (see 'ks --help' for details)")

p_host_arg :: Parser HostID
p_host_arg =
    argument decode
        $  metavar "HOST"
        <> help    "a host ID"

p_host :: Parser HostID
p_host =
    nullOption
        $  long "host"
        <> metavar "HOST"
        <> reader (maybe (fail "host not recognised") return . decode)
        <> help    "a host ID"

p_section :: Parser SectionID
p_section =
    nullOption
        $  long "section"
        <> metavar "SECTION"
        <> reader (maybe (fail "section not recognised") return . decode)
        <> help "a section ID"

p_key :: Parser KeyID
p_key =
    nullOption
        $  long "key"
        <> metavar "KEY"
        <> reader (maybe (fail "key not recognised") return . decode)
        <> help "a key ID"

p_out :: Parser FilePath
p_out =
    strOption
        $  long "out"
        <> metavar "FILE"
        <> help "output file"

p_ks_arg :: Parser String
p_ks_arg =
    argument Just
        $  metavar  "KS-ARG"
        <> help     "a ks command argument"

h_info :: Parser a -> InfoMod a -> ParserInfo a
h_info pr = info (helper <*> pr)

is_flg :: String -> Bool
is_flg ('-':_) = True
is_flg _       = False
