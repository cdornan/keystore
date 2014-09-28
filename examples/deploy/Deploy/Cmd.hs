{-# LANGUAGE OverloadedStrings          #-}

module Deploy.Cmd
    ( CtxCmd(..)
    , Cmd(..)
    , parseCLI
    ) where

import           Deploy.HostSectionKey
import           Data.KeyStore
import           Data.Monoid
import           Options.Applicative
import           System.Environment


data CtxCmd =
    CtxCmd
        { cc_params :: CtxParams
        , cc_cmd    :: Cmd
        }
    deriving (Show)

data Cmd
    = C_create
    | C_rotate        (Maybe HostID)  (Maybe SectionID)  (Maybe KeyID)
    | C_rotate_smart  (Maybe HostID)  (Maybe SectionID)  (Maybe KeyID)
    | C_deploy        Bool (Maybe FilePath) HostID
    | C_client
    | C_sign
    | C_verify
    | C_list_hosts
    | C_info_key      (Maybe KeyID    )
    | C_info_section  (Maybe SectionID)
    | C_secret_script
    | C_public_script
    | C_sample_script
    | C_ks CLI
    | C_pm (PMCommand SectionID)
    deriving (Show)

parseCLI :: PMConfig SectionID -> IO CtxCmd
parseCLI pmc = getArgs >>= runParse (pi_cli $ p_cli pmc)

pi_cli :: Parser CtxCmd -> ParserInfo CtxCmd
pi_cli psr =
    h_info psr $
        fullDesc   <>
        progDesc "For carrying out deployments from the keystore."

p_cli :: PMConfig SectionID -> Parser CtxCmd
p_cli pmc = CtxCmd <$> paramsParser <*> (p_command pmc)

p_command :: PMConfig SectionID -> Parser Cmd
p_command pmc =
    subparser
     $  command "create"                    pi_create
     <> command "rotate"                   (pi_rotate_key False)
     <> command "rotate-smart"             (pi_rotate_key True )
     <> command "deploy"                    pi_deploy
     <> command "client"                    pi_client
     <> command "sign"                      pi_sign
     <> command "verify"                    pi_verify
     <> command "list-hosts"                pi_list_hosts
     <> command "info-key"                  pi_info_key
     <> command "info-section"              pi_info_section
     <> command "secret-script"             pi_secret_script
     <> command "public-script"             pi_public_script
     <> command "sample-load-script"        pi_sample_script
     <> command "ks"                        pi_ks_args
     <> command "pm"                       (pi_pm_args pmc)

pi_create :: ParserInfo Cmd
pi_create =
    h_info
        (helper <*> (pure C_create))
        (progDesc "create a new keystore")

pi_rotate_key :: Bool -> ParserInfo Cmd
pi_rotate_key sm =
    h_info
        (helper <*>
            ((if sm then C_rotate_smart else C_rotate)
                <$> optional p_host
                <*> optional p_section
                <*> optional p_key))
        (progDesc $ if sm then "rotate keys, but only if they have changed" else "rotate keys")

pi_deploy :: ParserInfo Cmd
pi_deploy =
    h_info
        (helper <*> (C_deploy <$> p_shell_flg <*> optional p_out <*> p_host_arg))
        (progDesc $ "deploy a configuration file for a host " ++
                        "(here merely generating the JSON configuration file)")

pi_client :: ParserInfo Cmd
pi_client =
    h_info
        (helper <*> (pure C_client))
        (progDesc $ "run a mock client " ++
                        "(here merely displays the session token)")


pi_sign :: ParserInfo Cmd
pi_sign =
    h_info
        (helper <*> (pure C_sign))
        (progDesc "sign the keystore")

pi_verify :: ParserInfo Cmd
pi_verify =
    h_info
        (helper <*> (pure C_verify))
        (progDesc "verify the keystore")

pi_list_hosts :: ParserInfo Cmd
pi_list_hosts =
    h_info
        (helper <*> (pure C_list_hosts))
        (progDesc "list the hosts")

pi_info_key :: ParserInfo Cmd
pi_info_key =
    h_info
        (helper <*> (C_info_key <$> optional p_key))
        (progDesc "get the gen on the keystore keys")

pi_info_section :: ParserInfo Cmd
pi_info_section =
    h_info
        (helper <*> (C_info_section <$> optional p_a_section))
        (progDesc "get the gen on the keystore sections")

pi_secret_script :: ParserInfo Cmd
pi_secret_script =
    h_info
        (helper <*> (pure C_secret_script))
        (progDesc $ "print a script to establish the all section passwords in the environment")

pi_public_script :: ParserInfo Cmd
pi_public_script =
    h_info
        (helper <*> (pure C_public_script))
        (progDesc "print a script to save the public signing key in a file")

pi_sample_script :: ParserInfo Cmd
pi_sample_script =
    h_info
        (helper <*> (pure C_sample_script))
        (progDesc "print a sample script to define keystore passwords in the environment")

pi_ks_args :: ParserInfo Cmd
pi_ks_args =
    h_info
        (helper <*> (C_ks <$> cliParser))
        (progDesc "run a ks command (see 'ks --help' for details)")

pi_pm_args :: PMConfig SectionID -> ParserInfo Cmd
pi_pm_args pmc =
    h_info
        (helper <*> (C_pm <$> pmCommandParser pmc))
        (progDesc "run a pm command (see 'pm --help' for details)")

p_shell_flg :: Parser Bool
p_shell_flg =
    switch
        (long    "shell"        <>
         help    "launch a shell with the deploy passwords setup in their environment variables")

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

p_a_section :: Parser SectionID
p_a_section =
    argument decode
        $  metavar "SECTION"
        <> help    "a section ID"

p_key :: Parser KeyID
p_key =
    nullOption
        $  long     "key"
        <> metavar  "KEY"
        <> reader (maybe (fail "key not recognised") return . decode)
        <> help     "a key ID"

p_out :: Parser FilePath
p_out =
    strOption
        $  long     "out"
        <> metavar  "FILE"
        <> help     "output file"

h_info :: Parser a -> InfoMod a -> ParserInfo a
h_info pr = info (helper <*> pr)
