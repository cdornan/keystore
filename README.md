keystore: storing secret things
===============================

Writing deployment scripts is a critical yet error-prone activity which we
would rather do in Haskell. One of the most difficult aspect of deployment
scripts is the management of credentials: they cannot be stored in the
VCS like almost everything else, but need to be organised and accessed
while under lock and key. This is the problem that keystore is trying to solve:
flexible, secure and well-typed deployment scripts.

  * This module is written purely in Hakell and all of the cryptographic packages
    it relies upon are written in Haskell.

  * It stores everything in a JSON format that has proven to be stable. We can can
    use [migrations](http://hackage.haskell.org/package/api-tools) > in future
    should the store need to be reorganized.

  * The underlying model is simple and flexible:

      + *Named keys*: every key has an name within the store that is associated
        with some secret data. If the secret data for that key is to be stored then
        it must identify another key in the store that will be used to encrypt the
        data. (Some keys -- the passwords -- will typically be auto-loaded from
        environment variables.)
      + *Functional model*: keys can be deleted and added again but the design
        encourages the retention of the history. The old keys remain available
        but deployment scripts will naturally select the latest version of a key.
        When a key is rotated this merely loads a new generation for the rotated
        key.
      + *Simple metadata*: oher information, such as the identity of the key
        with its originating system (e.g., the identifier of an AWS IAM key)
        and some arbitrary textual information (the 'comment') may be associated
        with a key and accessible without recourse to the key or password needed
        to access the secret information.
      + *PKS*: the seret may be a RSA private key with the public key stored
        separately in the cler.
      + *MFA*: a secret may be protected with multiple named keys, all of which
        will be needed to recover the secret text.
      + *Hashing*: all keys can be hashed with an appropriate PBKDF-2 function
        and the hashes stored in the clear. These hashes may be sued to verify
        passwords but also can be inserted directly into configuration files
        for deployment. Precise control of the PBKDF-2 hash paramers is
        avaiable.
      + *Hierarchical organization*: keys can be stored in different sections
        with each key being protected by a master key for that section. Sections
        can be configured to store the master keys of other sections thereby
        gaining acces to all of the keys in those sections and the keys they
        have access to.
      + *Systems integratio*: keys can automatically loaded from Environment
        variables. Typically a keystore session will start by settingb up an
        environment variable for the deployment section corresponding for
        the node that you need to deploy to. This will provide access to
        precisely the keys whose secrets you need to carry out the deployment
        and no more. It only needs access to the hashes of admin keys then they
        can be placed in separate higher-level `admin` sections. Provided care
        is taken preparing the environment you will not deploy to the wrong host
        (e.g., a live server rather than a staging server, or the wrong live
        server) because those keys will not be accessible.
      + *Configuration control*: the parameters controling the encryption and
        hashing functions can be set up independently in each section of the
        store, allowing for heavier hashing to be used on live servers and
        light hashing to be used on development and staging servers where
        authentication needs to be quick.
      + *Keystore integrity*: the keystore can be signed and every operation
        made to check that the keystore matches its signature (and the public
        signing key matches an independent copy on the client).
      + *External crypto operations*: keys in the keystore can be used to sign
        or encrypt external obejcts (provided they can be loaded into memory).

  * The keystore package has several layers. Most users will probably need
    only the top "batteries-included" layer:

      + `Data.KeyStore.Sections`: this provides a high-level model that allows
        a flexible hierarchical keystore to be set up relatively easily.
        See the 'deploy' examplefor details.
      + `Data.KeyStore.CLI` : This provides a stanalone program for inspecting
        and editing your keystores. It can also be embedded into your own
        deployment app. See the `deploy` example for details.
      + `Data.KeyStore.PasswordManager` provides a password manager which each
        user can use to setup their own local password store for holding the
        deployment passwords and session tokens used to autheticate the server.
      + `Data.KeyStore.IO`: this library provides general programatic access to
        a keystore through `IO` primitives. See the source code for the `Sections`
        for an example of this module in use.
      + `Data.KeyStore.KS`: this library provides general programatic access to
        a keystore through functional `KS` primitives. See the source code for
        the `IO` for an exteded example this system in action.
      + `Data.KeyStore.Types`: This provides access to keystores at the types
        level.


Launch Instructions
-------------------

Set yourself up with a ghc-7.6.3 or ghc-7.8.3 environment as appropriate.
````bash
cabal install keystore
````
In addition to the keystore package library, this will establish in you cabal
bin directory the `ks` and `deploy` binaries. `ks` is the generic programme
for inspecting and editing keystores.
````bash
ks --help
````
will list the commands but they are no good to you because, apart from the
trivial ones (like `version`), they need a keystore to operate on.

The `deploy` example can get us going.

Generally the first step in setting up a keystore is to set up all of the
master passwords it will need for each of its sections in the environment
using your favourite random password generator. Your deployment app could
provide a template for this:
````bash
deploy sample-script
````
will in the current version (0.5.1.0) print this:
````bash
export KEY_pw_top=secret-top;
export KEY_pw_signing=secret-signing;
export KEY_pw_eu_admin=secret-eu_admin;
export KEY_pw_eu_deploy=secret-eu_deploy;
export KEY_pw_eu_staging=secret-eu_staging;
export KEY_pw_us_admin=secret-us_admin;
export KEY_pw_us_deploy=secret-us_deploy;
export KEY_pw_us_staging=secret-us_staging;
export KEY_pw_dev=secret-dev;
export KEY_pw_session=secret-session;
````

(These passwords can be more conveniently managed by the password manager
described below, but we will describe that separately.)

Having created the keystore you may want to clear down these definitions in
which case it may be best to do this in a sub-shell.
````bash
bash
# in the sub-shell eval the script to set up the variables with
# just the sample values
eval $(deploy sample-script)
# now we create the keystore, setting up the sections with the above passwords,
# including the special 'signing' and 'top' sections
deploy intialise
# keystore is set up but has not been signed; any attempt to use it will
# result in an error (you can try skipping thisn step and see what happens)
deploy sign
# the keystore has no useful deployment keys, so we can rotate in the initial
# set by running the rotate script with no filter arguments; this example
# just loads some stadard data for each key but in a real system random
# keys would be generated or they would be laoded from a secure staging area,
# depending upon the type of key
deploy rotate
deploy sign
# the keystore is loaded: we can now list the keys
deploy ks list
# this uses the generic 'ks' embedded in the 'deploy' app. We can also use
# the 'ks' command directly.
ks --store deploy-keystore.json list
# but now we have to tell it where to find our test keystore.
# Note that every key has a 'T' listed immediately after the ':' indicating that
# the secret text for the key is accessible. This is because the passwords for
# all of the keys are still bound in the environment providing access to all
# of the keys. We can inspect one of them:
deploy ks show-secret eu_admin_super_api_001
With all of the passwords present this looks just like a flat keystore. Let's
clear down the passwords and exit the sub-shell.
exit
````
Now if we try to show the secret again
````bash
deploy ks show-secret eu_admin_super_api_001
````
We get an error message complaining that the secret is not present.

If we list the keystore now we see the 'T' flags indicating that the
secret text for a key is accessible have all disappeared.

````bash
deploy ks list
````

To deploy a host we specify the host we use the `deploy` subcommand, specifying
the host that we want to deploy to.
````bash
deploy deploy --help
````

We can list the hosts to see what is available:
````bash
deploy list-hosts
````

In this context a 'deployment' will just make up a configuration file populated
with all the identifiers, hashes and secret keys that we need. (A real deployment
app might upload the configuration file along with a package into a staging area
triggering a daemon to carry out the deployment.

Supposing we choose to deploy to `live_eu`.

````bash
deploy deploy live_eu
````
But this won't work -- the deployment app can see none of the passwords it needs
nad so reports an error on the first one it tries to load.

We need to set up the `live_eu` deployment password in our environment.
````bash
export KEY_pw_eu_deploy=secret-eu_deploy;
````

Now if we list the key store we can see that just the keys we need have the
'T' against then, including the keys in the `eu_deploy`, `eu_staging` and `dev`
sections, but none of the keys in the `us_*` sections or the two passwords in
the `eu_admin` sections. The secrets from those sections are not needed for a
deployment, merely the hahses. (You will see other keys starting with, for example,
`save_` and `pw_`: these are part of the devices to arrange the sections into
the intended hierarchy).

````bash
deploy deploy live_eu
````

This should now print out an apropriatly filled out JSON configuration file.


The Password Manager
--------------------

You can use the password manager to manage your deployment passwords and client
session tokens. While the keystore is a shared store with hierarchical access,
each user would maintain their own password store.

The `Data.KeyStore.PasswordManager` module provides the API for the password
manager which has been set up with the `deploy` example program.

Each user sets up and manages their own password store with the `deploy pm`
sub-commands (see `deploy pm --help`). To setup a store,

````bash
deploy pm setup
````

This will prompt you for a password and sets up an encrypted password store in
the location configured by `deploy` (`pwstore.dat` in the current directory).
The password is hashed to form a key which must be bound in the environment
in the designated environment variable (`DEPLOY_MASTER` in this case, but it
is configurable).

By default the `setup` command runs an interactive shell with `DEPLOY_MASTER`
setup so that your private encrypted store is accessible. Once you exit this
shell the key will no longer be bound in the environmant and the encrypted
store will be insaccessible. To access the store again, user the `login`
command, which will prompt for a password and launch another interactive
shell with the `DEPLOY_MASTER` setup with the requisite encryption key:

````bash
deploy pm setup
````

The password manager has been set up with a corresponding sample script for
loading the keystore.

````bash
deploy pm sample-load-script
````

The current version (0.5.1.0) displays this sample script:
````bash
deploy pm comment 'loaded by the sample script' ;
deploy pm load top          secret-top           # 'top key: accesses everything' ;
deploy pm load signing      secret-signing       # 'keystore signing key'       ;
deploy pm load eu_admin     secret-eu_admin      # 'eu admin keys'              ;
deploy pm load eu_deploy    secret-eu_deploy     # 'eu deploy keys'             ;
deploy pm load eu_staging   secret-eu_staging    # 'eu staging deployment keys' ;
deploy pm load us_admin     secret-us_admin      # 'us admin keys'              ;
deploy pm load us_deploy    secret-us_deploy     # 'us deploy keys'             ;
deploy pm load us_staging   secret-us_staging    # 'us staging keys'            ;
deploy pm load dev          secret-dev           # 'dev deployment keys'        ;
deploy pm load session      secret-session       # 'client sessions tokens'     ;
````
N.B. Everything after the '#' is treated as a comment and is ignored.

(N.B. The sample passwords have changed from earlier versions of this package,
so if you have a sample keystore created by an earlier version you will have to
adjust this script to use the old passwords to access the old keystore.)

Note that each password has been assigned a password manager name, corresponding
to the environment variable it is managing. (We could have used the environment
variable names like `KEY_pw_top` instead of `top` but the environment variable
names are typically unwieldy to ensure they dont colide with any other environment
variables being used by the system.)

The quickest way to get going is probably this:
````bash
deploy pm sample-load-script | bash
````

Now you can try a deployment:
````bash
deploy deploy dev
````

This works without the need to bind `KEY_pw_dev` in the environment: before
loading the keystore the deployment software calls out to the password manager
to collect the passwords it needs. The password manager uses the `DEPLOY_MASTER`
key bound in the environment to decrypt the password store and bind the
individual passwords into the environment for the deployment scripts to pick up.
(Because this is all done in a sub-process they will all be discarded once the
process that executed the `deploy` command has completed.)


Priming Passwords
-----------------

This can all become too convenient! It is easy to imagine logging into the
password manager to test a development server and accidentally deploying
a production server. The help protect against such accidents the password
manager can be told that certain passwords are to be considered special and
are not to be loaded into the environment by default --
they will need to be primed for use.

The following will not work by itself, for example:
````bash
deploy deploy live_eu
````

Of course, you could set the export `KEY_pw_eu_deploy` manually as above, but
you could also tell the password manager that you want to use it before issuing
the deploy command.
````bash
deploy pm prime eu_deploy
deploy deploy live_eu
````

Sometimes you may wish to prime all of the passwords -- to rotate them all, for
example:
````bash
deploy pm prime-all
deploy rotate
deploy sign
````

If you change your mind you can also un-prime them:
````bash
deploy pm prime-all -u
````


Inspecting Passwords
--------------------

The following commands are available to inspect the state of session and the
store.

````bash
deploy pm status
deploy pm passwords
deploy pm info top
````

The `status` command gives the status of the login session; the `passwords`
command lists all of the passwords (note the `-`s in the second column for
one-shot passwords that need priming, which turn into '+'s on priming); the
`info` command provides information on an individual passwords, including
textual notes.


Sessions
--------

One of the motivation for the password manager was to manage sessions tokens
generated by the server for the client to authenticate with. The `session`
password was created for this purpose. The only way that session passwords
differ from ordinary passwords (apart from the fact thet they will be
used by a server cleint rather than deployment scripts) is that
the session passwords can each store multiple tokens, and these tokens get
parsed to extract session names. Each client must provide the parsers as
part of the password manager configuration, and the `deploy` session parsers
assume that everything before the first `:` in the token identifies the
session.

The sample script loaded a single session
````bash
deploy pm load session      secret-session
````

As there is no `:` the whole token is assumed to name the session. The sessions
can be listed with the `sessions` command:
````bash
deploy pm sessions
````
which should produce something like this:
````
secret-session     2014-09-08 19:50 [ACTIVE]
````

If you load another token, with a different name then that session will be added
and selected as the current session, but the original session gets stacked.
````bash
deploy pm load master:very-secret
````

If we look at the sessions,
````bash
deploy pm sessions
````
we see two, with the new `master` session selected:
````
master           - 2014-09-08 20:55 [ACTIVE]
secret-session     2014-09-08 19:50
````

We can try our sample client:
````bash
deploy client
````
which produces
````
session-token=>NONE
````

The problem is that the token parser has decided to marke this session as
a one-shot password that needs to be primed each time it is used. The `-` above
was indicating this.

We can try our sample client:
````bash
deploy prime session
deploy client
````
which produces
````
session-token=>master:very-secret
````
Better.


Importing Password Stores
-------------------------

You can also import the contents of one password store into another. To load
the above example passwords from an example password store:

````bash
deploy pm import examples/deploy/example-pwstore.dat deploy
````

The imported store's comment, passwords and sessions will be inserted into
current store, replace any like-named passwords and sessions and leaving the
rest.  It can be used to securely circulate a password set and to change the
password of a store (by create a new store under the new password, importing
the old passwords and deleting the old store).


Dynamic Passwords
-----------------

In addition to setting up a static list of passwords you may need to
manage a dynamic class of passwords, where you do not know the number
of passwords or their names. To do this, specify a '+' in front of the
password name when loading it. For example,

````
deploy pm load +john secret-of-john
````

These passwords will get loaded into the environment when the passwords
get collected according to the password store's configuration. The name
of the pasword can be the same as any of your named static passwords
without confusion. It can be listed with `passwords-plus` inspected
with `info` and deleted with `delete`.
