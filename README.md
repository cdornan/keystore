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
      + *PKS*: the seret may be a RSA provate key with the public key stored
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

  * Perhaps apropriately, the keystore package has several layers. Most users
    will probably need only the top "batteries-included" layer:

      + `Data.KeyStore.Sections`: this provides a high-level model that allows
        a flexible hierarchical keystore to be set up relatively easily.
        See the 'deploy' examplefor details.
      + `Data.KeyStore.CLI` : This provides a stanalone program for inspecting
        and editing your keystores. It can also be embedded into your own
        deployment app. See the `deploy` example for details.
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
Will list the commands but they are no good to you because, apart from the
trivial ones (like `version`), they need a keystore to operate on.

The `deploy` example can get us going.

Generally the first step in setting up a keystore is to set up all of the
master passwords it will need for each of its sections in the environment
using your favourite random password generator. Your deployment app should
provide a template for this:

````bash
deploy sample-script
````
will in the current version (0.4.0.0) print this:

````bash
export KEY_pw_top=pw_top;
export KEY_pw_signing=pw_signing;
export KEY_pw_eu_admin=pw_eu_admin;
export KEY_pw_eu_deploy=pw_eu_deploy;
export KEY_pw_eu_staging=pw_eu_staging;
export KEY_pw_us_admin=pw_us_admin;
export KEY_pw_us_deploy=pw_us_deploy;
export KEY_pw_us_staging=pw_us_staging;
export KEY_pw_dev=pw_dev;
````
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
export KEY_pw_eu_deploy=pw_eu_deploy;
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
