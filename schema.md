###KeyStore



JSON Type : **record object** [Haskell prefix is `ks`] KeyStore

Field  | Type          | Default
------ | ------------- | -------
config | Configuration | 
keymap | KeyMap        | 


###Configuration



JSON Type : **record object** [Haskell prefix is `cfg`] Configuration

Field    | Type       | Default
-------- | ---------- | -------
settings | Settings   | 
triggers | TriggerMap | 


###TriggerMap



JSON Type : **record object** [Haskell prefix is `tmp`] TriggerMap

Field | Type      | Default
----- | --------- | -------
map   | [Trigger] | 


###Trigger



JSON Type : **record object** [Haskell prefix is `trg`] Trigger

Field    | Type      | Default
-------- | --------- | -------
id       | TriggerID | 
pattern  | Pattern   | 
settings | Settings  | 


###Settings



JSON Type : **record object** [Haskell prefix is `stgs`] Settings

Field | Type | Default
----- | ---- | -------
json  | json | 


###TextJsonAssoc



JSON Type : **record object** [Haskell prefix is `tja`] TextJsonAssoc

Field | Type      | Default
----- | --------- | -------
id    | SettingID | 
key   | json      | 


###KeyMap



JSON Type : **record object** [Haskell prefix is `kmp`] KeyMap

Field | Type           | Default
----- | -------------- | -------
map   | [NameKeyAssoc] | 


###NameKeyAssoc



JSON Type : **record object** [Haskell prefix is `nka`] NameKeyAssoc

Field | Type | Default
----- | ---- | -------
name  | Name | 
key   | Key  | 


###Key



JSON Type : **record object** [Haskell prefix is `key`] Key

Field         | Type            | Default
------------- | --------------- | -------
name          | Name            | 
comment       | Comment         | 
identity      | Identity        | 
is_binary     | boolean         | 
env_var       | ? EnvVar        | 
hash          | ? Hash          | 
public        | ? PublicKey     | 
secret_copies | EncrypedCopyMap | 
clear_text    | ? ClearText     | 
clear_private | ? PrivateKey    | 
created_at    | utc             | 


###Hash



JSON Type : **record object** [Haskell prefix is `hash`] Hash

Field       | Type            | Default
----------- | --------------- | -------
description | HashDescription | 
hash        | HashData        | 


###HashDescription



JSON Type : **record object** [Haskell prefix is `hashd`] HashDescription

Field        | Type       | Default
------------ | ---------- | -------
comment      | Comment    | 
prf          | HashPRF    | 
iterations   | Iterations | 
width_octets | Octets     | 
salt_octets  | Octets     | 
salt         | Salt       | 


###EncrypedCopyMap



JSON Type : **record object** [Haskell prefix is `ecm`] EncrypedCopyMap

Field | Type           | Default
----- | -------------- | -------
map   | [EncrypedCopy] | 


###EncrypedCopy



JSON Type : **record object** [Haskell prefix is `ec`] EncrypedCopy

Field       | Type             | Default
----------- | ---------------- | -------
safeguard   | Safeguard        | 
cipher      | Cipher           | 
prf         | HashPRF          | 
iterations  | Iterations       | 
salt        | Salt             | 
secret_data | EncrypedCopyData | 


###Safeguard



JSON Type : **record object** [Haskell prefix is `sg`] Safeguard

Field | Type   | Default
----- | ------ | -------
names | [Name] | 


###EncrypedCopyData



JSON Type : **union object** [Haskell prefix is `ecd`] EncrypedCopyData

Alternative | Type
----------- | -------------
_rsa_       | RSASecretData
_aes_       | AESSecretData
_clear_     | ClearText
_no_data_   | Void


###RSASecretData



JSON Type : **record object** [Haskell prefix is `rsd`] RSASecretData

Field           | Type            | Default
--------------- | --------------- | -------
encrypted_key   | RSAEncryptedKey | 
aes_secret_data | AESSecretData   | 


###AESSecretData



JSON Type : **record object** [Haskell prefix is `asd`] AESSecretData

Field       | Type       | Default
----------- | ---------- | -------
iv          | IV         | 
secret_data | SecretData | 


###PublicKey



JSON Type : **record object** [Haskell prefix is `puk`] PublicKey

Field | Type    | Default
----- | ------- | -------
size  | integer | 
n     | Integer | 
e     | Integer | 


###PrivateKey



JSON Type : **record object** [Haskell prefix is `prk`] PrivateKey

Field | Type      | Default
----- | --------- | -------
pub   | PublicKey | 
d     | Integer   | 
p     | Integer   | 
q     | Integer   | 
dP    | Integer   | 
dQ    | Integer   | 
qinv  | Integer   | 


###Cipher



JSON Type : **string enumeration** [Haskell prefix is `cph`] Cipher

Enumeration | Comment
------ | -------
aes128 | 
aes192 | 
aes256 | 


###HashPRF



JSON Type : **string enumeration** [Haskell prefix is `prf`] HashPRF

Enumeration | Comment
------ | -------
sha1   | 
sha256 | 
sha512 | 


###EncryptionKey



JSON Type : **union object** [Haskell prefix is `ek`] EncryptionKey

Alternative | Type
----------- | ----------
_public_    | PublicKey
_private_   | PrivateKey
_symmetric_ | AESKey
_none_      | Void


###FragmentID



JSON Type : **string** [Haskell prefix is `fid`] FragmentID



###Pattern



JSON Type : **string** [Haskell prefix is `pat`] Pattern



###Iterations



JSON Type : **integer** [Haskell prefix is `its`] Iterations



###Octets



JSON Type : **integer** [Haskell prefix is `octs`] Octets



###Name



JSON Type : **string** [Haskell prefix is `nm`] Name



###Identity



JSON Type : **string** [Haskell prefix is `idn`] Identity



###SettingID



JSON Type : **string** [Haskell prefix is `sid`] SettingID



###TriggerID



JSON Type : **string** [Haskell prefix is `tid`] TriggerID



###Comment



JSON Type : **string** [Haskell prefix is `cmt`] Comment



###EnvVar



JSON Type : **string** [Haskell prefix is `ev`] EnvVar



###ClearText



JSON Type : **base64 string** [Haskell prefix is `ct`] ClearText



###Salt



JSON Type : **base64 string** [Haskell prefix is `slt`] Salt



###IV



JSON Type : **base64 string** [Haskell prefix is `iv`] IV



###HashData



JSON Type : **base64 string** [Haskell prefix is `hd`] HashData



###AESKey



JSON Type : **base64 string** [Haskell prefix is `aek`] AESKey



###SecretData



JSON Type : **base64 string** [Haskell prefix is `sd`] SecretData



###RSAEncryptedKey



JSON Type : **base64 string** [Haskell prefix is `rek`] RSAEncryptedKey



###RSASecretBytes



JSON Type : **base64 string** [Haskell prefix is `rsb`] RSASecretBytes



###RSASignature



JSON Type : **base64 string** [Haskell prefix is `rsg`] RSASignature



###EncryptionPacket



JSON Type : **base64 string** [Haskell prefix is `ep`] EncryptionPacket



###SignaturePacket



JSON Type : **base64 string** [Haskell prefix is `sp`] SignaturePacket



###Void



JSON Type : **integer** [Haskell prefix is `void`] Void



