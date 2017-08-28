{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE RecordWildCards            #-}

module Deploy.Deploy
    ( deploy
    ) where

import           Deploy.HostSectionKey
import           Data.KeyStore
import qualified Data.ByteString.Lazy.Char8     as LBS
import qualified Data.Text                    as T
import qualified Data.Aeson                   as A
import qualified Data.HashMap.Strict          as HM


deploy :: IC -> HostID -> IO LBS.ByteString
deploy ic h = A.encode . A.Object . HM.fromList <$> mapM (extract ic h)
                    [ k | k<-[minBound..maxBound],
                                  maybe True ($ h) $ keyIsHostIndexed k ]

extract :: IC -> HostID -> KeyID -> IO (T.Text,A.Value)
extract ic h k = mk <$> locate ic h k
  where
    mk key = (T.pack $ encode k,gen key)

    gen key =
      case k of
        K_admin_init_pw -> hash       k key
        K_super_api     -> hash       k key
        K_api           -> hash       k key
        K_cloudfront    -> clear_text k key
        K_s3            -> clear_text k key
        K_mail          -> clear_text k key
        K_logger        -> clear_text k key
        K_ssl           -> clear_text k key

hash :: KeyID -> Key -> A.Value
hash k Key{..} = chk $ A.Object $ HM.fromList
    [ (,) "name"     $ A.toJSON _key_name
    , (,) "identity" $ A.toJSON _key_identity
    , (,) "comment"  $ A.toJSON _key_comment
    , (,) "hash"     $ A.toJSON _key_hash
    ]
  where
    chk r = maybe oops (const r) $ _key_hash

    oops  = error $ encode k ++ ": hash not present"

clear_text :: KeyID -> Key -> A.Value
clear_text k Key{..} = chk $ A.Object $ HM.fromList
    [ (,) "name"       $ A.toJSON _key_name
    , (,) "identity"   $ A.toJSON _key_identity
    , (,) "comment"    $ A.toJSON _key_comment
    , (,) "clear_text" $ A.toJSON _key_clear_text
    ]
  where
    chk r = maybe oops (const r) $ _key_clear_text

    oops  = error $ encode k ++ ": secret not loaded"

locate :: IC -> HostID -> KeyID -> IO Key
locate ic h k = retrieve ic h k >>= \ei -> check ei >>= tst
  where
    check ei = return $ either oops id ei
      where
        oops RDG_key_not_reachable = error $ encode k ++ ": key not available from this section"
        oops RDG_no_such_host_key  = error $ encode k ++ ": host-indexed key not available"

    tst []      = error $ encode k ++ ": key not present in the this section"
    tst (key:_) = return key
