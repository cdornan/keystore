{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Data.KeyStore.Packet
    ( encocdeEncryptionPacket
    , decocdeEncryptionPacket
    , encocdeSignaturePacket
    , decocdeSignaturePacket
    -- debugging
    , testBP
    ) where

import           Data.KeyStore.KS
import           Data.KeyStore.Types
import           Data.API.Types
import qualified Data.ByteString                as B
import qualified Data.ByteString.Char8          as BC
import qualified Data.ByteString.Lazy.Char8     as LBS
import           Data.ByteString.Lazy.Builder
import           Data.Word
import           Data.Bits
import           Control.Applicative
import           Control.Monad.RWS.Strict
import qualified Control.Monad.Error            as E


newtype MagicWord = MagicWord B.ByteString

encryption_magic_word, signature_magic_word :: MagicWord
encryption_magic_word = MagicWord $ B.pack [0x54,0xab,0xcd,0x00]
signature_magic_word  = MagicWord $ B.pack [0x54,0xab,0xcd,0x80]


encocdeEncryptionPacket :: Safeguard -> RSASecretBytes -> EncryptionPacket
encocdeEncryptionPacket sg rsb =
    EncryptionPacket $ Binary $
        encodePacket encryption_magic_word sg $ _Binary $ _RSASecretBytes rsb

decocdeEncryptionPacket :: EncryptionPacket -> E (Safeguard,RSASecretBytes)
decocdeEncryptionPacket ep =
 do (sg,bs) <- decodePacket encryption_magic_word $ _Binary $ _EncryptionPacket ep
    return (sg,RSASecretBytes $ Binary bs)

encocdeSignaturePacket :: Safeguard -> RSASignature -> SignaturePacket
encocdeSignaturePacket sg rs =
    SignaturePacket $ Binary $
        encodePacket signature_magic_word sg $ _Binary $ _RSASignature rs

decocdeSignaturePacket :: SignaturePacket -> E (Safeguard,RSASignature)
decocdeSignaturePacket sp =
 do (sg,bs) <- decodePacket signature_magic_word $ _Binary $ _SignaturePacket sp
    return (sg,RSASignature $ Binary bs)


encodePacket :: MagicWord -> Safeguard -> B.ByteString -> B.ByteString
encodePacket (MagicWord mw_bs) sg bs =
    B.append     mw_bs $
    encodeSafeguard sg $
                    bs

decodePacket :: MagicWord -> B.ByteString -> E (Safeguard,B.ByteString)
decodePacket (MagicWord mw_bs) bs = run bs $
 do mw_bs' <- splitBP (Octets $ B.length bs)
    case mw_bs==mw_bs' of
      True  -> return ()
      False -> errorBP "bad magic word"
    sg   <- decodeSafeguard
    b_bs <- remainingBP
    return (sg,b_bs)

encodeSafeguard :: Safeguard -> ShowB
encodeSafeguard = encodeLengthPacket . BC.pack . printSafeguard

decodeSafeguard :: BP Safeguard
decodeSafeguard = decodeLengthPacket $ e2bp . parseSafeguard . BC.unpack

encodeLengthPacket :: B.ByteString -> ShowB
encodeLengthPacket bs t_bs = B.concat [ln_bs,bs,t_bs]
  where
    ln_bs = LBS.toStrict $ toLazyByteString $ int64LE $ toEnum $ B.length bs

decodeLengthPacket :: (B.ByteString->BP a) -> BP a
decodeLengthPacket bp =
 do ln_bs <- splitBP 8
    let ln = fromIntegral $ foldr (.|.) 0 $ map (f ln_bs) [0..7]
    btwBP $ show ln
    bs <- splitBP $ Octets ln
    bp bs
  where
    f bs i = rotate w64 $ 8*i
      where
        w64 :: Word64
        w64 = fromIntegral $ B.index bs i

type ShowB = B.ByteString -> B.ByteString

newtype BP a = BP { _BP :: E.ErrorT Reason (RWS () [LogEntry] B.ByteString) a }
    deriving (Functor, Applicative, Monad, E.MonadError Reason)

e2bp :: E a -> BP a
e2bp = either throwBP return

run :: B.ByteString -> BP a -> E a
run bs bp =
    case (B.null bs',e) of
      (False,Right _) -> Left $ strMsg "bad packet format (residual bytes)"
      _               -> e
  where
    (e,bs',_) = runBP bs bp

runBP :: B.ByteString -> BP a -> (E a,B.ByteString,[LogEntry])
runBP s p = runRWS (E.runErrorT (_BP p)) () s

testBP :: B.ByteString -> BP a -> IO a
testBP bs p =
 do mapM_ lg les
    case B.null rbs of
      True  -> return ()
      False -> putStrLn $ show(B.length rbs) ++ " bytes remaining"
    case e of
      Left dg -> error $ show dg
      Right r -> return r
  where
    (e,rbs,les) = runBP bs p

    lg LogEntry{..} = putStrLn $ "log: " ++ le_message

btwBP :: String -> BP ()
btwBP msg = BP $ tell [LogEntry True msg]

errorBP :: String -> BP a
errorBP = throwBP . strMsg . ("packet decode error: " ++)

throwBP :: Reason -> BP a
throwBP = E.throwError

splitBP :: Octets -> BP B.ByteString
splitBP (Octets n) =
 do bs <- peek_remainingBP
    let (bs_h,bs_r) = B.splitAt n bs
    case n<=B.length bs of
      True  -> modifyBP (const bs_r) >> return bs_h
      False -> errorBP "not enough bytes"

remainingBP :: BP B.ByteString
remainingBP =
 do bs <- peek_remainingBP
    modifyBP $ const B.empty
    return bs

peek_remainingBP :: BP B.ByteString
peek_remainingBP = BP get

modifyBP :: (B.ByteString->B.ByteString) -> BP ()
modifyBP upd = BP $ modify upd
