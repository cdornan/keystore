{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE QuasiQuotes                #-}

module Data.KeyStore.Types.UTC (UTC(..)) where

import           Data.Aeson
import           Data.API.JSON
import           Data.Time
import           Text.RE.Replace
import           Text.RE.TDFA.String


-- | package time has some variation in the formatting of second fractions
-- in %Q (http://hackage.haskell.org/package/time-1.8.0.2/changelog) so we
-- we will standardise on ".xxx"
newtype UTC = UTC { _UTC :: UTCTime }
  deriving (Eq,Show)


instance ToJSON UTC where
  toJSON = toJSON . formatUTC

instance FromJSON UTC where
  parseJSON = fmap UTC . parseJSON

instance FromJSONWithErrs UTC where
  parseJSONWithErrs = fmap UTC . parseJSONWithErrs


formatUTC :: UTC -> String
formatUTC (UTC u) = cleanup $ formatTime defaultTimeLocale fmt u
  where
    fmt = iso8601DateFormat $ Just "%H:%M:%S%QZ"

cleanup :: String -> String
cleanup s = case (captureTextMaybe [cp|u|] mtch,captureTextMaybe [cp|q|] mtch) of
    (Just u,Nothing) -> u ++ ".000Z"
    (Just u,Just q ) -> u ++ "." ++ rjust q ++ "Z"
    _ -> s
  where
    mtch = s ?=~ [re|^${u}([T0-9:-]+)(.${q}([0-9]*))?Z$|]

    rjust ds = take 3 $ ds ++ "000"
