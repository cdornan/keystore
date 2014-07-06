{-# LANGUAGE RecordWildCards            #-}

module Data.KeyStore.KS.Configuration where

import           Data.KeyStore.Types
import           Data.Monoid
import qualified Data.Map               as Map
import           Data.Maybe
import           Text.Regex


configurationSettings :: Configuration -> Settings
configurationSettings = _cfg_settings

trigger :: Name -> Configuration -> Settings -> E Settings
trigger nm cfg stgs0 =
    case checkSettingsCollisions stgs of
      []   -> Right stgs
      sids -> Left $ strMsg $ "settings collided in triggers: "
                                ++ nm_s ++ ": " ++ show(map _SettingID sids)
                                ++ "\n\n" ++ show (stgs0 : t_stgss)
  where
    stgs     = mconcat $ stgs0 : t_stgss

    t_stgss  = [ _trg_settings | Trigger{..}<-Map.elems $ _cfg_triggers cfg,
                                                            mtch _trg_pattern ]

    mtch pat = isJust $ matchRegex (_pat_regex pat) nm_s

    nm_s     = _name nm
