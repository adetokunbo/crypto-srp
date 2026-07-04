{-# OPTIONS_HADDOCK prune #-}

{- |
Module      : Crypto.SRP.Random
Copyright   : (c) 2025 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides cryptographically secure random byte generation used to produce the
private ephemeral key in the SRP handshake. Uses hardware entropy when
available, falling back to the OS entropy source via @System.Entropy@.
-}
module Crypto.SRP.Random
  ( genNSecureBytes
  , gen256BitInteger
  )
where

import Crypto.SRP.PrimeGroup (fromBytes)
import Data.ByteString (ByteString)
import System.Entropy (getEntropy, getHardwareEntropy)


-- | Get a specific number of bytes of cryptographically secure random data
genNSecureBytes :: Int -> IO ByteString
genNSecureBytes n = maybe (getEntropy n) pure =<< getHardwareEntropy n


-- | Generate a cryptographically secure random 256-bit @Integer@
gen256BitInteger :: IO Integer
gen256BitInteger = fromBytes <$> genNSecureBytes 32
