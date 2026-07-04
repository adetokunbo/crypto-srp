{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_HADDOCK prune #-}

{- |
Module      : Crypto.SRP.PrimeGroup
Copyright   : (c) 2025 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'PrimeGroup' type representing the standard SRP prime groups
(1024–8192 bits) and the group-arithmetic operations used during the SRP
handshake: public key generation ('pubOf'), modular exponentiation
('modExpPrime'), and @'ByteString'@ encoding helpers.
-}
module Crypto.SRP.PrimeGroup
  ( -- * the PrimeGroups
    PrimeGroup (..)
  , generatorFor
  , safePrimeFor
  , asByteString
  , hexLength
  , byteLength
  , pubOf
  , padAs
  , primeMod
  , modExpPrime

    -- * SRP Integer \<=> ByteString interconversion
  , bytesOf
  , fromBytes
  )
where

import Crypto.SRP.Constants
  ( fromHexBS
  , n1024Bits
  , n1536Bits
  , n2048Bits
  , n3072Bits
  , n4096Bits
  , n6144Bits
  , n8192Bits
  )
import Data.Bits (Bits (shiftR, testBit, (.&.)))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)
import Numeric.Natural (Natural)


-- | Represents the primeGroups used in SRP computations
data PrimeGroup
  = G1024
  | G1536
  | G2048
  | G3072
  | G4096
  | G6144
  | G8192
  deriving (Eq, Show)


-- | The generator for 'PrimeGroup'
generatorFor :: PrimeGroup -> Word8
generatorFor G1024 = 0x2
generatorFor G1536 = 0x2
generatorFor G2048 = 0x2
generatorFor G3072 = 0x5
generatorFor G4096 = 0x5
generatorFor G6144 = 0x5
generatorFor G8192 = 0x19


-- | The safe prime for 'PrimeGroup'
safePrimeFor :: PrimeGroup -> Integer
safePrimeFor G1024 = p1024
safePrimeFor G1536 = p1536
safePrimeFor G2048 = p2048
safePrimeFor G3072 = p3072
safePrimeFor G4096 = p4096
safePrimeFor G6144 = p6144
safePrimeFor G8192 = p8192


p1024, p1536, p2048, p3072, p4096, p6144, p8192 :: Integer
p1024 = fromHexBS n1024Bits
p1536 = fromHexBS n1536Bits
p2048 = fromHexBS n2048Bits
p3072 = fromHexBS n3072Bits
p4096 = fromHexBS n4096Bits
p6144 = fromHexBS n6144Bits
p8192 = fromHexBS n8192Bits


-- | A ByteString representing the safe prime in hexadecimal
asByteString :: PrimeGroup -> ByteString
asByteString G1024 = n1024Bits
asByteString G1536 = n1536Bits
asByteString G2048 = n2048Bits
asByteString G3072 = n3072Bits
asByteString G4096 = n4096Bits
asByteString G6144 = n6144Bits
asByteString G8192 = n8192Bits


-- | The number of hex characters in the representation of the safe prime
hexLength :: PrimeGroup -> Int
hexLength = BS.length . asByteString


-- | The number of bytes in the binary encoding of the safe prime
byteLength :: PrimeGroup -> Int
byteLength = (`div` 2) . hexLength


-- | Encode a @Natural@ number as a @ByteString@
bytesOf :: Natural -> ByteString
bytesOf 0 = BS.pack [0]
bytesOf n = BS.pack $ reverse (bytes n)
  where
    bytes 0 = []
    bytes x = fromIntegral (x .&. 0xFF) : bytes (shiftR x 8)


-- | Obtain an @Integer@ from its @ByteString@ encoding
fromBytes :: ByteString -> Integer
fromBytes = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0


-- | Reduce an @Integer@ modulo the safe prime of a 'PrimeGroup'
primeMod :: Integer -> PrimeGroup -> Integer
primeMod num pg =
  let prime = safePrimeFor pg
   in num `mod` prime


{- | Pad a 'ByteString' to the binary byte length of the safe prime of a
'PrimeGroup', prepending zero bytes as needed
-}
padAs :: ByteString -> PrimeGroup -> ByteString
padAs bs pg =
  let padLength = byteLength pg - BS.length bs
   in BS.replicate padLength 0 <> bs


{- | Generate the public version of a private ephemeral key

the private version of the key is expected to be randomly generated value of
64 bits
-}
pubOf :: Integer -> PrimeGroup -> Integer
pubOf priv pg = modExpPrime (fromIntegral (generatorFor pg)) priv pg


{- | Perform exponetiation modulus the large number in a 'PrimeGroup'

Example

  > modExpPrime base power G2048
-}
modExpPrime :: Integer -> Integer -> PrimeGroup -> Integer
modExpPrime base power pg = modExp base power (safePrimeFor pg)


modExp :: Integer -> Integer -> Integer -> Integer
modExp _base 0 _m = 1
modExp base expn m = t * modExp baseSquared (shiftR expn 1) m `mod` m
  where
    !baseSquared = (base * base) `mod` m
    !t = if testBit expn 0 then base `mod` m else 1
