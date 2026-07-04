{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.SRPSpec
  ( spec
  )
where

import Crypto.SRP
  ( FromClient (..)
  , FromServer (..)
  , KnownAlgorithm (..)
  , Results (..)
  , bytesOf
  , calcResults
  , digestSize
  , fromBytes
  , hash
  , verifyServerProof
  )
import Crypto.SRP.Constants
  ( n1024Bits
  , n1536Bits
  , n2048Bits
  , n3072Bits
  , n4096Bits
  , n6144Bits
  , n8192Bits
  )
import Crypto.SRP.PrimeGroup
  ( PrimeGroup (..)
  , byteLength
  , hexLength
  , padAs
  , safePrimeFor
  )
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char (ord)
import Data.Word (Word8)
import Fmt (build, fmt, hexF, (+|), (|+))
import Numeric (readHex)
import Numeric.Natural (Natural)
import Test.Hspec (Spec, context, describe, expectationFailure, it, shouldBe)
import Test.QuickCheck
  ( Property
  , chooseInteger
  , forAll
  )


spec :: Spec
spec = describe "module Crypto.SRP.Constants" $ do
  largeNumberSpec
  viaBytesSpec
  primeGroupSpec
  hashingSpec
  rfc5054Spec


viaBytes :: Natural -> Integer
viaBytes = fromBytes . bytesOf


max64Bit :: Integer
max64Bit = (2 ^ (63 :: Int)) - 1


prop_roundtripViaBytes :: Property
prop_roundtripViaBytes = forAll (chooseInteger (0, max64Bit)) $ \anInteger ->
  viaBytes (fromIntegral anInteger) == anInteger


viaBytesSpec :: Spec
viaBytesSpec = describe "roundtrip bytesOf then fromBytes" $ do
  context "for any 64-bit integer" $ do
    it "should succeed" prop_roundtripViaBytes


largeNumberSpec :: Spec
largeNumberSpec = describe "the fixed large numbers" $ do
  oneNumberSpec n1024Bits 1024
  oneNumberSpec n1536Bits 1536
  oneNumberSpec n2048Bits 2048
  oneNumberSpec n3072Bits 3072
  oneNumberSpec n4096Bits 4096
  oneNumberSpec n6144Bits 6144
  oneNumberSpec n8192Bits 8192


oneNumberSpec :: ByteString -> Int -> Spec
oneNumberSpec b bitSize = do
  context ("the ByteString representing the " +| bitSize |+ " bit number") $ do
    context "each byte" $ do
      it "should be a valid hexadecimal value" $ isAllHex b
    it "should roundtrip with its integer value" $ fromHexBS b == fromHexBS (bsShow (fromHexBS b))
    context "hexLength" $ do
      it "should be consistent with the number of bits" $ BS.length b == bitSize `div` 4


hashingSpec :: Spec
hashingSpec = describe "module Crypto.SRP.Hashing" $ do
  context "digestSize" $ do
    it "SHA1   is 20 bytes" $ digestSize SHA1 == 20
    it "SHA256 is 32 bytes" $ digestSize SHA256 == 32
    it "SHA384 is 48 bytes" $ digestSize SHA384 == 48
    it "SHA512 is 64 bytes" $ digestSize SHA512 == 64
  context "hash output length" $ do
    it "SHA1   produces digestSize bytes" $ BS.length (hash SHA1 "x") == 20
    it "SHA256 produces digestSize bytes" $ BS.length (hash SHA256 "x") == 32
    it "SHA384 produces digestSize bytes" $ BS.length (hash SHA384 "x") == 48
    it "SHA512 produces digestSize bytes" $ BS.length (hash SHA512 "x") == 64


-- RFC 5054 Appendix B test vectors (G1024 / SHA1).
-- Private ephemeral values a and b are fixed so the exchange is deterministic.
rfc5054Spec :: Spec
rfc5054Spec = describe "RFC 5054 Appendix B" $ do
  let salt = hexBS "BEB25379D1A8581EB5A727673A2441EE"
      aPriv = fromHexBS "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393"
      aPub =
        hexBS
          "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b"
      bPub =
        hexBS
          "bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58"
      fc =
        FromClient
          { fcUser = "alice"
          , fcPassword = "password123"
          , fcPrivateNumber = aPriv
          , fcPublicBytes = aPub
          }
      fs =
        FromServer
          { fsPublicBytes = bPub
          , fsSalt = salt
          , fsPrimeGroup = G1024
          , fsKnownAlgorithm = SHA1
          }
      expectedK = hexBS "017eefa1cefc5c2e626e21598987f31e0f1b11bb"
      expectedM1 = hexBS "62c71b289cb22a034b405667e1541202ce5d8e03"
      expectedM2 = hexBS "b475d7f2d75ce9537748005483e5d326048b59e9"

  it "calcResults produces the correct session key and proofs" $
    case calcResults () fc fs of
      Nothing -> expectationFailure "calcResults returned Nothing"
      Just results -> do
        rKey results `shouldBe` expectedK
        rClientProof results `shouldBe` expectedM1
        rServerProof results `shouldBe` expectedM2

  it "verifyServerProof returns True for the correct M2" $
    verifyServerProof () expectedM2 fc fs `shouldBe` True

  it "verifyServerProof returns False for a wrong M2" $
    verifyServerProof () (BS.replicate 20 0) fc fs `shouldBe` False

  it "calcResults returns Nothing when B is a multiple of N" $
    let fsInvalid = fs {fsPublicBytes = bytesOf (fromIntegral (safePrimeFor G1024))}
     in case calcResults () fc fsInvalid of
          Nothing -> pure ()
          Just _ -> expectationFailure "expected Nothing for B ≡ 0 (mod N)"


fromHexBS :: ByteString -> Integer
fromHexBS = BS.foldl' (\acc d -> acc * 16 + hexCharToInt d) 0


hexCharToInt :: Word8 -> Integer
hexCharToInt w =
  let to0 = w - ordAlt '0'
      toa = w - ordAlt 'a'
      toA = w - ordAlt 'A'
   in if
        | to0 < 10 -> fromIntegral to0
        | toa < 6 -> fromIntegral toa + 10
        | toA < 6 -> fromIntegral toA + 10
        | otherwise -> error $ "fromHexBS: invalid hex byte " ++ show w


hexBS :: String -> ByteString
hexBS = BS.pack . go
  where
    go [] = []
    go (a : b : rest) = case readHex [a, b] of
      [(v, "")] -> v : go rest
      _ -> error $ "hexBS: invalid pair: " ++ [a, b]
    go [_] = error "hexBS: odd-length string"


isHexChar :: Word8 -> Bool
isHexChar w = w - ordAlt '0' < 10 || w - ordAlt 'A' < 6 || w - ordAlt 'a' < 6


ordAlt :: Char -> Word8
ordAlt = fromIntegral . ord


isAllHex :: ByteString -> Bool
isAllHex b =
  let
    checkWord _ignored False = False
    checkWord nextChar True = isHexChar nextChar
   in
    BS.foldr checkWord True b


bsShow :: Integer -> ByteString
bsShow = fmt . build . hexF


primeGroupSpec :: Spec
primeGroupSpec = describe "module Crypto.SRP.PrimeGroup" $ do
  it "byteLength is hexLength `div` 2" $
    byteLength G2048 == hexLength G2048 `div` 2
  it "padAs pads a short ByteString to the binary byte length of N" $
    BS.length (BS.empty `padAs` G2048) == byteLength G2048
