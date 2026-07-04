{-# LANGUAGE OverloadedStrings #-}

module Crypto.PysrpCompatSpec
  ( spec
  )
where

import Crypto.SRP
  ( FromServer (..)
  , KnownAlgorithm (..)
  , PrimeGroup (..)
  , Results (..)
  , calcResults
  , fcPublicBytes
  , mkFromClient
  )
import qualified Data.ByteString as BS
import Numeric (readHex, showHex)
import Paths_crypto_srp (getDataFileName)
import System.Environment (getEnvironment)
import System.IO
  ( BufferMode (..)
  , hFlush
  , hGetLine
  , hPutStrLn
  , hSetBuffering
  )
import System.Process
  ( CreateProcess (..)
  , StdStream (..)
  , createProcess
  , proc
  , waitForProcess
  )
import Test.Hspec (Spec, describe, it, shouldBe)


encodeHex :: BS.ByteString -> String
encodeHex = concatMap padByte . BS.unpack
  where
    padByte b = case showHex b "" of
      [c] -> ['0', c]
      s -> s


decodeHex :: String -> BS.ByteString
decodeHex = BS.pack . go
  where
    go [] = []
    go (a : b : rest) = case readHex [a, b] of
      [(v, "")] -> v : go rest
      _ -> error $ "invalid hex pair: " ++ [a, b]
    go [_] = error "odd-length hex string"


spec :: Spec
spec = describe "pysrp compatibility" $
  it "completes a full SRP round-trip with pysrp as the server" $ do
    scriptPath <- getDataFileName "test/pysrp_server.py"
    baseEnv <- getEnvironment
    let creds = [("PYSRP_USER", "alice"), ("PYSRP_PASS", "hunter2")]
        processEnv = creds ++ baseEnv
        user = "alice"
        pass = "hunter2"

    fc <- mkFromClient user pass G2048

    (Just hin, Just hout, _, ph) <-
      createProcess
        (proc "python3" [scriptPath])
          { std_in = CreatePipe
          , std_out = CreatePipe
          , env = Just processEnv
          }
    hSetBuffering hin LineBuffering
    hSetBuffering hout LineBuffering

    hPutStrLn hin $ encodeHex $ fcPublicBytes fc
    hFlush hin

    line <- hGetLine hout
    let (saltBS, bBS) = case words line of
          [s, b] -> (decodeHex s, decodeHex b)
          _ -> error $ "unexpected pysrp_server.py output: " ++ line
        fs =
          FromServer
            { fsPublicBytes = bBS
            , fsSalt = saltBS
            , fsPrimeGroup = G2048
            , fsKnownAlgorithm = SHA256
            }

    case calcResults () fc fs of
      Nothing -> fail "calcResults returned Nothing (server public key was invalid)"
      Just results -> do
        hPutStrLn hin $ encodeHex $ rClientProof results
        hFlush hin

        m2Line <- hGetLine hout
        m2Line `shouldBe` encodeHex (rServerProof results)

        _ <- waitForProcess ph
        pure ()
