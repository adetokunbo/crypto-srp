{-# LANGUAGE NamedFieldPuns #-}
{-# OPTIONS_HADDOCK prune #-}

{- |
Module      : Crypto.SRP
Copyright   : (c) 2025 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Core types and functions for the client side of an SRP authentication sequence.

The typical flow:

1. Call 'mkFromClient' with the username, password and a 'PrimeGroup' to
   produce a 'FromClient' value and generate a random private ephemeral key.
2. Send 'fcPublicBytes' to the server; receive a 'FromServer' in reply.
3. Call 'calcResults' (supplying an 'XCalculator') to derive the shared
   session key and client\/server proofs.
4. Optionally call 'verifyServerProof' to confirm the server holds the same key.
-}
module Crypto.SRP
  ( -- * client-side inputs
    FromClient (..)
  , mkFromClient

    -- * server-side inputs
  , FromServer (..)

    -- ** choose how to calculate @\'x\''@
  , XCalculator (..)

    -- * shared key and proofs
  , Results (..)

    -- ** calculate and verify using @Results@
  , calcResults
  , verifyServerProof

    -- * SRP Integer <=> ByteString interconversion
  , bytesOf
  , fromBytes

    -- * type aliases
  , Username
  , Password

    -- * re-exports
  , PrimeGroup (..)
  , KnownAlgorithm (..)
  , digestSize
  , hashText
  , hashMany
  , hash
  )
where

import Crypto.SRP.Hashing
  ( KnownAlgorithm (..)
  , calcClientX
  , calcK
  , calcXorHashnHashg
  , digestSize
  , hash
  , hashMany
  , hashText
  )
import Crypto.SRP.PrimeGroup
  ( PrimeGroup (..)
  , bytesOf
  , fromBytes
  , modExpPrime
  , padAs
  , primeMod
  , pubOf
  )
import Crypto.SRP.Random (gen256BitInteger)
import Data.ByteString (ByteString)
import Data.Text (Text)


-- | Identifies a user
type Username = Text


-- | A user's cleartext password
type Password = Text


-- | The shared secret key and proofs resulting from an SRP sequence
data Results = Results
  { rKey :: !ByteString
  , rClientProof :: !ByteString
  , rServerProof :: !ByteString
  }
  deriving (Eq)


-- | Data sent back to the client from the server after it starts the SRP sequence
data FromServer = FromServer
  { fsPublicBytes :: !ByteString
  , fsSalt :: !ByteString
  , fsPrimeGroup :: !PrimeGroup
  , fsKnownAlgorithm :: !KnownAlgorithm
  }
  deriving (Eq)


-- | Data needed at the client to begin an SRP sequence
data FromClient = FromClient
  { fcUser :: !Username
  -- ^ identifies the user
  , fcPassword :: !Password
  -- ^ the clear text password
  , fcPrivateNumber :: !Integer
  -- ^ a randomly generated session secret
  , fcPublicBytes :: !ByteString
  -- ^ the client's public ephemeral key @g^a mod N@
  }


{- | Build a @FromClient@, generating the public and private ephemeral values
required for the client-side of the authentication process.

The private ephemeral key is generated as a 256-bit random integer, which meets
the minimum key size required by
[RFC 5054 §2.6](https://datatracker.ietf.org/doc/html/rfc5054#section-2.6).
-}
mkFromClient :: Username -> Password -> PrimeGroup -> IO FromClient
mkFromClient fcUser fcPassword pg = do
  private <- gen256BitInteger
  let public = private `pubOf` pg
  pure
    FromClient
      { fcUser
      , fcPassword
      , fcPublicBytes = bytesOf (fromIntegral public)
      , fcPrivateNumber = private
      }


-- | Verify a server proof
verifyServerProof :: (XCalculator a) => a -> ByteString -> FromClient -> FromServer -> Bool
verifyServerProof selectX serverProof fc fs =
  case calcResults selectX fc fs of
    Nothing -> False
    Just results -> serverProof == rServerProof results


{- | Calculate the shared session key and proofs

  K = H(S) -- @S@ is the premaster secret, @K@ is the shared session key

  @M@ (clientProof) is calculated independently on the server and client and is
  sent from the client to the server. If this does not match the server's value
  the server aborts the authentication process.  The client calculates this as:

  M = H(H(N) XOR H(g) | H(U) | s | A | B | K)

  @AMK@ (serverProof) is also calculated on both the server and client, but it's
  sent by the server to the client after the server accepts the clientProof
  received from the client

  AMK = H(A | M | K)

  if the serverProof does not match what the client expects, it aborts

  The 'XCalculator' argument models the choice existing in the calculation of
  @x@, a hash depending on the user's password, on which @S@ in turn depends

  the calculation will abort if server public valid is invalid; in this case, the function
  returns Nothing
-}
calcResults :: (XCalculator a) => a -> FromClient -> FromServer -> Maybe Results
calcResults selectX fc fs =
  let FromServer {fsPublicBytes, fsSalt, fsPrimeGroup = pg, fsKnownAlgorithm = alg} = fs
      FromClient {fcUser, fcPublicBytes = publicBytes} = fc
      bigS = calcPremasterSecret selectX fc fs
      xorNG = calcXorHashnHashg alg pg
      hashedName = hashText alg fcUser
      mkResult s =
        let rKey = hash alg $ bytesOf (fromIntegral s)

            rClientProof = hashMany alg [xorNG, hashedName, fsSalt, publicBytes, fsPublicBytes, rKey]
            rServerProof = hashMany alg [publicBytes, rClientProof, rKey]
         in Results {rKey, rClientProof, rServerProof}
   in mkResult <$> bigS


{- | Enables choice in the calculation of @x@ by 'calcResults'.

  One step in calculating @S@, the shared secret is the calculation of @x@,
  which is a hash that depends on the user password.

  @x@ must depend on the password, and the SRP RFC specifies a hash calculation
  that includes both the user identity and the password.

  However, it is not strictly necessary for @x@ to depend on the user identity,
  and there are SRP server deployments that don't include the user name in @x@;
  instead only the password is used, using a KDF (key derivation function) to
  further protect it
-}
class XCalculator a where
  -- |  Calculates @x@, a hash that must depend on the user password
  calcX :: a -> FromClient -> FromServer -> ByteString


{- | Implements the version of the @x@ calculation detailed in the SRP RFC

@ x = H(s | H(I | ":" | P)) @

where @s@ is the salt from the server, @I@ is the user name, @P@ is the user
password and @H@ is the hash algorithm
-}
instance XCalculator () where
  calcX () fc fs =
    calcClientX (fcUser fc, fcPassword fc) (fsSalt fs) (fsKnownAlgorithm fs)


{-
The premaster secret is calculated by the client as follows:
    I, P = <read from user>
    N, g, s, B = <read from server>
    a = random()
    A = g^a % N
    u = H(PAD(A) | PAD(B))
    k = H(N | PAD(g))
    x = calcX(FromClient, FromServer)
    <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
      == ((B - (k * g^x)) % N) ^ (a + (u * x)) % N
      == (((B % N) - ((k * g^x) % N)) % N) ^ (a + (u *x)) % N

the calculation will abort if B % N is zero; in this case, the function returns
Nothing
-}
calcPremasterSecret :: (XCalculator a) => a -> FromClient -> FromServer -> Maybe Integer
calcPremasterSecret selectX fc fs =
  let
    FromServer {fsPublicBytes, fsPrimeGroup = pg, fsKnownAlgorithm = alg} = fs
    FromClient {fcPrivateNumber = private, fcPublicBytes = publicBytes} = fc
    x = fromBytes $ calcX selectX fc fs
    u = fromBytes $ hashMany alg [publicBytes `padAs` pg, fsPublicBytes `padAs` pg]
    power = private + (u * x)
    x' = x `pubOf` pg
    bigB = fromBytes fsPublicBytes
    shouldAbort = bigB `primeMod` pg == 0
    k = fromBytes $ calcK alg pg
    base = ((bigB `primeMod` pg) - ((k * x') `primeMod` pg)) `primeMod` pg
   in
    if shouldAbort then Nothing else Just $ modExpPrime base power pg
