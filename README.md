# crypto-srp

`crypto-srp` provides primitives for the
[Secure Remote Password (SRP)](https://datatracker.ietf.org/doc/html/rfc5054) protocol.

It includes:

- `Crypto.SRP` — core SRP computation: public key exchange, premaster secret derivation,
  client/server proof generation and verification
- `Crypto.SRP.Constants` — standard large prime groups (1024–8192 bits) from
  [RFC 5054 Appendix A](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
- `Crypto.SRP.Hashing` — hash algorithm abstraction (`SHA1`, `SHA256`, `SHA384`, `SHA512`)
  used throughout the SRP calculation
- `Crypto.SRP.PrimeGroup` — prime group representation and byte-string encoding
- `Crypto.SRP.Random` — cryptographically random private key generation

