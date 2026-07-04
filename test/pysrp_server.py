#!/usr/bin/env python3
"""
pysrp compatibility server for crypto-srp tests.

Protocol (all values hex-encoded, one value per line):
  stdin:  A
  stdout: salt B
  stdin:  M1
  stdout: M2   (or FAIL if M1 did not verify)

Username and password are read from environment variables PYSRP_USER and PYSRP_PASS.
"""
import os
import sys
import srp

# Use RFC 5054 padding (PAD(g) for k, PAD(A)/PAD(B) for u) to match crypto-srp.
srp.rfc5054_enable()

user = os.environ["PYSRP_USER"]
password = os.environ["PYSRP_PASS"]

salt, verifier = srp.create_salted_verification_key(
    user, password, hash_alg=srp.SHA256, ng_type=srp.NG_2048
)

a_hex = sys.stdin.readline().strip()
A = bytes.fromhex(a_hex)

svr = srp.Verifier(user, salt, verifier, A, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
svr_salt, B = svr.get_challenge()

sys.stdout.write(svr_salt.hex() + " " + B.hex() + "\n")
sys.stdout.flush()

m1_hex = sys.stdin.readline().strip()
M1 = bytes.fromhex(m1_hex)

HAMK = svr.verify_session(M1)
if HAMK is None:
    sys.stdout.write("FAIL\n")
else:
    sys.stdout.write(HAMK.hex() + "\n")
sys.stdout.flush()
