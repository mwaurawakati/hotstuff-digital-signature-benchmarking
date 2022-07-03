from bls import *
from ecdsa import *
from eddsa import *
from schnorr import *
import time
from hashlib import sha256

# measure signing time
msg = "hello".encode('utf8')

bls_sk, bls_vk = bls_key_gen()
bls_sig = bls_sign(bls_sk, msg)
start_time = time.time()
for _ in range(100):
    bls_verify(bls_vk, msg, bls_sig)
print("BLS: --- %s seconds ---" % ((time.time() - start_time)/100))

ecdsa_sk, ecdsa_vk = ecdsa_key_gen()
ecdsa_sig = ecdsa_sign(ecdsa_sk, msg)
start_time = time.time()
for _ in range(100):
    ecdsa_verify(ecdsa_vk, msg, ecdsa_sig)
print("ECDSA: --- %s seconds ---" % ((time.time() - start_time)/100))

eddsa_sk, eddsa_vk = eddsa_key_gen()
eddsa_sig = eddsa_sign(eddsa_sk, msg)
start_time = time.time()
for _ in range(100):
    eddsa_verify(eddsa_vk, msg, eddsa_sig)
print("EdDSA: --- %s seconds ---" % ((time.time() - start_time)/100))

schnorr_sk, schnorr_vk = schnorr_key_gen()
schnorr_sig = schnorr_sign(schnorr_sk, msg)
start_time = time.time()
for _ in range(100):
    schnorr_verify(schnorr_vk, msg, schnorr_sig)
print("Schnorr: --- %s seconds ---" % ((time.time() - start_time)/100))
