from bls import *
from ecdsa import *
from eddsa import *
from schnorr import *
import time
from hashlib import sha256

print("Strating to measure the time it takes to verify a signature...")
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

print("\n ------------------------------ \n")

NUMBER_OF_SIGS = 100
print(f"Strating to measure the time it takes to verify {NUMBER_OF_SIGS} signatures...")

msgs = [("hello"+str(i)).encode("utf8") for i in range(NUMBER_OF_SIGS)]

bls_keys = [bls_key_gen() for _ in range(NUMBER_OF_SIGS)]
bls_sks = [i[0] for i in bls_keys]
bls_vks = [i[1] for i in bls_keys]
bls_sigs = [bls_sign(bls_sks[i], msgs[i]) for i in range(NUMBER_OF_SIGS)]
bls_aggregated_sig = bls_aggregate(bls_sigs)
start_time = time.time()
bls_verify_aggregate(bls_aggregated_sig, bls_vks, msgs)
print("BLS: --- %s seconds ---" % (time.time() - start_time))

ecdsa_keys = [ecdsa_key_gen() for _ in range(NUMBER_OF_SIGS)]
ecdsa_sks = [i[0] for i in ecdsa_keys]
ecdsa_vks = [i[1] for i in ecdsa_keys]
ecdsa_sigs = [ecdsa_sign(ecdsa_sks[i], msgs[i]) for i in range(NUMBER_OF_SIGS)]
start_time = time.time()
for i in range(NUMBER_OF_SIGS):
    ecdsa_verify(ecdsa_vks[i], msgs[i], ecdsa_sigs[i])
print("ECDSA: --- %s seconds ---" % (time.time() - start_time))

eddsa_keys = [eddsa_key_gen() for _ in range(NUMBER_OF_SIGS)]
eddsa_sks = [i[0] for i in eddsa_keys]
eddsa_vks = [i[1] for i in eddsa_keys]
eddsa_sigs = [eddsa_sign(eddsa_sks[i], msgs[i]) for i in range(NUMBER_OF_SIGS)]
start_time = time.time()
for i in range(NUMBER_OF_SIGS):
    eddsa_verify(eddsa_vks[i], msgs[i], eddsa_sigs[i])
print("ECDSA: --- %s seconds ---" % (time.time() - start_time))