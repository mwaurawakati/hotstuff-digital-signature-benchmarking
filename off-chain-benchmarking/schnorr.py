from hashlib import sha256
from petlib.ec import EcGroup
from petlib.bn import Bn
from binascii import hexlify

def schnorr_key_gen():
    # use secp256k1 curve
    group = EcGroup(714)
    sk = group.order().random()
    vk = sk * group.generator()
    return sk, vk

def schnorr_sign(sk, message):
    group = EcGroup(714)
    k = group.order().random()
    R = k * group.generator()
    e = sha256((hexlify(R.export()).decode('utf8')+str(message)).encode('utf8')).digest()
    e = Bn.from_hex(hexlify(e).decode("utf8")).mod(group.order())
    s = k.mod_sub(sk.mod_mul(e, group.order()), group.order())
    sig = (s, e)
    return sig

def schnorr_verify(vk, message, sig):
    group = EcGroup(714)
    s, e = sig
    R_v = (s * group.generator())+(e * vk)
    e_v = sha256((hexlify(R_v.export()).decode('utf8')+str(message)).encode('utf8')).digest()
    e_v = Bn.from_hex(hexlify(e_v).decode("utf8")).mod(group.order())
    return e_v == e

if __name__ == "__main__":
    message = "hello"
    encoded_message = message.encode("utf8")
    sk, vk = schnorr_key_gen()
    sig = schnorr_sign(sk, encoded_message)
    if schnorr_verify(vk, encoded_message, sig):
        print("Good")
    else:
        print("Bad")