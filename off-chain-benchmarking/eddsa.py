from hashlib import sha256
from petlib.ec import EcGroup
from petlib.bn import Bn
from binascii import hexlify

def eddsa_key_gen():
    group = EcGroup(714)
    sk = group.order().random()
    vk = sk * group.generator()
    return sk, vk

def eddsa_sign(sk, message):
    message_bn = Bn.from_hex(hexlify(message).decode("utf8"))
    group = EcGroup(714)
    vk = sk * group.generator()
    hashed_sk = Bn.from_hex(sha256(sk.repr().encode("utf8")).hexdigest())
    r = Bn.from_hex(sha256(hashed_sk.mod_add(message_bn, group.order()).repr().encode("utf8")).hexdigest())
    R = r * group.generator()
    h = Bn.from_hex((hexlify((R+vk).export()).decode("utf8"))).mod_add(message_bn, group.order())
    s = h.mod_mul(sk, group.order()).mod_add(r, group.order())
    sig = (R, s)
    return sig

def eddsa_verify(vk, message, sig):
    message_bn = Bn.from_hex(hexlify(message).decode("utf8"))
    group = EcGroup(714)
    R, s = sig
    h = Bn.from_hex((hexlify((R+vk).export()).decode("utf8"))).mod_add(message_bn, group.order())
    P1 = s * group.generator()
    P2 = h * vk + R
    return P1==P2

if __name__ == "__main__":
    message = "hello"
    encoded_message = message.encode("utf8")
    sk, vk = eddsa_key_gen()
    sig = eddsa_sign(sk, encoded_message)
    if eddsa_verify(vk, encoded_message, sig):
        print("Good")
    else:
        print("Bad")