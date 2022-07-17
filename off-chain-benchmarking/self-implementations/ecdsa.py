from hashlib import sha256
from petlib.ec import EcGroup
from petlib.bn import Bn
from binascii import hexlify

def ecdsa_key_gen():
    # use secp256k1 curve
    group = EcGroup(714)
    sk = group.order().random()
    vk = sk * group.generator()
    return sk, vk


def ecdsa_sign(sk, message):
    group = EcGroup(714)
    # hash the message
    hash = sha256(message).digest()
    hash_bn = Bn.from_hex(hexlify(hash).decode("utf8"))
    # generate a random number
    k = group.order().random()
    R = k * group.generator()
    # take x coordinate from R
    Rx = R.export()
    r = Bn.from_hex((hexlify(Rx).decode("utf8")))
    s = k.mod_inverse(group.order()).mod_mul(hash_bn.mod_add(r.mod_mul(sk, group.order()), group.order()), group.order())
    sig = (r, s)
    return sig

    
def ecdsa_verify(vk, message, sig):
    group = EcGroup(714)
    r, s = sig
    # hash the message
    hash = sha256(message).digest()
    hash_bn = Bn.from_hex(hexlify(hash).decode("utf8"))
    s1 = s.mod_inverse(group.order())
    R_pi = (hash_bn.mod_mul(s1, group.order()) * group.generator()).pt_add(r.mod_mul(s1, group.order())* vk)
    r_pi = Bn.from_hex((hexlify(R_pi.export()).decode("utf8")))
    return r_pi == r
    
if __name__ == "__main__":
    message = "hello"
    encoded_message = message.encode("utf8")
    sk, vk = ecdsa_key_gen()
    sig = ecdsa_sign(sk, encoded_message)
    if ecdsa_verify(vk, encoded_message, sig):
        print("Signatue scheme correct")
    else:
        print("No...")