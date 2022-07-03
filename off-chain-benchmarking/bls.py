from bplib.bp import BpGroup


def bls_key_gen():
	group = BpGroup()
	sk = group.order().random()
	vk = sk * group.gen2()
	return sk, vk

def bls_sign(sk, message):
	group = BpGroup()
	h = group.hashG1(message)
	sig = sk * h
	return sig

# Verify the signature
def bls_verify(vk, message, sig):
	group = BpGroup()
	h = group.hashG1(message)
	return group.pair(sig, group.gen2()) == group.pair(h, vk)

if __name__ == "__main__":
    message = "hello"
    encoded_message = message.encode("utf8")
    sk, vk = bls_key_gen()
    sig = bls_sign(sk, encoded_message)
    if bls_verify(vk, encoded_message, sig):
        print("Good")
    else:
        print("Bad")