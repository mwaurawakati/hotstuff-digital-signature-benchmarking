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

def bls_verify(vk, message, sig):
	group = BpGroup()
	h = group.hashG1(message)
	return group.pair(sig, group.gen2()) == group.pair(h, vk)

def bls_aggregate(sigs):
	aggregated_sig = sigs[0]
	for sig in sigs[1:]:
		aggregated_sig += sig
	return aggregated_sig

def bls_verify_aggregate(aggregated_sig, vks, messages):
	group = BpGroup()
	rhs = group.pair(group.hashG1(messages[0]), vks[0])
	for i in range(1, len(messages)):
		rhs = rhs.mul(group.pair(group.hashG1(messages[i]), vks[i]))
	lhs = group.pair(aggregated_sig, group.gen2())
	return lhs == rhs

if __name__ == "__main__":
	message = "hello"
	encoded_message = message.encode("utf8")
	sk, vk = bls_key_gen()
	sig = bls_sign(sk, encoded_message)
	if bls_verify(vk, encoded_message, sig):
		print("Signatue scheme correct")
	else:
		print("No...")

	# aggregate 2 signatures
	sk2, vk2 = bls_key_gen()
	message2 = "hello2"
	encoded_message2 = message2.encode("utf8")
	sig2 = bls_sign(sk2, encoded_message2)
	aggregated_sig = bls_aggregate([sig, sig2])
	if bls_verify_aggregate(aggregated_sig, [vk, vk2], [encoded_message, encoded_message2]):
		print("Aggreation correct")
	else:
		print("No...")