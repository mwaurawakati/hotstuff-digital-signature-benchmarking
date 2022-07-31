from bplib.bp import BpGroup
from petlib.bn import Bn
import hashlib
import time


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

def modified_bls_aggregate(vks, sigs):
	ts = []
	for vk in vks:
		ts.append(Bn.from_hex(hashlib.sha256(vk.export()).hexdigest()))
	aggregated_sig = sigs[0] * ts[0]
	for i in range(1, len(sigs)):
		aggregated_sig += sigs[i] * ts[i]
	return aggregated_sig

def modified_bls_verify_aggregate(aggregated_sig, vks, message):
	group = BpGroup()
	ts = []
	for vk in vks:
		ts.append(Bn.from_hex(hashlib.sha256(vk.export()).hexdigest()))
	avk = vks[0] * ts[0]
	for i in range(1, len(vks)):
		avk += vks[i] * ts[i]
	lhs = group.pair(group.hashG1(message), avk)
	rhs = group.pair(aggregated_sig, group.gen2())
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
	start_time = time.time()
	aggregated_sig = bls_aggregate([sig, sig2])
	if bls_verify_aggregate(aggregated_sig, [vk, vk2], [encoded_message, encoded_message2]):
		print("Aggreation correct")
	else:
		print("No...")
	print("Signature aggregation: --- %s seconds ---" % ((time.time() - start_time)/100))

	# multisig using modified bls
	sig3 = bls_sign(sk2, encoded_message)
	start_time = time.time()
	aggregated_sig = modified_bls_aggregate([vk, vk2], [sig, sig3])
	if modified_bls_verify_aggregate(aggregated_sig, [vk, vk2], encoded_message):
		print("Multisig correct")
	else:
		print("No...")
	print("Multi-signature: --- %s seconds ---" % ((time.time() - start_time)/100))