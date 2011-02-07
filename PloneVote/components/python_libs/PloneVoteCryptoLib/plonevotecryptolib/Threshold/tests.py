# -*- coding: utf-8 -*-
# ToDo: Turn this into an actual test case / doctest

from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem as egcs
from plonevotecryptolib.Threshold.ThresholdEncryptionSetUp import ThresholdEncryptionSetUp as tesu
from plonevotecryptolib.Threshold.ThresholdDecryptionCombinator import ThresholdDecryptionCombinator

cs = egcs.new()

class Trustee:
	def __init__(self, cs):
		kp = cs.new_key_pair()
		self.private_key = kp.private_key
		self.public_key = kp.public_key
		self.commitment = None
		self.tesu_fingerprint = None
		self.threshold_public_key = None
		self.threshold_private_key = None


trustees = [Trustee(cs) for i in range(0,5)]

tesetup = tesu(cs, 5, 3)

for i in range(1,6):
	tesetup.add_trustee_public_key(i, trustees[i - 1].public_key)

for i in range(1,6):
	trustees[i - 1].commitment = tesetup.generate_commitment()

for i in range(1,6):
	trustee_tesetup = tesu(cs, 5, 3)
	for j in range(1,6):
		trustee_tesetup.add_trustee_commitment(j, trustees[j - 1].commitment)
	trustees[i - 1].tesu_fingerprint = trustee_tesetup.get_fingerprint()
	kp = trustee_tesetup.generate_key_pair(i, trustees[i - 1].private_key)
	trustees[i - 1].threshold_public_key = kp.public_key
	trustees[i - 1].threshold_private_key = kp.private_key

message = "This is a test secret message: áñ. ö"

t_public_key = trustees[0].threshold_public_key

ciphertext = t_public_key.encrypt_text(message)

partial_decryptions = [None for i in range(1,6)]

for i in range(1,6):
	partial_decryptions[i - 1] = trustees[i - 1].threshold_private_key.generate_partial_decryption(ciphertext)

# Do combined decryption
combinator = ThresholdDecryptionCombinator(cs, ciphertext, 5, 3)

for i in range(1,4):
	combinator.add_partial_decryption(i, partial_decryptions[i - 1])

print combinator.decrypt_to_text()
