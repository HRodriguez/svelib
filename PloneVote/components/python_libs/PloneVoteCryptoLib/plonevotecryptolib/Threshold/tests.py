# ToDo: Turn this into an actual test case / doctest

from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem as egcs
from plonevotecryptolib.Threshold.ThresholdEncryptionSetUp import ThresholdEncryptionSetUp as tesu

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
	print trustees[i - 1].tesu_fingerprint
	trustees[i - 1].threshold_public_key = trustee_tesetup.generate_public_key()
	print trustees[i - 1].threshold_public_key.get_fingerprint()
	trustees[i - 1].threshold_private_key = trustee_tesetup.generate_private_key(i, trustees[i - 1].private_key)
		
