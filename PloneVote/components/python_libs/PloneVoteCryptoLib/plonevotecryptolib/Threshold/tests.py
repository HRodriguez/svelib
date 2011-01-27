# ToDo: Turn this into an actual test case / doctest

from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem as egcs
from plonevotecryptolib.Threshold.ThresholdEncryptionSetUp import ThresholdEncryptionSetUp as tesu

cs = egcs.new()

class Trustee:
	def __init__(self, cs):
		kp = cs.new_key_pair()
		self.priv_key = kp.private_key
		self.pub_key = kp.public_key
		self.commitment = None


trustees = [Trustee(cs) for i in range(0,5)]

tesetup = tesu(cs, 5, 3)

for i in range(1,6):
	tesetup.add_trustee_public_key(i, trustees[i - 1].pub_key)

c = tesetup.generate_commitment()

