# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  ThresholdPublicKey.py : 
#  A private key generated in a threshold encryption scheme.
#
#  Multiple threshold private keys are required in order to decrypt a 
#  ciphertext encrypted in a threshold encryption scheme.
#
#  Part of the PloneVote cryptographic library (PloneVoteCryptoLib)
#
#  Originally written by: Lazaro Clapp
#
# ============================================================================
# LICENSE (MIT License - http://www.opensource.org/licenses/mit-license):
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# ============================================================================

import xml.dom.minidom

from plonevotecryptolib.Threshold.ThresholdPublicKey import ThresholdPublicKey
from plonevotecryptolib.Threshold.PartialDecryption import PartialDecryption
from plonevotecryptolib.Threshold.PartialDecryption import PartialDecryptionBlock
from plonevotecryptolib.Threshold.PartialDecryption import PartialDecryptionBlockProof

from plonevotecryptolib.PVCExceptions import InvalidPloneVoteCryptoFileError
from plonevotecryptolib.PVCExceptions import IncompatibleCiphertextError

class ThresholdPrivateKey:
	"""
	A private key generated in a threshold encryption scheme.
	
	Multiple threshold private keys are required in order to decrypt a 
	ciphertext encrypted in a threshold encryption scheme. Because of this, the 
	interface and usage of this class is significantly different from that of 
	PrivateKey (which is why this class is not a subclass of PrivateKey).
	
	Note that multiple threshold private keys are associated with each 
	threshold public key, one for each trustee. This again in constrast with 
	simple private/public keys which are paired.
	
	Attributes:
		cryptosystem::EGCryptoSystem	-- The ElGamal cryptosystem in which 
										   this key is defined.
		num_trustees::int	-- Total number of trustees in the threshold scheme.
							   (the n in "k of n"-decryption)
		threshold::int	-- Minimum number of trustees required to decrypt 
						   threshold  encrypted messages. 
						   (the k in "k of n"-decryption)
		public_key::ThresholdPublicKey	-- The threshold public key to which 
										   this threshold private key is 
										   associated.
	"""
	
	def __init__(self, cryptosystem, num_trustees, threshold, 
				 threshold_public_key, private_key_value):
		"""
		Creates a new threshold private key. Should not be invoked directly.
		
		Instead of using this constructor from outside of PloneVoteCryptoLib, 
		please use ThresholdEncryptionSetUp.generate_private_key() or 
		ThresholdEncryptionSetUp.generate_key_pair().
		
		Arguments:
			(see class attributes for cryptosystem, num_trustees and threshold)
			threshold_public_key::ThresholdPublicKey	-- 
								The threshold public key to which this 
								threshold private key is associated.
			private_key_value::long		-- The actual value of the private key
							(P(j) for trustee j, see ThresholdEncryptionSetUp)
		"""
		self.cryptosystem = cryptosystem
		self.num_trustees = num_trustees
		self.threshold = threshold
		self.public_key = threshold_public_key
		self._key = private_key_value
	
	def generate_partial_decryption(self, ciphertext, task_monitor=None, 
									force=False):
		"""
		Generates a partial decryption for the given ciphertext.
		
		Arguments:
			ciphertext::Ciphertext	-- An encrypted Ciphertext object.
			task_monitor::TaskMonitor	-- A task monitor for this task.
			force:bool	-- Set this to true if you wish to force a decryption 
						   attempt, even when the ciphertext's stored public key
						   fingerprint does not match that of the public key 
						   associated with this private key.
		
		Returns:
			partial_decryption::PartialDecryption	-- A partial decryption of 
													   the given ciphertext 
													   generated with this 
													   threshold private key.
		
		Throws:
			IncompatibleCiphertextError -- The given ciphertext does not appear 
										   to be decryptable with the selected 
										   private key.
		"""
		# Check that the public key fingerprint stored in the ciphertext 
		# matches the public key associated with this private key.
		if(not force):
			if(ciphertext.nbits != self.cryptosystem.get_nbits()):
				raise IncompatibleCiphertextError("The given ciphertext is " \
						"not decryptable with the selected private key: " \
						"incompatible cryptosystem/key sizes.")
			
			if(ciphertext.pk_fingerprint != self.public_key.get_fingerprint()):
				raise IncompatibleCiphertextError("The given ciphertext is " \
						"not decryptable with the selected private key: " \
						"public key fingerprint mismatch.")
		
		nbits = self.cryptosystem.get_nbits()
		prime = self.cryptosystem.get_prime()
		key = self._key
		
		# New empty partial decryption
		partial_decryption = PartialDecryption(nbits)
		
		# Check if we have a task monitor and register with it
		if(task_monitor != None):
			# One tick per block
			ticks = ciphertext.get_length()
			partial_decrypt_task_mon = \
				task_monitor.new_subtask("Generate partial decryption", 
										 expected_ticks = ticks)
		
		# For each gamma component in the ciphertext, generate one partial 
		# decryption block (with proof):
		for gamma, delta in ciphertext:
		
			# To calculate the value of the block, elevate gamma to the 
			# threshold private key. That is block.value = g^{rP(i)} for each 
			# nbits block of original plaintext.
			value = pow(gamma, key, prime)
			
			# TODO: Add proof != None
			
			# Generate the block as (value, proof) and add it to the partial 
			# decryption object.
			block = PartialDecryptionBlock(value, None)
			partial_decryption.add_partial_decryption_block(block)
			
			# Update task progress
			if(task_monitor != None): partial_decrypt_task_mon.tick()
		
		return partial_decryption
			
		
	def _to_xml(self):
		"""
		Returns an xml document containing a representation of this private key.
		
		Returns:
			doc::xml.dom.minidom.Document
		"""
		doc = xml.dom.minidom.Document()
		root_element = doc.createElement("PloneVoteThresholdPrivateKey")
		root_element.setAttribute("trustees", str(self.num_trustees))
		root_element.setAttribute("threshold", str(self.threshold))
		doc.appendChild(root_element)
		
		priv_key_element = doc.createElement("PrivateKey")
		priv_key_str = hex(self._key)[2:]		# Remove leading '0x'
		if(priv_key_str[-1] == 'L'): 
			priv_key_str = priv_key_str[0:-1]		# Remove trailing 'L'
		priv_key_element.appendChild(doc.createTextNode(priv_key_str))
		root_element.appendChild(priv_key_element)
		
		cs_scheme_element = self.cryptosystem.to_dom_element(doc)
		root_element.appendChild(cs_scheme_element)
		
		return doc
		
	def to_file(self, filename):
		"""
		Saves this threshold private key to a file.
		"""
		doc = self._to_xml()
		
		file_object = open(filename, "w")
		file_object.write(doc.toprettyxml())
		file_object.close()
	
	@classmethod
	def from_file(cls, filename):
		"""
		Loads a threshold private key from file.
		"""
		pass
