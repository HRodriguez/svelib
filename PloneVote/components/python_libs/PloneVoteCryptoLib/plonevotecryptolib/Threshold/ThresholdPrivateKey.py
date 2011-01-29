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

from plonevotecryptolib.PublicKey import PublicKey
from plonevotecryptolib.PrivateKey import PrivateKey
from plonevotecryptolib.PVCExceptions import InvalidPloneVoteCryptoFileError

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
	"""
	
	#TODO: Add self.public_key
	
	def __init__(self, cryptosystem, num_trustees, threshold,
				 private_key_value):
		"""
		Creates a new threshold private key. Should not be invoked directly.
		
		Instead of using this constructor from outside of PloneVoteCryptoLib, 
		please use ThresholdEncryptionSetUp.generate_private_key() or 
		ThresholdEncryptionSetUp.generate_key_pair().
		
		Arguments:
			(see class attributes for cryptosystem, num_trustees and threshold)
			private_key_value::long		-- The actual value of the private key
							(P(j) for trustee j, see ThresholdEncryptionSetUp)
		"""
		self.cryptosystem = cryptosystem
		self.num_trustees = num_trustees
		self.threshold = threshold
		self._key = private_key_value
	
	def generate_partial_decryption(self, ciphertext):
		"""
		Generates a partial decryption for the given ciphertext.
		
		Returns:
			partial_decryption::PartialDecryption	-- A partial decryption of 
													   the given ciphertext 
													   generated with this 
													   threshold private key.
		"""
		# TODO: Add a public key fingerprint check here!
		
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
