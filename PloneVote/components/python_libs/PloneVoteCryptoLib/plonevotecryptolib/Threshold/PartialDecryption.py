# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  PartialDecryption.py : 
#  A partial decryption generated in a threshold encryption scheme.
#
#  Each trustee generates a partial decryption using their threshold private 
#  key, and then k=threshold distinct partial decryptions can be combined 
#  using ThresholdDecryptionCombinator into the decrypted plaintext.
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

class PartialDecryption:
	"""
	A partial decryption generated in a threshold encryption scheme.
	
	To decrypt a threshold encrypted ciphertext with n trustees and a threshold 
	of k, each decrypting trustee must generate a partial decryption from the 
	ciphertext using its threshold private key. Any k of this partial 
	decryptions can then be combined  using ThresholdDecryptionCombinator to 
	retrieve the original plaintext.
	
	Attributes:
		nbits::int	-- Size in bits of the cryptosystem/public key used to 
					   encrypt the ciphertext of which this is a partial 
					   decryption.
	"""
	
	def __getitem__(self, i):
		"""
		Makes this object indexable.
		
		Returns:
			block::long	-- Returns the ith nbits block of partial decryption. 
						   This blocks should only be used by select classes 
						   within PloneVoteCryptoLib, and not from outside 
						   classes.
		"""
		return self._blocks[i]
		
	# CONSIDER: ciphertext_fingerprint ?
	def __init__(self, nbits):
		"""
		Create an empty partial decryption object.
		
		This constructor is not intended to be called directly from outside 
		PloneVoteCryptoLib, instead, consider using 
		ThresholdPrivateKey.generate_partial_decryption()
		
		Arguments:
			nbits::int	-- Size in bits of the cryptosystem/public key used to 
					   encrypt the ciphertext of which this is a partial 
					   decryption.
		"""
		self.nbits = nbits
		self._blocks = []
	
	#TODO: Add support for proofs!
	def add_partial_decryption_block(self, block, proof=None):
		"""
		Add an nbits block of partial decryption.
		
		This method is not intended to be called directly from outside 
		PloneVoteCryptoLib, instead, consider using 
		ThresholdPrivateKey.generate_partial_decryption()
		
		Arguments:
			block::long	-- A block of partial decryption information. Each 
						   block corresponds to an nbits block of the original 
						   plaintext. One can also see it as corresponding to a 
						   (gamma, delta) pair of the ciphertext.
		"""
		self._blocks.append(block)
		
