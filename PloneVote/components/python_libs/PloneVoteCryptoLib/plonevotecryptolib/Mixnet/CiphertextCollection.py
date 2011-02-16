# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  CiphertextCollection.py : A class to represent a collection of ciphertexts.
#
#  This class is essentially a container for a list of Ciphertext objects 
#  encrypted with the same public key. 
#  Additionally, it implements the shuffle_with_proof() method, which provides 
#  a verifiable shuffling of the ciphertext collection into a different 
#  collection encapsulating the same plaintexts.
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

class CiphertextCollection:
	"""
	An object representing an ordered collection of ciphertexts.
	
	This object allows storing an ordered collection of Ciphertext objects and 
	provides indexing and iteration over said collection. All ciphertexts in 
	the collection must have been encrypted with the same public key, so that 
	they can be treated uniformly for shuffling.
	
	The shuffle_with_proof() method can be used to verifiably shuffle the 
	ciphertext collection into a different collection encapsulating the same 
	plaintexts.
	
	This class can be stored to and loaded to an XML file.
	
	Attributes:
		public_key::PublicKey	-- The public key that was used to encrypt all 
								   ciphertexts in the collection.
	"""
	
	def get_length(self):
		"""
		Returns the number of ciphertexts in the collection.
		"""
		return len(self._ciphertexts)
		
	def __getitem__(self, i):
		"""
		Makes this object indexable.
		
		Returns:
			ciphertext::Ciphertext	-- Returns the ith ciphertext in the 
									   collection. Index start at 0.
		"""
		length = len(self._ciphertexts)
		if(not (0 <= i < length)):
			return ValueError("Index out of range: Got %d, expected index " \
							  "between 0 and %d." % (i, length-1))
		
		return self._ciphertexts[i]
	
	def __iter__(self):
		"""
		Return an iterator for the current ciphertext collection.
		"""
		return self._ciphertexts.__iter__()
	
	def __eq__(self, other):
		"""
		Implements CiphertextCollection equality.
		
		Two ciphertext collections are equal if they have the same number of 
		elements and those elements are equal and in the same order. A 
		CiphertextCollection object is not equal to any object of a different 
		type.
		"""
		if(not isinstance(other, CiphertextCollection)):
			return False
		
		if(other.get_length() != self.get_length()):
			return False
		
		for i in range(0, self.get_length()):
			if(other[i] != self[i]):
				return False
		
		return True
	
	def __init__(self, public_key):
		"""
		Constructs a new (empty) CiphertextCollection.
		
		Arguments:
			(See class attributes)
		"""
		self.public_key = public_key
		# Cache the fingerprint to improve performance
		self._pk_fingerprint = self.public_key.get_fingerprint()
		self._ciphertexts = []
		
	def add_ciphertext(self, ciphertext):
		"""
		Adds a new Ciphertext object to the CiphertextCollection.
		
		Arguments:
			ciphertext::Ciphertext	-- The ciphertext to add.
		
		Throws:
			IncompatibleCiphertextError	-- If the given ciphertext was not 
										   encrypted with the public key for 
										   this collection.
		"""
		# Check that the ciphertext was encrypted with the correct public key 
		# for this collection.
		if(ciphertext.pk_fingerprint != self._pk_fingerprint):
			raise IncompatibleCiphertextError("The given ciphertext is " \
				"incompatible with this collection and cannot be added: It " \
				"was not encrypted with the public key declared for the " \
				"collection.")
		
		# Add the ciphertext
		self._ciphertexts.append(ciphertext)
	
	
	
