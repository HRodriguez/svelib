# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  CiphertextCollection.py : A class to represent a collection of ciphertexts.
#
#  This class is essentially a container for a list of Ciphertext objects. 
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

class CiphertextCollectionIterator:
	"""
	An iterator object for a CiphertextCollection.
	
	It returns each ciphertext in order.
	
	Attributes:
		collection::CiphertextCollection	-- The collection through which  
											   this iterator iterates.
	"""
	
	def __init__(self, collection):
		"""
		Constructs a new iterator.
		
		Arguments:
			collection::CiphertextCollection	-- the ciphertext collection 
												   through which we wish to 
												   iterate.
		"""
		self.collection = collection
		self._pos = 0
		self._max = collection.get_size()
	
	def next(self):
		"""
		Retrieve the next ciphertext.
		"""
		if(self._pos == self._max):
			raise StopIteration
		ciphertext = self.collection[self._pos]
		self._pos += 1
		return ciphertext


class CiphertextCollection:
	"""
	An object representing an ordered collection of ciphertexts.
	
	This object allows storing an ordered collection of Ciphertext objects and 
	provides indexing and iteration over said collection. 
	
	The shuffle_with_proof() method can be used to verifiably shuffle the 
	ciphertext collection into a different collection encapsulating the same 
	plaintexts.
	
	This class can be stored to and loaded to an XML file.
	"""
	
	def get_size(self):
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
		return CiphertextCollectionIterator(self)
	
	def __init__(self):
		"""
		Constructs a new (empty) CiphertextCollection.
		"""
		self._ciphertexts = []
		
	def add_ciphertext(self, ciphertext):
		"""
		Adds a new Ciphertext object to the CiphertextCollection.
		
		Arguments:
			ciphertext::Ciphertext	-- The ciphertext to add.
		"""
		self._ciphertexts.append(ciphertext)
	
	
	
