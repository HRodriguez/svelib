# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  CiphertextCollectionMapping.py :
#
#  This file also provides CiphertextCollectionMapping, a class for storing the 
#  explicit mapping between two CiphertextCollection objects, giving the 
#  re-ordering and re-encryption of the ciphertexts. Given two 
#  CiphertextCollection objects and their corresponding 
#  CiphertextCollectionMapping, it can be verified that both collections 
#  contain re-encryptions of the same collection of plaintexts (including 
#  repetitions of the same plaintext). This verification is not in 
#  Zero-Knowledge. In fact, the CiphertextCollectionMapping reveals the mapping 
#  from each ciphertext of one collection to another unique ciphertext in the 
#  second.
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

# secure version of python's random:
from Crypto.Random.random import StrongRandom

from plonevotecryptolib.Mixnet.CiphertextCollection import CiphertextCollection
from plonevotecryptolib.Mixnet.CiphertextReencryptionInfo import CiphertextReencryptionInfo
from plonevotecryptolib.PVCExceptions import IncompatibleCiphertextCollectionError

def _random_shuffle_in_place(strong_random, l):
	"""
	This method is a workaround for pycrypto's bug 720310 
	(https://bugs.launchpad.net/pycrypto/+bug/720310). 
	It implements StrongRandom.shuffle(l).
	DO NOT USE EXTERNALLY.
	"""
	# Make a (copy) of the list of objects we want to shuffle
	items = list(l)

	# Choose a random item (without replacement) until all the items have been
	# chosen.
	for i in xrange(len(l)):
		p = strong_random.randint(0, len(items) - 1)
		l[i] = items[p]
		del items[p]

class CiphertextCollectionMapping:
	"""
	Stores the explicit mapping between two CiphertextCollection objects.
	
	Using this class outside of PloneVoteCryptoLib is not recommended. Within 
	plonevotecryptolib.Mixnet, only CiphertextCollection, Mixer and 
	ShufflingProof should be used by most clients.
	
	This class contains both the re-ordering and re-encryption information 
	mapping a particular collection of ciphertexts into another shuffled 
	collection.
	
	To create a new mapping, use the new() class method with the collection to 
	be shuffled, this will create a CiphertextCollectionMapping compatible with 
	said collection. The shuffled collection corresponding to that mapping can 
	then be obtained by using the apply() method of the mapping with the 
	original collection as argument. Finally, given the original and shuffled 
	collections, as well as the mapping, the equivalence of the collections can 
	be verified with the verify() method of this class. Note that this 
	verification is not done in Zero-Knowledge. In fact, the 
	CiphertextCollectionMapping reveals the mapping from each ciphertext of one 
	collection to another unique ciphertext in the second.
	
	(See [TODO: Add reference] for more infomation).
	"""
	
	## SOME NOTES ON THE INTERNALS OF THIS MAPPING:
	#
	# A CiphertextCollectionMapping has two private fields:
	#
	#	* self._reordering, which stores the index re-ordering between the 
	#	  original ciphertext collection and the shuffled one. That is the ith 
	#	  element of the original collection corresponds to the 
	#	  self._reordering[i]-th element of the shuffled collection that 
	#	  results of applying this mapping to the original collection.
	#
	#	* self._reencryptions is a list of CiphertextReencryptionInfo objects 
	#	  providing the re-encryption information between individual elements 
	#	  of the original collection and elements of the shuffled collection.
	#	  It is important to note that this list of re-encryptions is indexed by
	#	   the index of the re-encrypted ciphertext in the original collection. 
	#	  That is, the ith element of self._reencryptions corresponds to the 
	#	  re-encryption information used to re-encrypt the ith element of the 
	#	  original collection into the self._reordering[i]-th element of the 
	#	  shuffled collection.
	#
	##
	
	def __init__(self):
		"""
		Constructs a new empty CiphertextCollectionMapping.
		
		This method should not be used outside of this class. Consider using 
		CiphertextCollectionMapping.new(...) for creating a new 
		CiphertextCollectionMapping object for a particular collection.
		"""
		self._reordering = []
		self._reencryptions = []
	
	@classmethod
	def new(cls, collection):
		"""
		Generate a new mapping compatible with the given collection.
		
		This method produces a new CiphertextCollectionMapping object that maps 
		the given collection into a randomly shuffled collection. To obtain 
		said shuffled collection, simply call the apply method of the returned 
		mapping, passing once again the collection as an argument.
		
		The reason this method takes the collection to be shuffled as an 
		argument is to ensure that the resulting CiphertextCollectionMapping is 
		compatible with said collection. This includes: providing a re-ordering 
		and re-encryption for the right number of elements of the right size, 
		as well as using the same public key for re-encryption as the one used 
		to encrypt the elements of the original collection.
		
		Arguments:
			collection::CiphertextCollection -- The collection for which we 
												wish to generate a new mapping.
		
		Returns:
			mapping::CiphertextCollectionMapping --
				A mapping from collection to a randomly shuffled new collection.
		"""
		# Get the public key and length of the collection
		public_key = collection.public_key
		length = collection.get_length()
		
		# Create an empty mapping
		mapping = CiphertextCollectionMapping()
		
		# Generate a list of all collection element indexes
		for i in range(0, length):
			mapping._reordering.append(i)
		
		# Randomly permute those indexes to generate a reordering
		random = StrongRandom()
		### random.shuffle(self._reordering) is broken upstream, workaround: 
		_random_shuffle_in_place(random, mapping._reordering)
		
		# Generate a random re-encryption for each ciphertext in the collection
		for ciphertext in collection:
			ciphertext_len = ciphertext.get_length()
			reencryption = \
				CiphertextReencryptionInfo.new(public_key, ciphertext_len)
			mapping._reencryptions.append(reencryption)
		
		# Return the generated mapping
		return mapping
		
		
	def apply(self, collection):
		"""
		Apply this mapping to the given collection.
		
		This returns a collection that is the same as the given collection, but 
		shuffled using the current mapping. That both collections have the same 
		contents (same encrypted plaintexts) can be then verified using the 
		verify(...) method of this same mapping.
		
		The given collection must be compatible with this mapping. The simplest 
		way to ensure that is if this mapping was originally created using 
		CiphertextCollectionMapping.new(...) with the same collection given as 
		the argument.
		
		Arguments:
			collection::CiphertextCollection	-- The collection to which to 
												   apply this mapping, 
												   thus shuffling it.
		
		Returns:
			shuffled_collection::CiphertextCollection	--
				The resulting shuffled collection.
		
		Throws:
			IncompatibleCiphertextCollectionError --
				If the given collection is not compatible with this mapping.
		"""
		# Get the length of the collection
		length = collection.get_length()
		
		# Check that the length is compatible with this mapping
		# (Same number of CiphertextReencryptionInfo objects and re-ordering 
		# indexes)
		assert len(self._reencryptions) == len(self._reordering)
		if(length != len(self._reencryptions)):
			raise IncompatibleCiphertextCollectionError( \
					"The given collection is incompatible with this mapping. " \
					"The mapping is configured to shuffle a collection of %d " \
					"ciphertexts, while the given collection contains %d " \
					"ciphertexts. To create a new random mapping compatible " \
					"with the given collection, use " \
					"CiphertextCollectionMapping.new(...)." % \
					(len(self._reencryptions), length))
		
		# Create a temporary array to store the mapped ciphertexts
		ciphertexts = [None for i in range(0, length)]
		
		# For each ciphertext in the original collection
		for i in range(0, collection.get_length()):
			ciphertext = collection[i]
			
			# Re-encrypt the ciphertext with the corresponding re-encryption 
			# info.
			reencryption = self._reencryptions[i]
			
			try:
				reencrypted_ciphertext = reencryption.apply(ciphertext)
			except IncompatibleCiphertextError, e:
				raise IncompatibleCiphertextCollectionError( \
					"The given collection is incompatible with this mapping. " \
					"The ciphertext #%d in the collection cannot be " \
					"re-encrypted with the corresponding re-encryption " \
					"associated with this mapping. Internal exception message "\
					"is \"%s\". To create a new random mapping compatible " \
					"with the given collection, use " \
					"CiphertextCollectionMapping.new(...)." % (i,e.msg))
					
			# Get the index after re-ordering
			index = self._reordering[i]
			
			# Store the re-encrypted ciphertext at that index in the temp array
			ciphertexts[index] = reencrypted_ciphertext
		
		# Turn the temp array into a new CiphertextCollection and return it
		shuffled_collection = CiphertextCollection(collection.public_key)
		for ciphertext in ciphertexts:
			shuffled_collection.add_ciphertext(ciphertext)
			
		return shuffled_collection
	
	def verify(self, original_collection, shuffled_collection):
		"""
		Verify that the given collections are mapped by the current mapping.
		
		This method checks whether shuffled_collection is obtained as a shuffle 
		of original_collection by means of applying the mapping represented by 
		this CiphertextCollectionMapping object. 
		
		If this method returns true, then we have proof that both collections 
		contain encryptions of the same collection of plaintexts. Otherwise we 
		gain no information about the two collections, other than they are not 
		mapped from the first to the second by this particular mapping.
		
		Note that, if this returns true, the information included in this 
		CiphertextCollectionMapping object can be used to determine which 
		ciphertexts in the first collection correspond to which ciphertexts on 
		the shuffled collection. This verification is not done in 
		Zero-Knowledge. ShufflingProof must be used instead to provide a 
		Zero-Knowledge proof of equivalence between two ciphertext collections.
		
		Arguments:
			original_collection::CiphertextCollection	--
				The original collection of ciphertexts.
			shuffled_collection::CiphertextCollection	--
				Another collection for which we wish to know if it was obtained 
				by applying this mapping to original_collection.
		
		Returns:
			result::bool	-- True if shuffled_collection can be obtained from 
							   original_collection by applying the current 
							   mapping.
							   False otherwise.
		"""
		try:
			original_shuffled = self.apply(original_collection)
		except IncompatibleCiphertextCollectionError:
			return False
		
		return (original_shuffled == shuffled_collection)
	
	def rebase(self, other_mapping):
		"""
		"""
		pass
