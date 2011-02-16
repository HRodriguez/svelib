# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  Ciphertext.py : A class to represent encrypted data within PloneVoteCryptoLib.
#
#  This class is mostly used to represent encrypted data in memory and to 
#  store/load that data to/from file.
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

## Note 001:
#
# By convention (followed across PloneVoteCryptoLib), before being encrypted, 
# all data is transformed into an array of bytes formated as follows:
#
# - The first 64 bits (8 bytes) are a long representation of the size of 
# the encrypted data ($size).
# - The next $size bits are the original data to be encrypted.
# - The rest of the array contains random padding.
#
#	[size (64 bits) | message (size bits) | padding (X bits) ]
#
# Note that this limits messages to be encrypted to 16 Exabits (2 Exabytes). 
# We deem this enough for our purposes (in fact, votes larger than a couple MB 
# are highly unlikely, and system memory is probably going to be a more  
# immediate problem).
#
##
import xml.dom.minidom

from plonevotecryptolib.utilities.BitStream import BitStream

class CiphertextIterator:
	"""
	An iterator object for a Ciphertext.
	
	It works block by block returning the (gamma, delta) pair for each block.
	"""
	
	def __init__(self,ciphertext):
		"""
		Constructs a new iterator.
		
		Arguments:
			ciphertext::Ciphertext	-- the ciphertext object through which we 
									   wish to iterate.
		"""
		self.ciphertext = ciphertext
		self._pos = 0
		self._max = ciphertext.get_length()
	
	def next(self):
		"""
		Retrieve next block in the ciphertext.
		
		Returns:
			(gamma, delta)::(long, long)	-- The gamma and delta pair 
											   representing a block of ElGamal 
											   encrypted ciphertext.
		"""
		if(self._pos == self._max):
			raise StopIteration
		pair = self.ciphertext[self._pos]
		self._pos += 1
		return pair


class Ciphertext:
	"""
	An object representing encrypted PloneVote data.
	
	Ciphertext objects are created by PublicKey encrypt operations and 
	decrypted through PrivateKey decrypt methods (or through 
	ThresholdDecryptionCombinator if the data was encrypted with a threshold 
	public key and all partial decryptions are available).
	
	This class can also be store to and loaded from file using the PloneVote 
	armored ciphertext XML format.
	
	Attributes:
		nbits::int	-- Size in bits of the cryptosystem/public key used to 
					   encrypt this ciphertext.
		pk_fingerprint::string -- A fingerprint of the public key used to 
								  encrypt this ciphertext. This fingerprint can 
								  then be compared with the result from 
								  PublicKey.get_fingerprint() to check for 
								  compatibility with a given key pair or 
								  combined public key.
		gamma::long[]
		delta::long[]	-- :
			This two attributes should only be accessed by key classes within 
			PloneVoteCryptoLib.
			See "Handbook of Applied Cryptography" Algorithm 8.18 for the 
			meaning of the variables. An array is used because the encrypted 
			data might be longer than the cryptosystem's bit size.
	"""
	
	def get_length(self):
		"""
		Returns the length, in blocks, of the ciphertext.
		"""
		assert len(self.gamma) == len(self.delta), "Each gamma component of " \
											"the ciphertext must correspond " \
											" to one delta component."
		return len(self.gamma)
	
	def __getitem__(self, i):
		"""
		Makes this object indexable.
		
		Returns:
			(gamma, delta)::(long, long)	-- Returns the gamma, delta pair 
											   representing a particular block 
											   of the encrypted data.
				Use ciphertext[i] for block i.
		"""
		return (self.gamma[i], self.delta[i])
	
	def __iter__(self):
		"""
		Return an iterator (CiphertextIterator) for the current ciphertext.
		"""
		return CiphertextIterator(self)
	
	def __eq__(self, other):
		"""
		Implements Ciphertext equality.
		
		Two ciphertexts are equal if they have the same bit size, public key 
		fingerprint and list of gamma and delta components. A ciphertext is not 
		equal to any object of a different type.
		"""
		if(not isinstance(other, Ciphertext)):
			return False
		
		if(other.nbits != self.nbits):
			return False
		
		if(other.pk_fingerprint != self.pk_fingerprint):
			return False
		
		if(other.gamma != self.gamma):
			return False
		
		if(other.delta != self.delta):
			return False
		
		return True
	
	def __init__(self, nbits, public_key_fingerprint):
		"""
		Create an empty ciphertext object.
		
		Arguments:
			nbits::int	-- Size in bits of the cryptosystem/public key used to 
						   encrypt this ciphertext.
			public_key_fingerprint::string	-- The fingerprint of the public 
											   key used to encrypt this data.
		"""
		self.gamma = []
		self.delta = []
		self.nbits = nbits
		self.pk_fingerprint = public_key_fingerprint
	
	def append(self, gamma, delta):
		"""
		Used internally by PublicKey.
		
		This method adds an encrypted block of data with its gamma and delta 
		components from ElGamal (see HoAC Alg. 8.18). 
		"""	
		self.gamma.append(gamma)
		self.delta.append(delta)
	
	def _encrypted_data_as_bitstream(self):
		"""
		Returns the contents of this ciphertext as a BitStream.
		
		This includes only the encrypted data (gamma and delta components), not 
		the nbits and public key fingerprint metadata.
		
		The components are encoded alternating as follows:
			[gamma[0], delta[0], gamma[1], delta[1], ...]
		with each component represented as a nbits long number.
		
		Returns:
			bitstream::BitStream	-- The gamma and delta components of this 
									   ciphertext as a bitstream.
		"""
		bitstream = BitStream()
		for i in range(0, self.get_length()):
			bitstream.put_num(self.gamma[i], self.nbits)
			bitstream.put_num(self.delta[i], self.nbits)
		return bitstream
	
	def _encrypted_data_as_base64(self):
		"""
		Returns the contents of this ciphertext as a base64 string.
		
		This includes only the encrypted data (gamma and delta components), not 
		the nbits and public key fingerprint metadata.
		"""
		bitstream = self._encrypted_data_as_bitstream()
		bitstream.seek(0)
		length = bitstream.get_length()
		
		assert length % 8 == 0, \
				"The ciphertext data must be a multiple of eight bits in size."
				
		return bitstream.get_base64(length)
		
		
	def _to_xml(self):
		"""
		Returns an xml document containing a representation of this ciphertext.
		
		Returns:
			doc::xml.dom.minidom.Document
		"""
		doc = xml.dom.minidom.Document()
		root_element = doc.createElement("PloneVoteCiphertext")
		doc.appendChild(root_element)
		
		nbits_element = doc.createElement("nbits")
		nbits_element.appendChild(doc.createTextNode(str(self.nbits)))
		root_element.appendChild(nbits_element)
		
		pkfingerprint_element = doc.createElement("PKFingerprint")
		pkfingerprint_element.appendChild(doc.createTextNode(self.pk_fingerprint))
		root_element.appendChild(pkfingerprint_element)
		
		data_element = doc.createElement("EncryptedData")
		data = self._encrypted_data_as_base64()
		data_element.appendChild(doc.createTextNode(data))
		root_element.appendChild(data_element)
		
		return doc
		
	def to_file(self, filename):
		"""
		Saves this ciphertext to a file.
		"""
		doc = self._to_xml()
		
		file_object = open(filename, "w")
		file_object.write(doc.toprettyxml())
		file_object.close()
	
	@classmethod
	def from_file(cls, filename):
		"""
		Loads a ciphertext from file.
		"""
		doc = xml.dom.minidom.parse(filename)
		
		# Check root element
		if(len(doc.childNodes) != 1 or 
			doc.childNodes[0].nodeType != doc.childNodes[0].ELEMENT_NODE or
			doc.childNodes[0].localName != "PloneVoteCiphertext"):
			
			raise InvalidPloneVoteCryptoFileError(filename, 
				"A PloneVoteCryptoLib stored ciphertext file must be an " \
				"XML file with PloneVoteCiphertext as its root element.")	
		
		root_element = doc.childNodes[0]
		
		nbits_element = fingerprint_element = data_element = None
		
		# Retrieve individual "tier 2" nodes
		for node in root_element.childNodes:
			if node.nodeType == node.ELEMENT_NODE:
				if node.localName == "nbits":
					nbits_element = node
				elif node.localName == "PKFingerprint":
					fingerprint_element = node
				elif node.localName == "EncryptedData":
					data_element = node
					
		# Check nbits node
		if(nbits_element == None):
			raise InvalidPloneVoteCryptoFileError(filename, 
				"The PloneVoteCryptoLib stored ciphertext file must include " \
				"the used cryptosystem's key size in bits.")
				
		if(len(nbits_element.childNodes) != 1 or 
			nbits_element.childNodes[0].nodeType != nbits_element.childNodes[0].TEXT_NODE):
			
			raise InvalidPloneVoteCryptoFileError(filename, 
				"The PloneVoteCryptoLib stored ciphertext file must include " \
				"the used cryptosystem's key size in bits.")
		
		nbits_str = nbits_element.childNodes[0].data.strip()	# trim spaces
		nbits = int(nbits_str)
					
		# Check fingerprint node
		if(fingerprint_element == None):
			raise InvalidPloneVoteCryptoFileError(filename, 
				"The PloneVoteCryptoLib stored ciphertext file must include " \
				"the fingerprint of the public key used to encrypt it.")
				
		if(len(fingerprint_element.childNodes) != 1 or 
			fingerprint_element.childNodes[0].nodeType != fingerprint_element.childNodes[0].TEXT_NODE):
			
			raise InvalidPloneVoteCryptoFileError(filename, 
				"The PloneVoteCryptoLib stored ciphertext file must include " \
				"the fingerprint of the public key used to encrypt it.")
		
		#	trim spaces
		fingerprint_str = fingerprint_element.childNodes[0].data.strip()
		
		# Check the EncryptedData node
		if(data_element == None):
			raise InvalidPloneVoteCryptoFileError(filename, 
				"The PloneVoteCryptoLib stored ciphertext file must include " \
				"the encrypted data inside an <EncryptedData> element.")
				
		if(len(data_element.childNodes) != 1 or 
			data_element.childNodes[0].nodeType != data_element.childNodes[0].TEXT_NODE):
			
			raise InvalidPloneVoteCryptoFileError(filename, 
				"The PloneVoteCryptoLib stored ciphertext file must include " \
				"the encrypted data inside an <EncryptedData> element.")
		
		#	trim spaces
		data_str = data_element.childNodes[0].data.strip()
		
		# Construct a new Ciphertext object with the given nbits and fingerprint
		ciphertext = cls(nbits, fingerprint_str)
		
		# Load the encrypted data
		bitstream = BitStream()
		bitstream.put_base64(data_str)
		bitstream.seek(0)
		length = bitstream.get_length()
		
		#     number of gamma and delta blocks in the bitstream:
		blocks = length / (nbits * 2)
		
		for i in range(0, blocks):
			gamma_val = bitstream.get_num(nbits)
			delta_val = bitstream.get_num(nbits)
			ciphertext.append(gamma_val, delta_val)
		
		# Return the ciphertext
		return ciphertext
