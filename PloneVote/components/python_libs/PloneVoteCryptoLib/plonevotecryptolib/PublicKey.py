# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  PublicKey.py : The public key class.
#
#  Used for data encryption.
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

import math
import xml.dom.minidom

# secure version of python's random:
from Crypto.Random.random import StrongRandom
import Crypto.Hash.SHA256	# sha256 is not available in python 2.4 standard lib

from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem, EGStub
from plonevotecryptolib.Ciphertext import Ciphertext
from plonevotecryptolib.utilities.BitStream import BitStream

class MessageToLongError(Exception):
	"""
	The given message to encrypt is larger than the allowed maximum.
	"""

	def __init__(self):
		"""
		Create a new MessageToLongError exception.
		"""
		self.msg = "The message to encrypt exceeds the maximum allowed size " \
				   "(16 Exabytes)."


class PublicKey:
	"""
	An ElGamal public key object used for encryption.
	
	Attributes:
		cryptosystem::EGCryptoSystem	-- The ElGamal cryptosystem in which 
										   this key is defined.
	"""
	
	cryptosystem = None
	
	def get_fingerprint(self):
		"""
		Gets a fingerprint of the current public key.
		
		This fingerprint should be stored with any text encrypted with this 
		public key, in order to facilitate checking compatibility with a 
		particular key pair for future decryption or manipulation.
		"""
		fingerprint = Crypto.Hash.SHA256.new()
		fingerprint.update(hex(self.cryptosystem.get_nbits()))
		fingerprint.update(hex(self.cryptosystem.get_prime()))
		fingerprint.update(hex(self.cryptosystem.get_generator()))
		fingerprint.update(hex(self._key))
		return fingerprint.hexdigest()	
	
	def __init__(self, cryptosystem, public_key_value):
		"""
		Creates a new public key. Should not be invoked directly.
		
		Instead of using this constructor from outside of PloneVoteCryptoLib, 
		please use the class methods KeyPair.new() or PublicKey.from_file(file).
		
		Arguments:
			cryptosystem::EGCryptoSystem-- The ElGamal cryptosystem in which 
										   this key is defined.
			public_key_value::long		-- The actual value of the public key
										   (g^a mod p, where a is the priv. key)
		"""
		self.cryptosystem = cryptosystem
		self._key = public_key_value
		
	def encrypt_bitstream(self, bitstream, pad_to=None, task_monitor=None):
		"""
		Encrypts the given bitstream into a ciphertext object.
		
		Arguments:
			bitstream::BitStream-- A stream of bits to encrypt 
								   (see BitStream utility class).
			pad_to::int			-- Minimum size (in bytes) of the resulting 
								   ciphertext. Data will be padded before 
								   encryption to match this size.
			task_monitor::TaskMonitor	-- A task monitor for this task.
		
		Returns:
			ciphertext:Ciphertext	-- A ciphertext object encapsulating the 
									   encrypted data.		
		"""
		random = StrongRandom()
		
		## PART 1
		# First, format the bitstream as per Ciphertext.py Note 001,
		# previous to encryption.
		# 	[size (64 bits) | message (size bits) | padding (X bits) ]
		##
		formated_bitstream = BitStream()
		
		# The first 64 encode the size of the actual data in bits
		SIZE_BLOCK_LENGTH = 64
		size_in_bits = bitstream.get_length()
		
		if(size_in_bits >= 2**SIZE_BLOCK_LENGTH):
			raise ValueError("The size of the bitstream to encrypt is larger " \
							 "than 16 Exabits. The current format for  " \
							 "PloneVote ciphertext only allows encrypting a  " \
							 "maximum of 16 Exabits of information.")
		
		formated_bitstream.put_num(size_in_bits, SIZE_BLOCK_LENGTH)
		
		# We then copy the contents of the original bitstream
		bitstream.seek(0)
		formated_bitstream.put_bitstream_copy(bitstream)
		
		# Finally, we append random data until we reach the desired pad_to 
		# length
		unpadded_length = formated_bitstream.get_length()
		if(pad_to != None and (pad_to * 8) > unpadded_length):
			full_length = pad_to * 8
		else:
			full_length = unpadded_length
		
		padding_left = full_length - unpadded_length
		
		while(padding_left > 1024):
			padding_bits = random.randint(1, 2**1024)
			formated_bitstream.put_num(padding_bits,1024)
			padding_left -= 1024
		
		if(padding_left > 0):
			padding_bits = random.randint(1, 2**padding_left)
			formated_bitstream.put_num(padding_bits, padding_left)
			padding_left = 0
		
		## PART 2
		# We encrypt the formated bitsteam using ElGamal into a Ciphertext 
		# object.
		# See "Handbook of Applied Cryptography" Algorithm 8.18
		##
		
		# block_size is the size of each block of bits to encrypt
		# since we can only encrypt messages in [0, p - 1]
		# we should use (nbits - 1) as the block size, where 
		# 2**(nbits - 1) < p < 2**nbits
		
		block_size = self.cryptosystem.get_nbits() - 1
		prime = self.cryptosystem.get_prime()
		generator = self.cryptosystem.get_generator()
		
		# We pull data from the bitstream one block at a time and encrypt it
		formated_bitstream.seek(0)
		ciphertext = \
			Ciphertext(self.cryptosystem.get_nbits(), self.get_fingerprint())		
		
		plaintext_bits_left = formated_bitstream.get_length()
		
		# Check if we have a task monitor and register with it
		if(task_monitor != None):
			# We will do two tick()s per block to encrypt: one for generating 
			# the gamma component of the ciphertext block and another for the 
			# delta component (those are the two time intensive steps, 
			# because of exponentiation). 
			ticks = math.ceil((1.0 * plaintext_bits_left) / block_size) * 2
			encrypt_task_mon = \
				task_monitor.new_subtask("Encrypt data", expected_ticks = ticks)
		
		while(plaintext_bits_left > 0):
		
			# get next block (message, m, etc) to encrypt
			if(plaintext_bits_left >= block_size):
				block = formated_bitstream.get_num(block_size)
				plaintext_bits_left -= block_size
			else:
				block = formated_bitstream.get_num(plaintext_bits_left)
				# Encrypt as if the stream was filled with random data past its 
				# end, this avoids introducing a 0's gap during decryption to 
				# bitstream
				displacement = block_size - plaintext_bits_left
				block = block << displacement
				padding = random.randint(0, 2**displacement - 1)
				assert (padding / 2**displacement == 0), \
							"padding should be at most displacement bits long"
				block = block | padding
				plaintext_bits_left = 0
			
			# Select a random integer k, 1 <= k <= p − 2
			k = random.randint(1, prime - 2)
			
			# Compute gamma and delta
			gamma = pow(generator, k, prime)
			if(task_monitor != None): encrypt_task_mon.tick()
			
			delta = (block * pow(self._key, k, prime)) % prime
			if(task_monitor != None): encrypt_task_mon.tick()
			
			# Add this encrypted data portion to the ciphertext object
			ciphertext.append(gamma, delta)
		
		# return the ciphertext object
		return ciphertext
		
	
	def encrypt_text(self, text, pad_to=None, task_monitor=None):
		"""
		Encrypts the given string into a ciphertext object.
		
		Arguments:
			text::string			-- A string to encrypt.
			pad_to::int			-- Minimum size (in bytes) of the resulting 
								   ciphertext. Data will be padded before 
								   encryption to match this size.
			task_monitor::TaskMonitor	-- A task monitor for this task.
		
		Returns:
			ciphertext:Ciphertext	-- A ciphertext object encapsulating the 
									   encrypted data.
		"""
		bitstream = BitStream()
		bitstream.put_string(text)
		return self.encrypt_bitstream(bitstream, pad_to, task_monitor)
		
	def _to_xml(self):
		"""
		Returns an xml document containing a representation of this public key.
		
		Returns:
			doc::xml.dom.minidom.Document
		"""
		doc = xml.dom.minidom.Document()
		root_element = doc.createElement("PloneVotePublicKey")
		# This is a single public key, as opposed to a composite one
		root_element.setAttribute("type", "single")
		doc.appendChild(root_element)
		
		key_element = doc.createElement("PublicKey")
		key_str = hex(self._key)[2:]		# Remove leading '0x'
		if(key_str[-1] == 'L'): 
			key_str = key_str[0:-1]			# Remove trailing 'L'
		key_element.appendChild(doc.createTextNode(key_str))
		root_element.appendChild(key_element)
		
		cs_scheme_element = self.cryptosystem.to_dom_element(doc)
		root_element.appendChild(cs_scheme_element)
		
		return doc
		
	def to_file(self, filename):
		"""
		Saves this public key to a file.
		"""
		doc = self._to_xml()
		
		file_object = open(filename, "w")
		file_object.write(doc.toprettyxml())
		file_object.close()
		
	@classmethod
	def from_file(cls, filename):
		"""
		Loads a public key from file.
		"""
		doc = xml.dom.minidom.parse(filename)
		
		# Check root element
		if(len(doc.childNodes) != 1 or 
			doc.childNodes[0].nodeType != doc.childNodes[0].ELEMENT_NODE or
			doc.childNodes[0].localName != "PloneVotePublicKey"):
			
			raise InvalidPloneVoteCryptoFileError(filename, 
				"A PloneVoteCryptoLib stored public key file must be an " \
				"XML file with PloneVotePublicKey as its root element.")	
		
		root_element = doc.childNodes[0]
		
		# Verify that we are dealing with a single public key and not a 
		# composite one.
		type_attribute = root_element.getAttribute("type")
		if(type_attribute == "single"):
			pass		# this is the expected value, lets continue parsing
		elif(type_attribute == "composite"):
			# We load this file as a composite key instead!
			raise Exception("Not implemented: support for composite keys!")
		else:
			raise InvalidPloneVoteCryptoFileError(filename, 
				"Unknown public key type \"%d\". Valid public key types are " \
				"\"single\" and \"composite\".")
		
		cs_scheme_element = key_element = None
		
		# Retrieve individual "tier 2" nodes
		for node in root_element.childNodes:
			if node.nodeType == node.ELEMENT_NODE:
				if node.localName == "PublicKey":
					key_element = node
				elif node.localName == "CryptoSystemScheme":
					cs_scheme_element = node
					
		# Check CryptoSystemScheme node
		if(cs_scheme_element == None):
			raise InvalidPloneVoteCryptoFileError(filename, 
				"A PloneVoteCryptoLib stored public key file must contain " \
				"a CryptoSystemScheme element")
		
		# Parse the inner CryptoSystemScheme element using the parser defined
		# in EGStub
		(nbits, prime, generator) = \
					EGStub.parse_crytosystem_scheme_xml_node(cs_scheme_element)	
		
		# Check the actual key information
		if(key_element == None):
			raise InvalidPloneVoteCryptoFileError(filename, 
				"The PloneVoteCryptoLib stored public key file must contain " \
				"a <PublicKey> element, with the value of the public key " \
				" inside it.")
				
		if(len(key_element.childNodes) != 1 or 
			key_element.childNodes[0].nodeType != key_element.childNodes[0].TEXT_NODE):
			
			raise InvalidPloneVoteCryptoFileError(filename, 
				"The PloneVoteCryptoLib stored public key file must contain " \
				"a <PublicKey> element, with the value of the public key " \
				" inside it.")
		
		key_str = key_element.childNodes[0].data.strip()	# trim spaces
		key = int(key_str, 16)
		
		if(not (0 <= key < prime)):
			raise InvalidPloneVoteCryptoFileError(filename, 
				"The value of the public key given in the file is invalid " \
				"for the indicated cryptosystem (could the file be corrupt?).")
		
		# Construct the cryptosystem object
		cryptosystem = EGCryptoSystem.load(nbits, prime, generator)
		
		# Construct and return the PublicKey object
		return cls(cryptosystem, key)
