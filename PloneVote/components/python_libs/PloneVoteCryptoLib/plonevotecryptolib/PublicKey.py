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

# secure version of python's random:
from Crypto.Random.random import StrongRandom

from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem
from plonevotecryptolib.Ciphertext import Ciphertext
from plonevotecryptolib.utilities.BitStream import BitStream

_MESSAGE_SIZE_SPACE = 8 # (see Ciphertext, Note 001)
_MAX_MESSAGE_SIZE = 2**(_MESSAGE_SIZE_SPACE*8)

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
		size_in_bits = bitstream.get_length()
		
		if(size_in_bits >= 2**64):
			raise ValueError("The size of the bitstream to encrypt is larger " \
							 "than 16 Exabits. The current format for  " \
							 "PloneVote ciphertext only allows encrypting a  " \
							 "maximum of 16 Exabits of information.")
		
		formated_bitstream.put_num(size_in_bits, 64)
		
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
		ciphertext = Ciphertext()
		
		plaintext_bits_left = formated_bitstream.get_length()
		while(plaintext_bits_left > 0):
			
			# get next block (message, m, etc) to encrypt
			if(plaintext_bits_left >= block_size):
				block = formated_bitstream.get_num(block_size)
				plaintext_bits_left -= block_size
			else:
				block = formated_bitstream.get_num(plaintext_bits_left)
				plaintext_bits_left = 0
			
			# Select a random integer k, 1 <= k <= p − 2
			k = random.randint(1, prime - 2)
			
			# Compute gamma and delta
			gamma = pow(generator, k, prime)
			delta = (block * pow(self._key, k, prime)) % prime
			
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
		
	def to_file(self, filename):
		"""
		Saves this private key to a file.
		"""
		pass
		
	@classmethod
	def from_file(self, filename):
		"""
		Loads a public key from file.
		"""
		pass
	
