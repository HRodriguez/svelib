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
		
	def encrypt_bytes(self, byte_array, pad_to=None, task_monitor=None):
		"""
		Encrypts the given array of bytes into a ciphertext object.
		
		Arguments:
			byte_array::byte[]	-- An array of bytes to encrypt.
			pad_to::int			-- Minimum size (in bytes) of the resulting 
								   ciphertext. Data will be padded before 
								   encryption to match this size.
			task_monitor::TaskMonitor	-- A task monitor for this task.
		
		Returns:
			ciphertext:Ciphertext	-- A ciphertext object encapsulating the 
									   encrypted data.
		
		See "Handbook of Applied Cryptography" Algorithm 8.18
		"""
		random = StrongRandom()
		
		# With a nbits long prime, we actually can only encrypt with certainty 
		# (nbits - 1) of data (for most schemes, this will mean as much as a 
		# byte per block going unused).
		key_size_bytes = (self.cryptosystem.get_nbits() - 1) / 8 
		
		# Create pre-encryption format byte array (see Ciphertext.py, Note 001)
		# [size in bytes][message][padding]
		
		# Size without padding
		message_size_bytes = len(byte_array)
		data_size_bytes = _MESSAGE_SIZE_SPACE + message_size_bytes
		
		if(message_size_bytes > _MAX_MESSAGE_SIZE):
			raise MessageToLongError()
		
		# Size with padding
		if(pad_to != None and (data_size_bytes < pad_to)):
			data_size_bytes = pad_to
		
		# Adjust to block boundaries
		if(data_size_bytes % key_size_bytes != 0):
			data_size_bytes += key_size_bytes - (data_size_bytes % key_size_bytes)
		
		assert data_size_bytes % key_size_bytes == 0, "Data size should had been adjusted to be a multiple of the cryptosystem key/block size."
		
		# Copy the byte array to the structured format
		data_bytes = bytearray(data_size_bytes)
		
		#	Copy the size in the first 8 bytes
		m_size = message_size_bytes
		i = _MESSAGE_SIZE_SPACE
		while(m_size != 0):
			i -= 1
			assert i >= 0, "The size of the message cannot exceed 16 Exabytes, yet it somehow didn't fit in a 8 byte word (!)."
			data_bytes[i] = m_size % 256	# last 8 bits
			m_size >> 8
		
		#   Copy the message
		pos = _MESSAGE_SIZE_SPACE
		data_bytes[pos:(message_size_bytes + pos)]
		pos += message_size_bytes
		
		#	Pad
		# 	   Pad with long words
		l_word_max = 2**64
		while(pos + 8 < data_size_bytes):
			random_long_word = random.randint(1, l_word_max)
			for i in range(0, 8):
				data_bytes[pos + i] = random_long_word % 256	# last 8 bits
				random_long_word >> 8
			
		#	   Pad byte by byte
		random_long_word = random.randint(1, l_word_max)
		for i in range(0, data_size_bytes - pos):
			data_bytes[pos + i] = random_long_word % 256	# last 8 bits
			random_long_word >> 8
		
		# ToDo: TEMP, add actual encryption !!!	
		return data_bytes
				
	
	def encrypt_text(self, text, task_monitor=None):
		"""
		Encrypts the given string into a ciphertext object.
		
		Arguments:
			text::string			-- A string to encrypt.
			task_monitor::TaskMonitor	-- A task monitor for this task.
		
		Returns:
			ciphertext:Ciphertext	-- A ciphertext object encapsulating the 
									   encrypted data.
		"""
		pass
		
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
	
