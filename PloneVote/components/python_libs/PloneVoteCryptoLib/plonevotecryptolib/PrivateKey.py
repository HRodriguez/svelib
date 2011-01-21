# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  PublicKey.py : The private key class.
#
#  Used for data decryption.
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

from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem
from plonevotecryptolib.Ciphertext import Ciphertext
from plonevotecryptolib.utilities.BitStream import BitStream

class PrivateKey:
	"""
	An ElGamal private key object used for decryption.
	
	Attributes:
		cryptosystem::EGCryptoSystem	-- The ElGamal cryptosystem in which 
										   this key is defined.
		public_key::PublicKey	-- The associated public key.
	"""
	
	cryptosystem = None
	public_key = None
	
	def __init__(self, cryptosystem, public_key, private_key_value):
		"""
		Creates a new private key. Should not be invoked directly.
		
		Instead of using this constructor from outside of PloneVoteCryptoLib, 
		please use the class methods KeyPair.new() or 
		PrivateKey.from_file(file).
		
		Arguments:
			cryptosystem::EGCryptoSystem-- The ElGamal cryptosystem in which 
										   this key is defined.
			public_key::PublicKey		-- The associated public key.
			private_key_value::long		-- The actual value of the private key.
		"""
		self.cryptosystem = cryptosystem
		self.public_key = public_key
		self._key = private_key_value
		
	def decrypt_to_bitstream(self, ciphertext):
		"""
		Decrypts the given ciphertext into a bitstream.
		
		If the bitstream was originally encrypted with PublicKey.encrypt_X(), 
		then this method returns a bitstream following the format described 
		in Note 001 of the Ciphertext.py file:
			[size (64 bits) | message (size bits) | padding (X bits) ]
		
		Arguments:
			ciphertext::Ciphertext	-- An encrypted Ciphertext object
		
		Returns:
			bitstream::Bitstream	-- A bitstream containing the unencrypted 
									   data.
		"""
		# TODO: possible check that the ciphertext is compatible with the 
		# cryptosystem and public key corresponding to this private key
		# (use a hash? or the full info?)
		
		# We read and decrypt the ciphertext block by block
		# See "Handbook of Applied Cryptography" Algorithm 8.18
		bitstream = BitStream()
		
		block_size = self.cryptosystem.get_nbits() - 1
		prime = self.cryptosystem.get_prime()
		key = self._key
		
		for gamma, delta in ciphertext:
			assert max(gamma, delta) < 2**(block_size + 1), "The ciphertext object includes blocks larger than the expected block size."
			m = (pow(gamma, prime - 1 - key, prime) * delta) % prime
			bitstream.put_num(m, block_size)
			
		return bitstream
			
	
	def decrypt_to_text(self, ciphertext):
		"""
		Decrypts the given ciphertext into its text contents as a string
		
		This method assumes that the ciphertext contains an encrypted stream of 
		data in the format of Note 001 of the Ciphertext.py file, were message 
		contains string information (as opposed to a binary format).
			[size (64 bits) | message (size bits) | padding (X bits) ]
		
		Arguments:
			ciphertext::Ciphertext	-- An encrypted Ciphertext object, 
									   containing data in the above format.
		
		Returns:
			string::string	-- Decrypted "message" as a string.
		"""
		bitstream = self.decrypt_to_bitstream(ciphertext)
		bitstream.seek(0)
		length = bitstream.get_num(64)
		return bitstream.get_string(length)
		
	def to_file(self, filename):
		"""
		Saves this private key to a file.
		"""
		pass
		
	@classmethod
	def from_file(self, filename):
		"""
		Loads a private key from file.
		"""
		pass
