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
		
	def decrypt_to_bytes(self, ciphertext):
		"""
		"""
		pass
	
	def decrypt_to_text(self, ciphertext):
		"""
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
		Loads a private key from file.
		"""
		pass
