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

from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem

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
		
	def encrypt_bytes(self, byte_array):
		"""
		"""
		pass
	
	def encrypt_text(self, text):
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
		Loads a public key from file.
		"""
		pass
	
