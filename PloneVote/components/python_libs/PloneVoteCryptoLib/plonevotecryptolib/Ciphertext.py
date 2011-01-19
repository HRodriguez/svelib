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
# - The next $size bytes are the original data to be encrypted.
# - The rest of the array contains random padding.
#
#	[size (64 bytes) | message (size bytes) | padding (X bytes) ]
#
# Note that this limits messages to be encrypted to 16 Exabytes. 
# We deem this enough for our purposes (in fact, votes larger than a couple MB 
# are highly unlikely, and system memory is probably going to be a more  
# immediate problem).
#
##

class Ciphertext:
	"""
	An object representing encrypted PloneVote data.
	
	Ciphertext objects are created by PublicKey encrypt operations and 
	decrypted through PrivateKey methods (or CombinedPublicKey if the data was 
	encrypted with a combined key and all partial decryptions are available).
	
	This class can also be store to and loaded from file using the PloneVote 
	armored ciphertext XML format.
	"""
	
	# This attributes should only be accessed by key classes within 
	# PloneVoteCryptoLib
	# See "Handbook of Applied Cryptography" Algorithm 8.18 for the meaning of 
	# the variables. An array is used because the encrypted data might be 
	# longer than the cryptosystem's bit size.
	gamma = []
	delta = []
	
	def __init__(self):
		"""
		Create an empty ciphertext object.
		"""
		self.gamma = []
		self.delta = []
	
	def append(self, gamma, delta):
		"""
		Used internally by PublicKey.
		
		This method adds an encrypted block of data with its gamma and delta 
		components from ElGamal (see HoAC Alg. 8.18). 
		"""	
		self.gamma.append(gamma)
		self.delta.append(delta)
