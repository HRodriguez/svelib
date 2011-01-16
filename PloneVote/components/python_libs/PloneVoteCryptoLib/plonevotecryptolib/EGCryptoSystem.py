# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  EGCryptoSystem.py : Basic cryptosystem class.
#
#  Used for creating and storing instances of an ElGamal cryptosystem.
#
#  Part of the PloneVote cryptographic library (PloneVoteCryptoLib)
#
#  Originally written by: Lazaro Clapp
#
#  Based on ElGamal.py from the Python Cryptography Toolkit, version 2.3
#  by A.M. Kuchling.
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



# ============================================================================
# Imports and constant definitions:
# ============================================================================

# We use pycrypto (>= 2.1.0) to generate probable primes (pseudo-primes that 
# are real primes with a high probability) and cryptographically secure random 
# numbers. Note that pycrypto < 2.1.0 uses a different (ostensibly broken) 
# random  number generator, which can't be used by PloneVoteCryptoLib.
#
# We do not directly use Crypto.PublicKey.ElGamal, because doing so would 
# require relying on methods that are not part of pycrypto's public API, and 
# thus subject to change. We need a lot of data about the internals of our
# ElGamal cryptosystem in order to implement: verification, mixing, 
# threshold-encryption, etc. This is not all publicly exposed by pycrypto. 
#
# Thus, we duplicate some of the code from ElGamal.py.

import Crypto.Util.number
# secure version of python's random:
from Crypto.Random.random import StrongRandom


# Use configuration parameters from params.py
import params

# Use some PloneVoteCryptoLib exceptions
from PVCExceptions import KeyLengthTooLowError
# ============================================================================



# ============================================================================
# Helper functions:
# ============================================================================
def _generate_safe_prime(Nbits):
		"""
		Generate a safe prime of size Nbits.
		
		A safe prime is one of the form p = 2q + 1, where q is also a prime. 
		The prime p used for ElGamal must be a safe prime, otherwise some 
		attacks that rely on factoring the order p - 1 of the cyclic group 
		Z_{p}^{*} may become feasible if p - 1 does not have a large prime 
		factor. (p = 2q + 1, means p - 1 = 2q, which has a large prime factor,
		namely q)
		
		Arguments:
			Nbits::int	-- Bit size of the safe prime p to generate. 
						   This private method assumes that the
						   Nbits parameter has already been checked to satisfy 
						   all necessary security conditions.
		
		Returns:
			p::long		-- A safe prime.
		"""
		found = False
		
		# We generate (probable) primes q of size (Nbits - 1) 
		# until p = 2*q + 1 is also a prime
		while(not found):
			q = Crypto.Util.number.getPrime(Nbits - 1)
			p = 2*q + 1
			
			if(not Crypto.Util.number.isPrime(p, 
						false_positive_prob=params.FALSE_PRIME_PROBABILITY)):
				continue
				
			# Are we sure about q, though? (pycrypto may allow a higher 
			# probability of q being composite than what we might like)
			if(not Crypto.Util.number.isPrime(q, 
						false_positive_prob=params.FALSE_PRIME_PROBABILITY)):
				continue
			
			found = True
			
		# DEBUG CHECK: The prime p must be of size n=Nbits, that is, in 
		# [2**(n-1),2**n] (and q must be of size Nbits - 1)
		if(params.DEBUG):
			assert 2**(Nbits - 1) < p < 2**(Nbits), \
					"p is not an Nbits prime."
			assert 2**(Nbits - 2) < q < 2**(Nbits - 1), \
					"q is not an (Nbits - 1) prime"
					
		return p


def _get_generator(p):
		"""
		Returns the generator of the Z_{p}^{*} cyclic group.
		
		This method makes two assumptions about p:
			1) p is prime
			2) p = 2q + 1 such that q is prime 
			(i.e. p is a safe prime)
		
		Since p is prime, Z_{p}^{*} is a cyclic group of order p - 1. 
		
		We seek a generator of the group, that is, an element g, such that 
		g^{p-1} = g^{2q} = 1 mod p, and g^{i} != 1 mod p \\forall i < (p-1).
		
		Algorithm explanation:
		
		a^{p-1} = 1 mod p by Euler's theorem and the fact that p is prime.
		
		For any a, if a^{i} = 1 mod p, then a generates a cyclic subgroup 
		of Z_{p}^{*} of order i. By Lagrange's theorem, the order of a (finite) 
		subgroup must divide the order of the group. Thus:
		
		a^{i} = 1 mod p => i | (p - 1)
		
		Since p - 1 = 2q, we need only check that a^{2} != 1 mod p and 
		a^{q} != mod p, since only 2 or q divide p - 1, the order of Z_{p}^{*}. 
		Should both those conditions be true, a must be a generator of Z_{p}^{*}.
		
		We can then generate random a's and perform those two tests until we 
		find a generator.
		
		References: I.N. Herstein pg. 35, 
					"Handbook of Applied Cryptography" Algorithm 4.80
		
		Arguments:
			p::long	-- A safe prime.
		
		Returns:
			g::long	-- A generator of Z_{p}^{*}
		"""
		q = (p - 1) / 2		# Since p = 2q + 1
		
		random = StrongRandom()
		
		found = False
		while(not found):
			candidate = random.randint(1, p - 1)
			if(pow(candidate, 2, p) == 1):
				continue
			if(pow(candidate, q, p) == 1):
				continue
			found = True
		
		if(params.DEBUG):
			assert pow(candidate, 2*q, p) == 1, \
				   "generator^{p-1} != 1 mod p (!) see method's " \
				   "algorithm explanation."
		
		return candidate # this is the generator
		
	
# ============================================================================		



# ============================================================================
# Classes
# ============================================================================
class EGCryptoSystem:
	"""
	A particular cryptosystem used for PloneVote.
	
	EGCryptoSystem represents a particular instance of an ElGamal cryptosystem 
	up to the selection of of a Z_{p}^{*} group and its corresponding generator.
	
	This class is used to instantiate compatible (private + public) key pairs. 
	That is, key pairs in which the public keys can be merged into one combined 
	public key of a threshold-encryption scheme.
	
	The crypto system used also determines the cryptographic strength of the 
	generated keys, by specifying the bit size used for all keys (aka. the 
	length of the prime p or, equivalently, the cardinality of the cyclic group)
	.
	
	USAGE: (ToDo)
	"""
	
	_nbits = None
	_prime = None
	_generator = None	
	
	
	def get_nbits(self):
		"""
		Return the number of bits used for the key size by this ElGamal instance.
		"""
		return self._nbits	
	
	
	def get_prime(self):
		"""
		Return the prime p used for the key size by this ElGamal instance.
		"""
		return self._prime	
	
	
	def get_generator(self):
		"""
		Return the generator used for the key size by this ElGamal instance.
		
		The generator of the Z_{p}^{*} cyclic group, where p is the same as in 
		self.get_prime().
		"""
		return self._generator
		
	
	def __init__(self, Nbits=params.DEFAULT_KEY_SIZE):
		"""
		Construct a new EGCryptoSystem object with an specific bit size.
		
		This generates a prime, cyclic group and generator for the ElGamal 
		cryptographic scheme, given the desired length in bits of the prime. 
		If the bit size is not given, a default is used which depends upon the 
		PloneVoteCryptoLib configuration in params.py (mainly SECURITY_LEVEL, 
		but can be override by setting CUSTOM_DEFAULT_KEY_SIZE).
		
		Arguments:
			Nbits::int	-- (optional) Bit size of the prime to use for the 
						   ElGamal scheme. Higher is safer but slower.
						   Defaults to params.DEFAULT_KEY_SIZE.		   
		"""
		
		# Check that the key size meets the minimum key size requirements
		if(Nbits < params.MINIMUM_KEY_SIZE):
		
			# Throw an exception w/ an appropriate message if Nbits is too small
			raise KeyLengthTooLowError(Nbits, params.MINIMUM_KEY_SIZE, 
				"The given size in bits for the cryptosystem (%d bits) is too" \
				" low. For security reasons, current minimum allowed key/" \
				"cryptosystem bit size is %d bits. It is recommended that " \
				" only keys of that length or higher are generated or used. " \
				" If you must use smaller keys, you may configure " \
				"PloneVoteCryptoLib's security parameters in params.py at " \
				"your own risk." % (Nbits, params.MINIMUM_KEY_SIZE))
				
		# Check that the key size is can be expressed as whole bytes (i.e. is
		# a multiple of 8)
		if(Nbits % 8 != 0):
			raise KeyLengthNonBytableError(Nbits,
				"The given size in bits for the cryptosystem (%d bits) is " \
				"not a multiple of eight. Currently, only key sizes that are " \
				"multiples of eight, and thus expressible in whole bytes, " \
				"are allowed by PloneVoteCryptoLib. Perhaps you could use %d " \
				"bit keys?" % (Nbits, (Nbits/8 + 1)*8) )
		
		# Accept the key size
		self._nbits = Nbits
		
		# Generate a safe (pseudo-)prime of size _nbits
		self._prime = _generate_safe_prime(self._nbits)
			
		# Now we need the generator for the Z_{p}^{*} cyclic group
		self._generator = _get_generator(self._prime)


# ============================================================================
