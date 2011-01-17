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
def _is_safe_prime(p):
		"""
		Test if the number p is a safe prime.
		
		A safe prime is one of the form p = 2q + 1, where q is also a prime.
		
		Arguments:
			p::long	-- Any integer.
		
		Returns:
			True	if p is a safe prime
			False	otherwise
		"""
		# Get q (p must be odd)
		if(p % 2 == 0): 
			return False
		
		q = (p - 1)/2
		
		prob = params.FALSE_PRIME_PROBABILITY
		return (Crypto.Util.number.isPrime(q, false_positive_prob=prob) and 	# q first to shortcut the most common False case
				Crypto.Util.number.isPrime(p, false_positive_prob=prob))
				

def _generate_safe_prime(nbits):
		"""
		Generate a safe prime of size nbits.
		
		A safe prime is one of the form p = 2q + 1, where q is also a prime. 
		The prime p used for ElGamal must be a safe prime, otherwise some 
		attacks that rely on factoring the order p - 1 of the cyclic group 
		Z_{p}^{*} may become feasible if p - 1 does not have a large prime 
		factor. (p = 2q + 1, means p - 1 = 2q, which has a large prime factor,
		namely q)
		
		Arguments:
			nbits::int	-- Bit size of the safe prime p to generate. 
						   This private method assumes that the
						   nbits parameter has already been checked to satisfy 
						   all necessary security conditions.
		
		Returns:
			p::long		-- A safe prime.
		"""
		found = False
		
		# We generate (probable) primes q of size (nbits - 1) 
		# until p = 2*q + 1 is also a prime
		while(not found):
			q = Crypto.Util.number.getPrime(nbits - 1)
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
			
		# DEBUG CHECK: The prime p must be of size n=nbits, that is, in 
		# [2**(n-1),2**n] (and q must be of size nbits - 1)
		if(params.DEBUG):
			assert 2**(nbits - 1) < p < 2**(nbits), \
					"p is not an nbits prime."
			assert 2**(nbits - 2) < q < 2**(nbits - 1), \
					"q is not an (nbits - 1) prime"
					
		return p


def _is_generator(p, g):
		"""
		Checks whether g is a generator of the Z_{p}^{*} cyclic group.
		
		This function makes two assumptions about p:
			1) p is prime
			2) p = 2q + 1 such that q is prime 
			(i.e. p is a safe prime)
		
		Since p is prime, Z_{p}^{*} is a cyclic group of order p - 1. 
		
		We ask whether g is a generator of the group, that is, whether
		g^{p-1} = g^{2q} = 1 mod p, and g^{i} != 1 mod p \\forall i < (p-1).
		
		Algorithm explanation:
		
		g^{p-1} = 1 mod p \\forall g, by Euler's theorem and the fact that p is 
		prime.
		
		For any g, if g^{i} = 1 mod p, then g generates a cyclic subgroup 
		of Z_{p}^{*} of order i. By Lagrange's theorem, the order of a (finite) 
		subgroup must divide the order of the group. Thus:
		
		g^{i} = 1 mod p => i | (p - 1)
		
		Since p - 1 = 2q, we need only check that g^{2} != 1 mod p and 
		g^{q} != mod p, since only 2 or q divide p - 1, the order of Z_{p}^{*}. 
		Should both those conditions be true, g must be a generator of Z_{p}^{*}.
		
		References: I.N. Herstein pg. 35, 
					"Handbook of Applied Cryptography" Algorithm 4.80
		
		Arguments:
			p::long	-- A safe prime.
			g::long	-- An element in Z_{p}^{*}
		
		Returns:
			True	if g is a generator of Z_{p}^{*}
			False	otherwise
		"""
		if(params.DEBUG):
			assert 1 <= g <= (p - 1), "g must be an element in Z_{p}^{*}."
		
		q = (p - 1) / 2		# Since p = 2q + 1
		if(pow(g, 2, p) == 1):
			return False
		elif(pow(g, q, p) == 1):
			return False
		else:
			return True


def _get_generator(p):
		"""
		Returns the generator of the Z_{p}^{*} cyclic group.
		
		We take random numbers in Z_{p}^{*} = [0, ..., p - 1], until one of  
		them is a generator for the group. This function assumes that p is a 
		safe prime (p = 2q + 1 with both p and q prime).
		
		See the documentation for _is_generator(p, g) for more information 
		about testing whether a number is a generator of Z_{p}^{*}.
		
		Arguments:
			p::long	-- A safe prime.
		
		Returns:
			g::long	-- A generator of Z_{p}^{*}
		"""		
		random = StrongRandom()
		candidate = random.randint(1, p - 1)
		
		while(not _is_generator(p, candidate)):
			candidate = random.randint(1, p - 1)
		
		if(params.DEBUG):
			assert pow(candidate, p - 1, p) == 1, \
				   "generator^{p-1} != 1 mod p (!) see method's " \
				   "algorithm explanation."
		
		return candidate # this is the generator
		
	
# ============================================================================		



# ============================================================================
# Classes
# ============================================================================
class EGCSUnconstructedStateError(Exception):
	"""
	Raised when an EGCryptoSystem instance is improperly constructed and used.
	
	This exception is raised when an EGCryptoSystem instance that was not 
	properly constructed is accessed.
	
	EGCryptoSystem may not be constructed through the __init__ constructor. It 
	must be created through one of its factory class methods, such as new() or
	load(nbits, prime, generator).
	"""

	def __init__(self):
		"""
		Create a new EGCSUnconstructedStateError exception.
		"""
		self.msg = "Attempted to use an improperly constructed cryptosystem. " \
        		   "EGCryptoSystem objects must be obtained through the " \
        		   "class' factory methods, such as new() or load(nbits, " \
        		   "prime, generator)."
	

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
	
	EGCryptoSystem may not be constructed through the __init__ constructor. It 
	must be created through one of its factory class methods, such as new() or
	load(nbits, prime, generator).
	
	USAGE: (ToDo)
	"""
	
	_nbits = None
	_prime = None
	_generator = None
	
	_constructed = False;
	
	
	def get_nbits(self):
		"""
		Return the number of bits used for the key size by this ElGamal instance.
		"""
		if(not self._constructed): raise EGCSUnconstructedStateError()
		return self._nbits	
	
	
	def get_prime(self):
		"""
		Return the prime p used for the key size by this ElGamal instance.
		"""
		if(not self._constructed): raise EGCSUnconstructedStateError()
		return self._prime	
	
	
	def get_generator(self):
		"""
		Return the generator used for the key size by this ElGamal instance.
		
		The generator of the Z_{p}^{*} cyclic group, where p is the same as in 
		self.get_prime().
		"""
		if(not self._constructed): raise EGCSUnconstructedStateError()
		return self._generator
		
	
	@classmethod	
	def _verify_key_size(cls, nbits):
		"""
		Checks that nbits is a valid key size.
		
		This method verifies that nbits is longer than params.MINIMUM_KEY_SIZE 
		and expressible in bytes (nbits is a multiple of eight), and throws 
		an exception otherwise.
		
		Arguments:
			nbits::int	-- The key size to test
		
		Returns:
			nbits::int	-- The same key size, if it passes the tests
			
	    Throws:
	    	KeyLengthTooLowError	-- If nbits is smaller than 
	    							   params.MINIMUM_KEY_SIZE.
	    	KeyLengthNonBytableError -- If nbits is not a multiple of 8.
		"""
		# Check that the key size meets the minimum key size requirements
		if(nbits < params.MINIMUM_KEY_SIZE):
		
			# Throw an exception w/ an appropriate message if nbits is too small
			raise KeyLengthTooLowError(nbits, params.MINIMUM_KEY_SIZE, 
				"The given size in bits for the cryptosystem (%d bits) is too" \
				" low. For security reasons, current minimum allowed key/" \
				"cryptosystem bit size is %d bits. It is recommended that " \
				" only keys of that length or higher are generated or used. " \
				" If you must use smaller keys, you may configure " \
				"PloneVoteCryptoLib's security parameters in params.py at " \
				"your own risk." % (nbits, params.MINIMUM_KEY_SIZE))
				
		# Check that the key size is can be expressed as whole bytes (i.e. is
		# a multiple of 8)
		if(nbits % 8 != 0):
		
			raise KeyLengthNonBytableError(nbits,
				"The given size in bits for the cryptosystem (%d bits) is " \
				"not a multiple of eight. Currently, only key sizes that are " \
				"multiples of eight, and thus expressible in whole bytes, " \
				"are allowed by PloneVoteCryptoLib. Perhaps you could use %d " \
				"bit keys?" % (nbits, (nbits/8 + 1)*8) )
				
		return nbits

	
	def __init__(self):
		"""
		DO NOT USE THIS CONSTRUCTOR
		
		This constructor should never be used directly. Instead, the following 
		factory methods should be considered:
		
			new()				-- Generates a new EGCryptoSystem with the 
								   default security
			new(nbits::int)		-- Generates a new EGCryptoSystem with key size
								   nbits
			load(nbits::int, 
				prime::int, 
				generator::int) -- Loads an EGCryptoSystem with key size nbits, 
								   prime p and generator g. Verifies parameters.
		"""
		pass
		
	
	@classmethod
	def new(cls, nbits=params.DEFAULT_KEY_SIZE):
		"""
		Construct a new EGCryptoSystem object with an specific bit size.
		
		This generates a prime, cyclic group and generator for the ElGamal 
		cryptographic scheme, given the desired length in bits of the prime. 
		If the bit size is not given, a default is used which depends upon the 
		PloneVoteCryptoLib configuration in params.py (mainly SECURITY_LEVEL, 
		but can be override by setting CUSTOM_DEFAULT_KEY_SIZE).
		
		Arguments:
			nbits::int	-- (optional) Bit size of the prime to use for the 
						   ElGamal scheme. Higher is safer but slower.
						   Must be a multiple of eight (ie. expressible in bytes).
						   Defaults to params.DEFAULT_KEY_SIZE.
	    Throws:
	    	KeyLengthTooLowError	-- If nbits is smaller than 
	    							   params.MINIMUM_KEY_SIZE.
	    	KeyLengthNonBytableError -- If nbits is not a multiple of 8.
		"""
		# Call empty class constructor
		cryptosystem = cls()
		
		# Verify the key size
		cryptosystem._nbits = cls._verify_key_size(nbits)
		
		# Generate a safe (pseudo-)prime of size _nbits
		cryptosystem._prime = _generate_safe_prime(cryptosystem._nbits)
			
		# Now we need the generator for the Z_{p}^{*} cyclic group
		cryptosystem._generator = _get_generator(cryptosystem._prime)
		
		# Mark the object as constructed
		cryptosystem._constructed = True
		
		# Return the EGCryptoSystem instance
		return cryptosystem
		
	
	@classmethod
	def load(cls, nbits, prime, generator):
		"""
		Construct an EGCryptoSystem object with pre-generated parameters.
		
		This method returns a new ElGamal cryptosystem with the given bit size, 
		safe prime and generator. All three arguments are tested before the 
		cryptosystem is constructed.
		
		This constructor is intended for loading pre-generated cryptosystems, 
		such as those stored as files via EGStub.
		
		Arguments:
			nbits::int	-- Bit size of the prime to use for the ElGamal scheme. 
						   Must be a multiple of eight (ie. expressible in bytes).
			prime::long -- A nbits-long safe prime 
						   (that is (prime-1)/2 is also prime).
			generator:long -- A generator of the Z_{p}^{*} cyclic group.
		"""
		
		# Call empty class constructor
		cryptosystem = cls()
		
		# Verify the key size
		cryptosystem._nbits = cls._verify_key_size(nbits)
		
		# Verify that prime is a safe prime
		if(_is_safe_prime(prime)):
			cryptosystem._prime = prime
		else:
			raise NotASafePrimeError(prime,
				"The number given as prime p for the ElGamal cryptosystem " \
				"is not a safe prime.")
			
		# Verify the generator
		if(_is_generator(prime, generator)):
			cryptosystem._generator = generator
		else:
			raise NotAGeneratorError(prime, num,
				"The number given as generator g for the ElGamal cryptosystem " \
				"is not a generator of Z_{p}^{*}.")
		
		# Mark the object as constructed
		cryptosystem._constructed = True
		
		# Return the EGCryptoSystem instance
		return cryptosystem


# ============================================================================
