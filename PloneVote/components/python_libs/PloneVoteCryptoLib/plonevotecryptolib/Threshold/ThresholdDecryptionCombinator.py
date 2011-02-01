# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  ThresholdDecryptionCombinator.py : 
#  An auxiliary class used for combining partial decryptions.
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

# ============================================================================
# Imports and constant definitions:
# ============================================================================

# Non crypto secure random, used only for shuffling lists of partial decryptions
import random
# Configurable precision rationals:
import decimal

from plonevotecryptolib.utilities.BitStream import BitStream

__all__ = ["ThresholdDecryptionCombinator", 
		   "InsuficientPartialDecryptionsError"]

# ============================================================================

# ============================================================================
# Helper classes and functions:
# ============================================================================

class FractionTuple:
	"""
	A simple "tuple" with named attributes, used to represent a fraction.
	
	This doesn't support any fraction operations, just retrieving the numerator 
	and denominator.
	
	Attributes:
		numerator::int		-- The fraction's numerator.
		denominator::int	-- The fraction's denominator.
	"""
	
	def _gcd(self, a, b):
		if a < 0: a *= -1
		if b < 0: b *= -1
		
		if (a < b):
		    a, b = b, a
		while b != 0:
		    a, b = b, a%b
		return a
	
	def __init__(self, numerator, denominator):
		"""
		Constructs a new fraction tuple.
		
		Arguments:
			(see class attributes)
		"""
		if(denominator == 0):
			raise ValueError("The denominator of a fraction must not be 0.")
		if(numerator % 1 != 0 or denominator % 1 != 0):
			raise ValueError("The denominator and numerator of a fraction " \
							 "must be integer numbers.")
		
		gcd = self._gcd(numerator, denominator)
		self.numerator = numerator / gcd
		self.denominator = denominator / gcd
		if(self.denominator < 0):
			self.numerator *= -1
			self.denominator *= -1
		


def _lagrange_coefficient(indexes, i, x):
	"""
	Returns the Lagrange Coefficient for index i and value x in the given list 
	of indexes.
	
	The coefficient is returned in fraction form.
	
	LaTeX definition of the Lagrange Coefficient:
		$\lambda_{i}(x)=\prod_{j\in Indexes-\{i\}}\frac{x-j}{i-j}$
	
	See: http://en.wikipedia.org/wiki/Polynomial_interpolation
	
	Arguments:
		indexes::int[]	-- The valid indexes for the Lagrange Coefficient, 
						   which are the same as the x-coordinates at which we 
						   know the value of the polynomial for interpolation.
		i::int			-- Index of the Lagrange Coefficient we want.
		x::int			-- x-coordinate at which we wish to interpolate the 
						   value of the polynomial.
	
	Returns:
		lagrange_coeff::FractionTuple	-- Lagrange Coefficient as a 
										   fraction.
	"""
	numerator = 1
	denominator = 1
	
	for j in indexes:
		if(i == j):
			continue
		numerator *= (x - j)
		denominator *= (i - j)
		
	return FractionTuple(numerator, denominator)


def _decimal_nth_root(num, n):
	"""
	Takes the nth root of a given Decimal configurable precision rational.
	
	Note: The root is taken with a precision of decimal.getcontext().prec.
	
	Adapted from:
		http://www.programmish.com/?p=24
	Algorithm:
		http://en.wikipedia.org/wiki/Nth_root_algorithm
	
	Arguments:
		num::Decimal	-- The number of which we wish to obtain the nth root.
		n::int			-- n as in "the nth root"
	
	Returns:
		num**(1/n) with precision decimal.getcontext().prec.
	"""
	assert type(num) == type(decimal.Decimal(0)), "num must be a Decimal."
	
	oneOverN = 1 / decimal.Decimal(n)
	nMinusOne = decimal.Decimal(n) - 1
	
	# Initial guess
	curVal = decimal.Decimal(num) / (decimal.Decimal(n) ** 2)
	if curVal <= decimal.Decimal("1.0"):
		curVal = decimal.Decimal("1.1")
	lastVal = decimal.Decimal(0)
	
	# Note that this comparison is done with precision 
	# decimal.getcontext().prec.
	while lastVal != curVal:
		lastVal = curVal
		curVal = oneOverN * ( (nMinusOne * curVal) + (num / (curVal ** (n-1))))
	return curVal

	
def	_round_decimal_to_int(dec):
	"""
	Takes a Decimal rational number and returns the closest integer.
	
	Note that we need this function, because int(Decimal) truncates instead of 
	rounding and round() doesn't seem to work properly on Decimal objects.
	
	Arguments:
		dec::Decimal	-- Any rational
	
	Returns:
		result::int		-- The closest int to dec
	"""
	one_half = decimal.Decimal(1) / decimal.Decimal(2)
	if(dec % 1 > one_half):
		return int(dec) + 1
	else:
		return int(dec)

# ============================================================================

# ============================================================================
# Exceptions:
# ============================================================================

class InsuficientPartialDecryptionsError(Exception):
	"""
	Raised when ThresholdDecryptionCombinator.decrypt_to_X is called before at 
	least threshold partial decryptions have been registered with the 
	ThresholdDecryptionCombinator.
	"""
    
	def __str__(self):
		return self.msg

	def __init__(self, msg):
		"""
		Create a new InsuficientPartialDecryptionsError exception.
		"""
		self.msg = msg

# ============================================================================

# ============================================================================
# Core class (ThresholdDecryptionCombinator):
# ============================================================================
	
class ThresholdDecryptionCombinator:
	"""
	Used for combining partial decryptions into a full decryption.
	
	Accepts threshold partial decryptions for a threshold encryption scheme and 
	combines them to retrieve the original plaintext. This assumes that all 
	partial decryptions correspond to the same plaintext and where correctly 
	created with the correct trustee's theshold private key.
	
	Attributes (public):
		cryptosystem::EGCryptoSystem	-- The shared cryptosystem used by the 
										   threshold scheme.
		ciphertext::Ciphertext	-- The encrypted ciphertext that this 
								   combinator is set-up to decrypt.
	"""
	
	def __init__(self, cryptosystem, ciphertext, num_trustees, threshold):
		"""
		Constructs a ThresholdDecryptionCombinator class.
		
		Arguments:
			cryptosystem::EGCryptoSystem	-- The cryptosystem used by the 
										   	   threshold scheme.
			ciphertext::Ciphertext	-- The encrypted ciphertext that this 
									   combinator is set-up to decrypt.
			num_trustees::int	-- Total number of trustees in the threshold 
								   scheme. (the n in "k of n"-decryption)
			threshold::int	-- Minimum number of trustees required to decrypt 
							   threshold encrypted messages. 
							   (the k in "k of n"-decryption)
		"""
		self.cryptosystem = cryptosystem
		self.ciphertext = ciphertext
		self._num_trustees = num_trustees
		self._threshold = threshold
		# We initialize the array of trustee partial decryptions to None each
		self._trustees_partial_decryptions = [None for i in range(1,num_trustees + 1)]
		
	def add_partial_decryption(self, trustee, partial_decryption):
		"""
		Registers the partial decryption of a given trustee with this object.
		
		Arguments:
			trustee::int	-- The index within the threshold scheme of the 
							   trustee which generated the partial decryption 
							   to be registered.
							   (trustees are indexed from 1 to num_trustees)
			partial_decryption::PartialDecryption	--  The trustee's partial 
													    decryption.
		"""
		if(not (1 <= trustee <= self._num_trustees)):
			raise ValueError("Invalid trustee. The threshold scheme trustees " \
							"must be indexed from 1 to %d" % self._num_trustees)
		
		# TODO: Consider adding compatibility (fingerprint?) checks with the 
		# ciphertext. Possibly even performing partial decryption verification 
		# here if possible.
		# Check at least that decryptions are the RIGHT LENGTH 
		
		self._trustees_partial_decryptions[trustee - 1] = partial_decryption
	
	#TODO: Consider whether "force" is needed here or on add_partial_decryption
	# (perhaps on the constructor? )
	def decrypt_to_bitstream(self, task_monitor=None):
		"""
		Decrypt the ciphertext to a bitstream, using the partial decryptions.
		
		At least (threshold) correctly generated partial decryptions for the 
		ciphertext must be registered with this instance in order for 
		decryption to succeed.
		
		Arguments:
			task_monitor::TaskMonitor	-- A task monitor for this task.
		
		Returns:
			bitstream::Bitstream	-- A bitstream containing the unencrypted 
									   data.
									   
		Throws:
			InsuficientPartialDecryptionsError	-- If there aren't enough 
									partial decryptions registered with this 
									object to perform combined decryption.
		"""
		# Get the indexes of all trustees for which we have a registered
		# partial decryption
		trustees_indexes = []
		for trustee in range(1, self._num_trustees + 1):
			decryption = self._trustees_partial_decryptions[trustee - 1]
			if(decryption != None):
				trustees_indexes.append(trustee)
		
		# Check that we have enough trustees.
		if (len(trustees_indexes) < self._threshold):
			raise InsuficientPartialDecryptionsError("Not enough partial " \
					"decryptions have been registered with this object to " \
					"create a combined decryption. Registered partial " \
					"decryptions: %d. Required partial decryptions " \
					"(threshold): %d." \
					% (len(trustees_indexes), self._threshold))
					
		# We only need threshold trustees, exactly. Select those at random.
		random.shuffle(trustees_indexes)
		trustees_indexes = trustees_indexes[0:self._threshold]
		
		# We get the number of bits and prime for the cryptosystem
		nbits = self.cryptosystem.get_nbits()
		prime = self.cryptosystem.get_prime()
		
		# We initialize our bitstream
		bitstream = BitStream()
		
		# We are using decimal.Decimal configurable precision rationals for a 
		# few of the following operations. We set decimal to use nbits 
		# precision, so that we get the correct results when rounding to 
		# integers in Z_{p}
		decimal.getcontext().prec = nbits
		import pdb; pdb.set_trace()
		# For each block of partial decryption/(gamma, delta) pair of ciphertext
		for b_index in range(0, self.ciphertext.get_length()):
			
			# Each partial decryption block is of the form g^{rP(i)}, where 
			# (gamma, delta) = (g^r, m*g^{rP(0)}).
			# We must first interpolate val=g^{rP(0)} from the g^{rP(i)}'s.
			# Interpolation of val (LaTeX):
			# $g^{rP(0)}=g^{r\sum_{i\in I}P(i)\lambda_{i}(0)}=
			# \prod_{i\in I}\left(g^{rP\left(i\right)}\right)^{\lambda_{i}(0)}$
			# where \lambda_{i}(0) are the Lagrange Coefficients.
			
			gamma, delta = self.ciphertext[b_index]
			val = decimal.Decimal(1)
			for trustee in trustees_indexes:
				p_decryption = self._trustees_partial_decryptions[trustee - 1]
				pd_block = p_decryption[b_index]
				l_coeff = _lagrange_coefficient(trustees_indexes, trustee, 0)
				
				# We wish to calculate pd_block^l_coeff, with l_coeff = a / b
				# integers. That is, we wish to obtain:
				# b-root((pd_block^a))
				# Important: We use Decimal to avoid rounding errors.
				power = decimal.Decimal(pd_block) ** l_coeff.numerator
				power = _decimal_nth_root(power, l_coeff.denominator)
				val *= power
			
			val = _round_decimal_to_int(val) % prime
			
			# We decrypt a block of message as m = delta/val.
			m = delta/val
			
			# ... and add it to the bitstream.
			bitstream.put_num(m, nbits)
		
		# Return the decrypted bitstream
		return bitstream
		
	
	def decrypt_to_text(self, task_monitor=None):
		"""
		Decrypt the ciphertext into its text contents as a string.
		
		At least (threshold) correctly generated partial decryptions for the 
		ciphertext must be registered with this instance in order for 
		decryption to succeed.
		
		Arguments:
			task_monitor::TaskMonitor	-- A task monitor for this task.
		
		Returns:
			string::string	-- Decrypted message as a string.
									   
		Throws:
			InsuficientPartialDecryptionsError	-- If there aren't enough 
									partial decryptions registered with this 
									object to perform combined decryption.
		"""
		bitstream = self.decrypt_to_bitstream(task_monitor)
		bitstream.seek(0)
		length = bitstream.get_num(64)
		return bitstream.get_string(length)
