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

from plonevotecryptolib.utilities.BitStream import BitStream

__all__ = ["ThresholdDecryptionCombinator", 
		   "InsuficientPartialDecryptionsError"]

# ============================================================================

# ============================================================================
# Helper functions:
# ============================================================================

def _lagrange_coefficient(indexes, i, x, prime_modulus):
	"""
	Returns the Lagrange Coefficient for index i and value x in the given list 
	of indexes, calculated on the field Z_{prime_modulus}.
	
	The coefficient is returned as a whole number in the field 
	Z_{prime_modulus}.
	
	LaTeX definition of the Lagrange Coefficient:
		$\lambda_{i}(x)=\prod_{j\in Indexes-\{i\}}\frac{x-j}{i-j}$
	
	See: http://en.wikipedia.org/wiki/Polynomial_interpolation
	
	Note that we use division of the field Z_{prime_modulus}, rather than real 
	division. That is:
		$\lambda_{i}(x)=\prod_{j\in Indexes-\{i\}}(x-j)(i-j)^{-1}$
	
	Where $(i-j)^{-1}$ is the inverse of (i-j) in the field Z_{prime_modulus}.
	
	Arguments:
		indexes::int[]	-- The valid indexes for the Lagrange Coefficient, 
						   which are the same as the x-coordinates at which we 
						   know the value of the polynomial for interpolation.
		i::int			-- Index of the Lagrange Coefficient we want.
		x::int			-- x-coordinate at which we wish to interpolate the 
						   value of the polynomial.
		prime_modulus::long	-- A prime number. Which guarantees that 
							   Z_{prime_modulus} is a field.
	
	Returns:
		lagrange_coeff::long -- The lagrange coefficient in Z_{prime_modulus}.
	"""
	# We calculate the whole coefficient as a fraction and the take the inverse 
	# of the denominator in Z_{prime_modulus}, rather than inverting each (i-j)  
	numerator = 1
	denominator = 1
	
	for j in indexes:
		if(i == j):
			continue
		numerator *= (x - j)
		denominator *= (i - j)
	
	numerator = numerator % prime_modulus
	denominator = denominator % prime_modulus
	# a^(p-2) is the inverse of a in Z_{p} with p prime. Proof:
	# (a)(a^(p-2)) = a^(p-1) = 1
	inv_denominator = pow(denominator, prime_modulus - 2, prime_modulus)
	
	result = (numerator*inv_denominator) % prime_modulus
	return result

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
		trustee_indexes = []
		for trustee in range(1, self._num_trustees + 1):
			decryption = self._trustees_partial_decryptions[trustee - 1]
			if(decryption != None):
				trustee_indexes.append(trustee)
		
		# Check that we have enough trustees.
		if (len(trustee_indexes) < self._threshold):
			raise InsuficientPartialDecryptionsError("Not enough partial " \
					"decryptions have been registered with this object to " \
					"create a combined decryption. Registered partial " \
					"decryptions: %d. Required partial decryptions " \
					"(threshold): %d." \
					% (len(trustee_indexes), self._threshold))
					
		# We only need threshold trustees, exactly. Select those at random.
		random.shuffle(trustee_indexes)
		trustee_indexes = trustee_indexes[0:self._threshold]
		
		# We get the number of bits and prime for the cryptosystem
		nbits = self.cryptosystem.get_nbits()
		prime = self.cryptosystem.get_prime()
		#  prime = 2q + 1 with q prime by construction (see EGCryptoSystem).
		q = (prime - 1) / 2
		
		# See PublicKey.encrypt_bitstream for why we use nbits - 1 as the block 
		# size.
		block_size = self.cryptosystem.get_nbits() - 1
		
		# We initialize our bitstream
		bitstream = BitStream()
		
		# We pre-calculate the lagrange coefficients for the trustees in Z_{q}
		# for x = 0, to avoid doing so for each block of ciphertext.
		# See below for an explanation of the use of lagrange coefficients.
		lagrange_coeffs = [None for i in range(0,self._num_trustees + 1)]
		for trustee in trustee_indexes:
			lagrange_coeffs[trustee] = \
				_lagrange_coefficient(trustee_indexes, trustee, 0, q)
		
		# For each block of partial decryption/(gamma, delta) pair of ciphertext
		for b_index in range(0, self.ciphertext.get_length()):
			
			# Each partial decryption block is of the form g^{rP(i)}, where 
			# (gamma, delta) = (g^r, m*g^{r2P(0)}).
			#
			# We must first interpolate val=g^{r2P(0)} from the g^{rP(i)}'s.
			# Interpolation of val (LaTeX):
			# $g^{r2P(0)}=g^{\sum_{i\in I}r2P(i)\lambda_{i}(0)}=
			# \prod_{i\in I}\left(g^{rP\left(i\right)}\right)^{2\lambda_{i}(0)}$
			# where \lambda_{i}(0) are the Lagrange Coefficients.
			#
			# Note that the polynomials are in the field Z_{q} where q is such 
			# that p = 2*q + 1 and prime. This allows us to use lagrange 
			# interpolation. However, in order for the whole g^{...} values to 
			# be equal mod p, we need to have the exponents be equal mod (p-1) 
			# (rather than mod q), so we multiply by 2. Remember that this 
			# means that 2P(0) is our private key for the threshold encryption 
			# (although it never gets created by any of the parties), and the 
			# reason why g^2P(0) is the threshold public key.
			#
			# See (TODO: Add reference) for the full explanation
			
			gamma, delta = self.ciphertext[b_index]
			val = 1
			for trustee in trustee_indexes:
				p_decryption = self._trustees_partial_decryptions[trustee - 1]
				pd_block = p_decryption[b_index]
				
				# We get \lambda_{i}(0) in the field Z_{q} for the trustees
				l_coeff = lagrange_coeffs[trustee]
				
				# We assert that the \lambda_{i}(0) was pre-calculated.
				assert (l_coeff != None), "lagrange coefficients for " \
										  "trustees in trustee_indexes " \
										  "should have been pre-calculated."
				
				# factor: $\left(g^{rP\left(i\right)}\right)^{2\lambda_{i}(0)}$
				factor = pow(pd_block, 2*l_coeff, prime)
				
				val = (val*factor) % prime
			
			# We decrypt a block of message as m = delta/val = delta*(val)^{-1}.
			# (val)^{-1} the inverse of val in Z_{p}
			inv_val = pow(val, prime - 2, prime)
			m = (delta*inv_val) % prime
			
			# ... and add it to the bitstream.
			bitstream.put_num(m, block_size)
		
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
