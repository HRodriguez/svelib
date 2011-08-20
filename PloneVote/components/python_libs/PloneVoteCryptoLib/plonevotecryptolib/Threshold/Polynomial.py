# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  Polynomial.py : Classes to work with polynomials
# 
#  This module contains a few clases for working with polinomials which are 
#  used for the threshold encryption scheme operations (set-up and decryption).
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


class CoefficientsPolynomial:
	"""
	Represents a polynomial for which we know the value of its coefficients.
	
	That is, P(x) = sum(c_{i}x^{i}) with i from 0 to (degree - 1). Where we 
	explicitly know all c_{i}'s.
	
	Only integer coefficients are supported by this class. Additionally, all 
	arithmetic for the polynomial is performed with a given modulus value. 
	This is natural, since all operations within an ElGamal cryptosystem occur 
	in the cyclic group Z_{p} of the integers modulus p.
	"""
	
	def get_modulus(self):
		"""
		Get the modulus of the operations for this polynomial.
		"""
		return self._modulus
	
	def get_degree(self):
		"""
		Get the degree of the polynomial
		"""
		return len(self._coefficients) - 1
	
	def get_coefficient(self, index):
		"""
		Returns the (index)th coefficient of the polynomial.
		(ie. c_{index} if P(x) = sum(c_{i}x^{i}) )
		"""
		if(not (0 <= index <= self.get_degree())):
			raise ValueError("Coefficient index out of range: got %d expected "\
							 "index in [0, %d]" % (index, self.get_degree()))
							 
		return self._coefficients[index]
	
	def get_coefficients(self):
		"""
		Returns the list of coefficients.
		"""
		return list(self._coefficients) # return a copy
	
	def __call__(self, x):
		"""
		Return P(x): this polynomial valued at x.
		"""
		# We use Horner scheme
		# Remember that all arithmetic is using the given modulus
		value = 0
		for coeff in reversed(self._coefficients):
			value = (value * x + coeff) % self._modulus
		return value
			
		
	def __init__(self, modulus, coefficients):
		"""
		Construct a new polynomial, with the given list of coefficients.
		
		Arguments:
			modulus::long	-- All arithmetic for this polynomial will be 
							   performed with this modulus. 
							   That is, in the Z_{modulus} multiplicative group.
			coefficients::long[]	-- The list of indexed coefficients.
		"""
		self._modulus = modulus
		if((len(coefficients) - 1) < 0):
			raise ValueError("Cannot create a polynomial without at least " \
							 "one coefficient.")
		
		self._coefficients = []
		for coeff in coefficients:
			self._coefficients.append(coeff % self._modulus)
	
	@classmethod
	def new_random_polynomial(cls, modulus, degree):
		"""
		Construct a new polynomial of the given degree with random coefficients.
		
		Arguments:
			modulus::long	-- All arithmetic for this polynomial will be 
							   performed with this modulus. 
							   That is, in the Z_{modulus} multiplicative group.
			degree::int		-- Degree of the new polynomial.
 		"""
		coefficients = []
		random = StrongRandom()
		for i in range(0, degree + 1):
			coeff =  random.randint(1, modulus - 1)
			coefficients.append(coeff)
		
		return cls(modulus, coefficients)
