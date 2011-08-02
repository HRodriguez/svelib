# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestEGCryptoSystem.py : Unit tests for 
#                       plonevotecryptolib/EGCryptoSystem.py
#
#  For usage documentation of EGCryptoSystem.py, see, besides this file:
#    * TODO: Add a doctest for basic ElGammal (cryptosys initialization,
#           key pair creation, encryption and decryption)
#    * plonevotecryptolib/tests/doctests/full_election_doctest.txt
#    * the documentation strings for the classes and methods of 
#      EGCryptoSystem.py
#
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

import unittest
import copy
import Crypto.Util.number
import xml.dom.minidom

import plonevotecryptolib.params as params
from plonevotecryptolib.EGCryptoSystem import *
from plonevotecryptolib.PVCExceptions import *
    
# ============================================================================
# Helper functions and other definitions:
# ============================================================================

# Temporarily disable PloneVoteCryptoLib's minimum key size security check, 
# allowing cryptosystems of any size to be accepted as valid.
params.MINIMUM_KEY_SIZE = 0

NBITS = 1024
_cryptosys = None

def get_cryptosys():
    """
    This function returns an EGCryptoSystem object for tests. It caches the 
    cryptosystem and returns a new *copy* of it everytime it is called.
    
    This is necessary because creating a new EGCryptoSystem for each test would 
    make this unit test suite too time consuming.
    """
    global _cryptosys
    # Check if we have already created a cryptosystem for this test run
    if(_cryptosys == None):
        # If not, create it now, as a new 1024 bit ElGamal cryptosystem
        _cryptosys = EGCryptoSystem.new(nbits=NBITS)
    
    # Now, instead of returning the cached cryptosystem, lets return a copy
    # so that test cases can modify it freely without breaking isolation
    return copy.deepcopy(_cryptosys)
    
class Logger:
    def __init__(self): self._s = ""
    def __str__(self): return self._s
    def log(self, msg): self._s += msg

# ============================================================================
# The actual test cases:
# ============================================================================          

class TestEGCryptoSystem(unittest.TestCase):
    """
    A collection of test cases related to obtaining a new EGCryptoSystem.
    """
    
    ## =======================================================================
    ## EGCryptoSystem.new(...) class method tests:
    ## =======================================================================
    
    def test_cryptosystem_correct_creation(self):
        """
        Test that EGCryptoSystem.new(...) returns a correct ElGamal 
        cryptosystem.
        """
        # Instead of calling EGCryptoSystem.new(...) directly, lets use our 
        # helper function to obtain a copy of a cryptosystem created with
        # EGCryptoSystem.new(nbits=NBITS)
        cryptosys = get_cryptosys()
        
        # Check that the number of bits is correct
        self.assertEqual(cryptosys.get_nbits(), NBITS)
        
        # Check that cryptosys.get_prime is actually a prime number between
        # 2**(NBITS-1) and 2**NBITS
        prime = cryptosys.get_prime()
        self.assertTrue(2**(NBITS-1) < prime < 2**NBITS)
        self.assertTrue(Crypto.Util.number.isPrime(prime))
        
        # Furthermore, prime must be a SAFE PRIME, which means that 
        # q = (prime-1)/2 is also prime
        self.assertTrue(Crypto.Util.number.isPrime((prime-1)/2))
        
        # Finally,cryptosys.get_generator should return a generator of 
        # Z_{prime}^*
        g = cryptosys.get_generator()
        
        # First, g must be an element of the group
        self.assertTrue(1 <= g < prime)
        
        # g not generator => g^{2} = 1 mod p or g^{(prime-1)/2} = 1 mod p
        # see. I.N. Herstein pg. 35, "Handbook of Applied Cryptography" 
        #      Algorithm 4.80
        # and the documentation string for EGCryptoSystem._is_generator
        q = (prime - 1) / 2
        self.assertFalse(pow(g, 2, prime) == 1)
        self.assertFalse(pow(g, q, prime) == 1)
        
    def test_cryptosystem_new_invalid_bits(self):
        """
        Test that appropriate exceptions are raised when invoking 
        EGCryptoSystem.new(...) with an invalid nbits parameter.
        """
        # 1)
        # EGCryptoSystem.new(...) raises KeyLengthNonBytableError when asked to 
        # create a cryptosystem of a size that is not a multiple of 8 bits 
        # (ie. not expressible in bytes)
        self.assertRaises(KeyLengthNonBytableError, EGCryptoSystem.new, 1025)
        
        # 2)
        # EGCryptoSystem.new(...) raises KeyLengthTooLowError when asked to 
        # create a cryptosystem of a size smaller than params.MINIMUM_KEY_SIZE
        
        #  Temporarily increase params.MINIMUM_KEY_SIZE so that this
        #  cryptosystem is no longer considered secure to use:
        old_minimum_key_size = params.MINIMUM_KEY_SIZE
        params.MINIMUM_KEY_SIZE = 2*NBITS
        
        #  Check that EGCryptoSystem.new(...) with nbits < 2*NBITS
        #  raises an exception:
        self.assertRaises(KeyLengthTooLowError, EGCryptoSystem.new, NBITS)
        
        #  Restore params.MINIMUM_KEY_SIZE:
        params.MINIMUM_KEY_SIZE = old_minimum_key_size
    
    ## =======================================================================
    ## EGCryptoSystem.__init__(...) unusable constructor tests:
    ## =======================================================================

    def test_egcs_unconstructed_state(self):
        """
        Test that the EGCryptoSystem object returned directly by the class 
        constructor throws exceptions that prevent it from being used.
        
        This is because an EGCryptoSystem object must be obtained using the 
        new(...), load(...) or from_file(...) methods, never the constructor 
        directly.
        """
        unconst_cryptosys = EGCryptoSystem()
        self.assertRaises(EGCSUnconstructedStateError, 
                          unconst_cryptosys.get_nbits)
        self.assertRaises(EGCSUnconstructedStateError, 
                          unconst_cryptosys.get_prime)
        self.assertRaises(EGCSUnconstructedStateError, 
                          unconst_cryptosys.get_generator)
        self.assertRaises(EGCSUnconstructedStateError, 
                          unconst_cryptosys.to_stub, 
                          "Unconst cryptosys", "description")
        self.assertRaises(EGCSUnconstructedStateError, 
                          unconst_cryptosys.to_dom_element,
                          xml.dom.minidom.Document())
        self.assertRaises(EGCSUnconstructedStateError, 
                          unconst_cryptosys.to_file, 
                          "Unconst cryptosys", "description", 
                          "cryptosys.pvcryptosys")
        self.assertRaises(EGCSUnconstructedStateError, 
                          unconst_cryptosys.new_key_pair)
    
    ## =======================================================================
    ## EGCryptoSystem.load(...) class method tests:
    ## =======================================================================
                          
    def test_load_correctly(self):
        """
        Test the EGCryptoSystem.load(...) method when used to load a correct 
        cryptosystem from its (nbits, prime, generator) defining values.
        """
        # Get our usual (correct) cryptosystem
        cryptosys = get_cryptosys()
        
        # Use load(...) to instantiate a new cryptosystem with the same values 
        # as the original cryptosystem
        cryptosys2 = EGCryptoSystem.load(cryptosys.get_nbits(),
                                         cryptosys.get_prime(),
                                         cryptosys.get_generator())
                                         
        # Check that the cryptosys2 was loaded correctly
        self.assertEquals(cryptosys2.get_nbits(), cryptosys.get_nbits())
        self.assertEquals(cryptosys2.get_prime(), cryptosys.get_prime())
        self.assertEquals(cryptosys2.get_generator(), cryptosys.get_generator())
        
        # Check equality and inequality (testing __eq__ and __neq__ while we 
        # are at it)
        self.assertTrue(cryptosys2 == cryptosys)
        self.assertFalse(cryptosys2 != cryptosys)
                          
    def test_load_nbits_too_small(self):
        """
        Test the EGCryptoSystem.load(...) method when used to load a valid 
        cryptosystem which has nbits value smaller than the minimum allowed 
        by the params.MINIMUM_KEY_SIZE security parameter.
        """
        # Get our usual (correct) cryptosystem
        cryptosys = get_cryptosys()
        
        # Get its values
        nbits = cryptosys.get_nbits()
        prime = cryptosys.get_prime()
        generator = cryptosys.get_generator()
        
        # Temporarily increase params.MINIMUM_KEY_SIZE so that this
        # cryptosystem is no longer considered secure to use
        old_minimum_key_size = params.MINIMUM_KEY_SIZE
        params.MINIMUM_KEY_SIZE = 2*NBITS
        
        # Check that EGCryptoSystem.load(...) with the (now) invalid parameters 
        # raises an exception
        self.assertRaises(KeyLengthTooLowError, EGCryptoSystem.load, \
                          nbits, prime, generator)
        
        # Restore params.MINIMUM_KEY_SIZE
        params.MINIMUM_KEY_SIZE = old_minimum_key_size
                          
    def test_load_nbits_non_bytable(self):
        """
        Test the EGCryptoSystem.load(...) method when used to load an invalid 
        cryptosystem that has nbits defined to be a value which is not a 
        multiple of 8 (ie. not expressible in whole bytes)
        """
        # Get our usual (correct) cryptosystem
        cryptosys = get_cryptosys()
        
        # Get its values
        nbits = cryptosys.get_nbits()
        prime = cryptosys.get_prime()
        generator = cryptosys.get_generator()
        
        # Decrease nbits by 1 so that it becomes not divisible by 8
        nbits -= 1
        assert (nbits % 8 != 0)
        
        ## NOTE: 
        # Now the parameters are also invalid for another reason, 
        # namely that prime is no longer of the right size.
        # This test case relies on the fact that nbits is checked by load(...) 
        # before checking the size of prime. If this changes in the future, 
        # this test case must be adapted or discarded.
        ##
        
        # Check that EGCryptoSystem.load(...) with the (now) invalid parameters 
        # raises an exception
        self.assertRaises(KeyLengthNonBytableError, EGCryptoSystem.load, \
                          nbits, prime, generator)
                          
    def test_load_length_mismatch(self):
        """
        Test the EGCryptoSystem.load(...) method when used to load an invalid 
        cryptosystem that has mismatched nbits and prime values. 
        """
        # Get our usual (correct) cryptosystem
        cryptosys = get_cryptosys()
        
        # Get its values
        nbits = cryptosys.get_nbits()
        prime = cryptosys.get_prime()
        generator = cryptosys.get_generator()
        
        # Decrease nbits by 8 so that prime is no longer of length nbits
        nbits -= 8
        assert (nbits % 8 == 0)
        
        # Check that EGCryptoSystem.load(...) with the (now) invalid parameters 
        # raises an exception
        self.assertRaises(KeyLengthMismatch, EGCryptoSystem.load, \
                          nbits, prime, generator)
                          
    def test_load_not_prime(self):
        """
        Test the EGCryptoSystem.load(...) method when used to load an invalid 
        cryptosystem with a composite number passed as the prime parameter. 
        """
        # Get our usual (correct) cryptosystem
        cryptosys = get_cryptosys()
        
        # Get its values
        nbits = cryptosys.get_nbits()
        prime = cryptosys.get_prime()
        generator = cryptosys.get_generator()
        
        # Decrease prime -1, getting a multiple of 2, which is thus composite
        prime -= 1
        
        # Check that EGCryptoSystem.load(...) with the (now) invalid parameters 
        # raises an exception
        self.assertRaises(NotASafePrimeError, EGCryptoSystem.load, \
                          nbits, prime, generator)
                          
    def test_load_prime_not_safe_prime(self):
        """
        Test the EGCryptoSystem.load(...) method when used to load an invalid 
        cryptosystem with a prime parameter that is prime but not a SAFE prime
        (ie. (prime-1)/2 is composite. 
        """
        # Get our usual (correct) cryptosystem
        cryptosys = get_cryptosys()
        
        # Get its values
        nbits = cryptosys.get_nbits()
        generator = cryptosys.get_generator()
        
        # Generate a prime of size nbits which is *NOT* a safe prime:
        prime = Crypto.Util.number.getPrime(nbits)
        while(Crypto.Util.number.isPrime((prime-1)/2)):
            prime = Crypto.Util.number.getPrime(nbits)
        
        # Check that EGCryptoSystem.load(...) with the (now) invalid parameters 
        # raises an exception
        self.assertRaises(NotASafePrimeError, EGCryptoSystem.load, \
                          nbits, prime, generator)
                          
    def test_load_invalid_generator(self):
        """
        Test the EGCryptoSystem.load(...) method when used to load an invalid 
        cryptosystem with an erroneous generator. 
        """
        # Get our usual (correct) cryptosystem
        cryptosys = get_cryptosys()
        
        # Get its values
        nbits = cryptosys.get_nbits()
        prime = cryptosys.get_prime()
        
        # First, we try a generator that falls outside of the Z_{p}^* group:
        generator = prime + 1 # Not \in [1, prime)
        
        # Check that EGCryptoSystem.load(...) with the (now) invalid parameters 
        # raises an exception
        self.assertRaises(NotAGeneratorError, EGCryptoSystem.load, \
                          nbits, prime, generator)
        
        # Now, lets try an element of the group that is NOT a generator 
        # specifically: g^2 where g is a generator (this is not a generator 
        # because, since g^(p-1) = 1 mod p, (g^2)^((p-1)/2) = 1 mod p with 
        # ((p-1)/2) < p.
        generator = pow(cryptosys.get_generator(), 2, prime)
        
        # Check that EGCryptoSystem.load(...) with the (now) invalid parameters 
        # raises an exception
        self.assertRaises(NotAGeneratorError, EGCryptoSystem.load, \
                          nbits, prime, generator)
        
        # For similar reasons, g^((p-1)/2) is also not a generator, we try it 
        # as well (mostly to increase our statement coverage)
        generator = pow(cryptosys.get_generator(), (prime-1)/2, prime)
        self.assertRaises(NotAGeneratorError, EGCryptoSystem.load, \
                          nbits, prime, generator)        


if __name__ == '__main__':
    unittest.main()
