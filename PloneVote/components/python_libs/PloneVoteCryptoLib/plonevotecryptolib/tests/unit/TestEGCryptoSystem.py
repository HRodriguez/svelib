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

# Standard library imports
import unittest
import copy
import os
import tempfile
import xml.dom.minidom

# Third party library imports
import Crypto.Util.number

# Main library PloneVoteCryptoLib imports
import plonevotecryptolib.params as params
from plonevotecryptolib.EGCryptoSystem import *
from plonevotecryptolib.PVCExceptions import *
from plonevotecryptolib.utilities.TaskMonitor import TaskMonitor

# plonevotecryptolib.tests.* imports
# Get Counter and Logger from TestTaskMonitor
from plonevotecryptolib.tests.unit.TestTaskMonitor import (Counter as Counter,\
                                                           Logger as Logger)
    
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

# ============================================================================
# The actual test cases:
# ============================================================================

class TestEGCryptoSystem(unittest.TestCase):
    """
    Test the class: plonevotecryptolib.EGCryptoSystem.EGCryptoSystem
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
    
    def test_cryptosystem_new_with_task_monitor(self):
        """
        Test that EGCryptoSystem.new(...) correctly reports progress using 
        task monitor.
        """
        # Get new counter and logger objects
        counter = Counter()
        logger = Logger()
        
        # Create a task monitor
        task_monitor = TaskMonitor()
        
        # Register callbacks for:
        
        # 1) logging subtask creation,
        def task_start_cb(tm):
            tm_p = tm.parent
            msg = "New task started: \"%s\" " \
                  "(Subtask #%d of %d for task \"%s\")\n" % \
                  (tm.task_name, tm_p.current_subtask_num, \
                   tm_p.num_subtasks, tm_p.task_name)
            logger.log(msg)
           
        task_monitor.add_on_task_start_callback(task_start_cb)
        
        # 2) logging subtask completion,
        def task_end_cb(tm):
            msg = "Task completed: \"%s\"\n" % tm.task_name
            logger.log(msg)
           
        task_monitor.add_on_task_end_callback(task_end_cb)
        
        # 3) counting the number of ticks of progress
        task_monitor.add_on_tick_callback(lambda tm: counter.increment(), 
                                               num_ticks = 1)
        
        # Note:
        # EGCryptoSystem.new(...) does not provide progress percent monitoring 
        
        # We call EGCryptoSystem.new(...) with our task monitor object 
        # We use the *insecure* size of 256bits for performance reasons
        EGCryptoSystem.new(nbits=256, task_monitor=task_monitor)
        
        # Check that the logged match the expected output of our callbacks:
        expected_log = \
"""New task started: \"Generate safe prime\" (Subtask #1 of 1 for task \"Root\")
Task completed: \"Generate safe prime\"
New task started: \"Obtain a generator for the cyclic group\" (Subtask #2 of 2 for task \"Root\")
Task completed: \"Obtain a generator for the cyclic group\"
"""
        self.assertEqual(str(logger),expected_log)
        
        # Also, each of the two subtask produces a progress tick before testing 
        # each safe prime or generator candidate (respectively). So counter 
        # must have registered at least two ticks (likely more)
        self.assertTrue(counter.value >= 2)
        
        
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
    
    ## =======================================================================
    ## to_file(...) and from_file(...) save and load methods tests:
    ## =======================================================================
                          
    def test_save_load_file(self):
        """
        Test that we can correctly save a cryptosystem to a file and load it 
        back. 
        """
        # Get our usual (correct) cryptosystem
        cryptosys = get_cryptosys()
        
        # Get its values
        nbits = cryptosys.get_nbits()
        prime = cryptosys.get_prime()
        generator = cryptosys.get_generator()
        
        # Get a temporary file object using tempfile
        (file_object, file_path) = tempfile.mkstemp()
        
        # We close the file descriptor since we will not be using it, instead 
        # EGCryptoSystem's methods take the filename and open/close the file 
        # as needed.
        # Note that using mkstemp() instead tempfile.TemporaryFile means the 
        # file remains in the filesystem even after it is closed.
        os.close(file_object)
        
        # Save the cryptosystem using to_file(...)
        cryptosys.to_file("Test cryptosystem", "Description...", file_path)
        
        # Load it back using EGCryptoSystem.from_file(...)
        cryptosys2 = EGCryptoSystem.from_file(file_path)
                                         
        # Check that the cryptosys2 was loaded correctly
        self.assertEquals(cryptosys2.get_nbits(), cryptosys.get_nbits())
        self.assertEquals(cryptosys2.get_prime(), cryptosys.get_prime())
        self.assertEquals(cryptosys2.get_generator(), cryptosys.get_generator())
        
        # Check equality and inequality
        self.assertTrue(cryptosys2 == cryptosys)
        self.assertFalse(cryptosys2 != cryptosys)
        
        # Delete the temporary file
        os.remove(file_path)
                          
    def test_load_invalid_file(self):
        """
        Test that loading a cryptosystem from a file in an invalid format 
        raises an appropriate exception.
        """
        # Construct the path to the directory where our invalid test files are 
        # located:
        # __file__ is the file corresponding to this module (TestEGCryptoSystem)
        invalid_files_dir = os.path.join(os.path.dirname(__file__), 
                                         "TestEGCryptoSystem.resources",
                                         "invalid_cryptosystem_xml_files")
        
        # We check that attempting to load files that are not XML files or
        # malformed results in an exception being raised.
        #
        # Note:
        # The exception type is subject to change in all cases, as it depends 
        # on xml.dom.minidom, so we test for any subclass of Exception.
        inv_file = os.path.join(invalid_files_dir, "err_bin_file.pvcryptosys")
        self.assertRaises(Exception, EGCryptoSystem.from_file, inv_file)
        
        inv_file = os.path.join(invalid_files_dir, 
                                "err_not_xml_file.pvcryptosys")
        self.assertRaises(Exception, EGCryptoSystem.from_file, inv_file)
        
        inv_file = os.path.join(invalid_files_dir, 
                                "err_malformed_xml_file.pvcryptosys")
        self.assertRaises(Exception, EGCryptoSystem.from_file, inv_file)
        
        inv_file = os.path.join(invalid_files_dir, 
                                "err_no_root_element_file.pvcryptosys")
        self.assertRaises(Exception, EGCryptoSystem.from_file, inv_file)
        
        # Now we check files that are valid XML files, but do not match the 
        # expected format for an stored PloneVoteCryptoLib cryptosystem.
        # All these files should raise InvalidPloneVoteCryptoFileError when 
        # attempting to load them as EGCryptoSystem objects (or EGStub objects, 
        # for that matter).
        for file_name in ["err_invalid_root_element_file.pvcryptosys",
                          "err_missing_name_element_file.pvcryptosys",
                          "err_missing_description_element_file.pvcryptosys",
                          "err_missing_nbits_element_file.pvcryptosys",
                          "err_missing_prime_element_file.pvcryptosys",
                          "err_missing_generator_element_file.pvcryptosys",
                          "err_non_int_nbits_element_file.pvcryptosys",
                          "err_non_int_prime_element_file.pvcryptosys",
                          "err_non_int_generator_element_file.pvcryptosys"]:
            inv_file = os.path.join(invalid_files_dir, file_name)
            self.assertRaises(InvalidPloneVoteCryptoFileError, 
                              EGCryptoSystem.from_file, inv_file)


class TestEGStub(unittest.TestCase):
    """
    Test the class: plonevotecryptolib.EGCryptoSystem.EGStub
    """
    
    # NOTE: Most of EGStub methods are exercised indirectly when using 
    # EGCryptoSystem.to_file and EGCryptoSystem.from_file.
    # In this class we just add a few tests to check additional functionality 
    # which is not checked for above.
    
    def test_to_stub_and_to_cryptosys(self):
        """
        Test that:
            1) EGCryptoSystem.to_stub produces a correct EGStub object
            2) Said object can be saved to file and restored from it as an 
               EGStub
            3) The restored EGStub can be converted back into a EGCryptoSystem 
               that is the same as the original.
        """
        # Get our usual (correct) cryptosystem
        cryptosys = get_cryptosys()
        
        # Get its values
        nbits = cryptosys.get_nbits()
        prime = cryptosys.get_prime()
        generator = cryptosys.get_generator()
        
        # Obtain the corresponding EGStub object
        name = "Test Cryptosystem"
        description = "A Cryptosystem object generated for unit testing."
        cryptosys_stub = cryptosys.to_stub(name, description)
        
        # Check that all the EGStub values are the expected ones
        self.assertEqual(cryptosys_stub.name, name)
        self.assertEqual(cryptosys_stub.description, description)
        self.assertEqual(cryptosys_stub.nbits, nbits)
        self.assertEqual(cryptosys_stub.prime, prime)
        self.assertEqual(cryptosys_stub.generator, generator)
        
        # Save the EGStub to a new temporary file and read it back
        (file_object, file_path) = tempfile.mkstemp()
        os.close(file_object) # see TestEGCryptoSystem.test_save_load_file
        
        cryptosys_stub.to_file(file_path)
        cryptosys_stub_2 = EGStub.from_file(file_path)
        
        # Delete the temporary file
        os.remove(file_path)
        
        # Check that all the EGStub values are still correct
        self.assertEqual(cryptosys_stub_2.name, name)
        self.assertEqual(cryptosys_stub_2.description, description)
        self.assertEqual(cryptosys_stub_2.nbits, nbits)
        self.assertEqual(cryptosys_stub_2.prime, prime)
        self.assertEqual(cryptosys_stub_2.generator, generator)
        
        # Transform the re-loaded EGStub back into an EGCryptoSystem with 
        # to_cryptosystem()
        cryptosys2 = cryptosys_stub_2.to_cryptosystem()
        
        # Check that the cryptosys2 has the same values as cryptosys
        self.assertEquals(cryptosys2.get_nbits(), cryptosys.get_nbits())
        self.assertEquals(cryptosys2.get_prime(), cryptosys.get_prime())
        self.assertEquals(cryptosys2.get_generator(), cryptosys.get_generator())
        
        # Check equality and inequality
        self.assertTrue(cryptosys2 == cryptosys)
        self.assertFalse(cryptosys2 != cryptosys)
    
    def test_is_secure(self):
        """
        Test the EGStub.is_secure() method
        """
        # Get our usual (correct) cryptosystem
        cryptosys = get_cryptosys()
        
        # Obtain the corresponding EGStub object
        name = "Test Cryptosystem"
        cryptosys_stub = cryptosys.to_stub("Test Cryptosystem", "Decription")
        
        # Check that it is considered a secure cryptosystem
        # This only checks that the size of the prime (ie. nbits) is greater 
        # or equal than params.MINIMUM_KEY_SIZE
        self.assertTrue(cryptosys_stub.is_secure())
        
        # Temporarily increase params.MINIMUM_KEY_SIZE so that this
        # cryptosystem is no longer considered secure to use
        old_minimum_key_size = params.MINIMUM_KEY_SIZE
        params.MINIMUM_KEY_SIZE = 2*NBITS
        
        # Check that is_secure now returns False.
        self.assertFalse(cryptosys_stub.is_secure())
        
        # Restore params.MINIMUM_KEY_SIZE
        params.MINIMUM_KEY_SIZE = old_minimum_key_size
        


if __name__ == '__main__':
    unittest.main()
