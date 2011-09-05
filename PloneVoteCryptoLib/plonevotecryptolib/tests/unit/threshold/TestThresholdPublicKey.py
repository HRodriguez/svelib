# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestThresholdPublicKey.py : Unit tests for 
#                    plonevotecryptolib/Threshold/ThresholdPublicKey.py
#
#  For usage documentation of ThresholdPublicKey.py, see, besides this 
#  file:
#    * plonevotecryptolib/tests/doctests/full_election_doctest.txt
#    * the documentation strings for the classes and methods of 
#      ThresholdPublicKey.py
#
#
#  Part of the PloneVote cryptographic library (PloneVoteCryptoLib)
#
#  Originally written by: Hugo Rodriguez 
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
import os
import tempfile


# Main library PloneVoteCryptoLib imports
import plonevotecryptolib.params as params
from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem
from plonevotecryptolib.Threshold.ThresholdEncryptionSetUp import *
from plonevotecryptolib.Threshold.ThresholdPublicKey import *
from plonevotecryptolib.PVCExceptions import *
from plonevotecryptolib.utilities.TaskMonitor import TaskMonitor

# plonevotecryptolib.tests.* imports
# Get Counter and Logger from TestTaskMonitor
from plonevotecryptolib.tests.unit.utilities.TestTaskMonitor import \
                                        (Counter as Counter, Logger as Logger)
    
# ============================================================================
# Helper functions and other definitions:
# ============================================================================

# Temporarily disable PloneVoteCryptoLib's minimum key size security check, 
# allowing cryptosystems of any size to be accepted as valid.
params.MINIMUM_KEY_SIZE = 0

_cryptosys = None

def get_cryptosystem():
    """
    This function returns a predetermined EGCryptoSystem object.
    
    The EGCryptoSystem object is loaded from a resource file and guaranteed to 
    be always the same, at least for same execution of the test suite. The 
    cryptosystem is also cached in memory for quicker access.
    """
    global _cryptosys
    # Check if we have already loaded a cryptosystem for this test run
    if(_cryptosys == None):
        # If not, load it now:
        # Construct the path to the cryptosystem test resource file
        cryptosys_file = os.path.join(os.path.dirname(__file__), 
                                      "TestThresholdEncryptionSetUp.resources",
                                      "test1024bits.pvcryptosys")
        
        # Load the cryptosystem from file
        _cryptosys = EGCryptoSystem.from_file(cryptosys_file)
    
    # Return the cached cryptosystem 
    # (Note: this is the original reference, not a deepcopy, tests using the 
    #  cryptosystem object should treat it as read-only to preserve isolation)
    return _cryptosys

class Trustee:
    """
    Class used to represent a Trustee
    """

    def __init__(self):
        """
        The trustee is created with private and public keys.
        Every key is generated from the same EGCryptoSystem
        """
        # Las llaves las generamos con el cryptosis _cryptosys
        kp = get_cryptosystem().new_key_pair()
        self.private_key = kp.private_key
        self.public_key = kp.public_key
        self.commitment = None
        self.tesu_fingerprint = None
        self.threshold_public_key = None
        self.threshold_private_key = None

# ============================================================================
# The actual test cases:
# ============================================================================

class TestThresholdPublicKey(unittest.TestCase):
    """
    Test the class: plonevotecryptolib.Threshold.ThresholdPublicKey.
    ThresholdPublicKey
    """
    
    def setUp(self):
        """
        Unit test setup method.
        """
        self.num_trustees = 5
        self.threshold = 3
        self.trustees = []
        self.commitments = []
        for i in range(self.num_trustees):
            self.trustees.append(Trustee())
            
        # Generate a new instance of ThresholdEncryptionSetUp to be used
        # for generate publickeys
        cryptosystem = get_cryptosystem()
        self.tSetUp = ThresholdEncryptionSetUp(cryptosystem, 
                                          self.num_trustees, self.threshold)                         
        # Adding the keys from trustees
        for i in range(self.num_trustees):
            self.tSetUp.add_trustee_public_key(i, self.trustees[i].public_key)
        # Generate commitmes for trustees
        for i in range(self.num_trustees):
            self.commitments.append(self.tSetUp.generate_commitment())               
        # Adding the first  trustees  commitments 
        for i in range(self.num_trustees):
           self.tSetUp.add_trustee_commitment(i, self.commitments[i])  
 
            
    def test_publickey_generation(self):
        """
        Create a new ThresholdPublicKey, verify that is created correctly
        and get_fingerpint and get_partial_public_key returns what spected
        """
        
        # Generate public_key_value and verification_partial_public_keys as 
        # generated at
        # ThresholEncryptionSetUp.ThresholdEncryptionSetUp.generate_public_key()
        key = 1
        prime = self.tSetUp.cryptosystem.get_prime()
        for commitment in self.tSetUp._trustees_commitments:
            factor = pow(commitment.public_coefficients[0], 2, prime)
            key = (key * factor) % prime
        partial_public_keys = []
        for trustee in range(1, self.tSetUp._num_trustees + 1):
            partial_pub_key = 1
            for commitment in self.tSetUp._trustees_commitments:
                ppub_key_fragment = 1
                for k in range(0, self.tSetUp._threshold):
                    ppub_key_fragment *= pow(commitment.public_coefficients[k],\
                                             2*(trustee**k), prime)
                    ppub_key_fragment = ppub_key_fragment % prime
                partial_pub_key = (partial_pub_key * ppub_key_fragment) % prime    
            partial_public_keys.append(partial_pub_key)
        
        # ThresholdPublicKey shoul raise ValueError if threshold > num_trustees
        # and if len(verification_partial_public_keys) != num_trustees
        
        self.assertRaises(ValueError, ThresholdPublicKey, 
                          self.tSetUp.cryptosystem, 
                          self.tSetUp._num_trustees, 
                          self.tSetUp._threshold + self.tSetUp._num_trustees, 
                          key, partial_public_keys)
                          
        self.assertRaises(ValueError, ThresholdPublicKey, 
                          self.tSetUp.cryptosystem, 
                          self.tSetUp._num_trustees +1 , 
                          self.tSetUp._threshold, 
                          key, partial_public_keys)
        
        # Generate a new ThresholdPublicKey                           
        pkey = ThresholdPublicKey(self.tSetUp.cryptosystem, 
                                  self.tSetUp._num_trustees, 
                                  self.tSetUp._threshold, 
                                  key, partial_public_keys)
                                  
        finger = pkey.get_fingerprint()
        # The generated fingerprint must be an alphanumeric 
        # becouse is hexadecimal
        self.assertTrue(finger.isalnum())
        
        # Get a partial public key for some trustee k
        k = 3
        ppk = pkey.get_partial_public_key(k)
        
        # The returned partial public key for k must be the same we generate
        self.assertEquals(ppk, partial_public_keys[k])
             
        
    def test_save_load_file(self):
        """
        Test that we can correctly save a ThresholdPublicKey to a file and 
        load it back. 
        """
        # Get a new threshold public key object
        key = self.tSetUp.generate_public_key()
        
        # Get its fingerprint for comparison after deserialization
        original_fingerprint = key.get_fingerprint()
        
        # Get a temporary file object using tempfile
        (file_object, file_path) = tempfile.mkstemp()
        
        # We close the file descriptor since we will not be using it, instead 
        # PublicKey's methods take the filename and open/close the file as 
        # needed.
        # Note that using mkstemp() instead tempfile.TemporaryFile means the 
        # file remains in the filesystem even after it is closed.
        os.close(file_object)
        
        # Save the key using to_file(...)
        key.to_file(file_path)
        
        # Load it back using PublicKey.from_file(...)
        recovered_key = ThresholdPublicKey.from_file(file_path)
                                         
        # Get the fingerprint of the recovered key
        recovered_fingerprint = recovered_key.get_fingerprint()
        
        # Check that the fingerprints match (and thus they're the same key)
        self.assertEqual(recovered_fingerprint, original_fingerprint)
        
        # Delete the temporary file
        os.remove(file_path)
                                
    def test_load_invalid_file(self):
        """
        Test that loading a threshold public key from a file in an invalid 
        format raises an appropriate exception.
        """
        # Construct the path to the directory where our invalid test files are 
        # located:
        invalid_files_dir = os.path.join(os.path.dirname(__file__), 
                                         "TestThresholdPublicKey.resources",
                                         "invalid_tpublickey_xml_files")
        
        # Add invalid private key files as needed                               
        for file_name in ["err_missing_pub_key_elem.pvpubkey",
                          "err_single_public_key.pvpubkey",
                          "err_not_number_prime_elem.pvpubkey",
                          "err_pub_key_too_large.pvpubkey",
                          "err_par_pub_key_too_large.pvpubkey"]:
            inv_file = os.path.join(invalid_files_dir, file_name)
            self.assertRaises(InvalidPloneVoteCryptoFileError, 
                              ThresholdPublicKey.from_file, inv_file)

if __name__ == '__main__':
    unittest.main()  
