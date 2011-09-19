# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestThresholdPrivateKey.py : Unit tests for 
#                    plonevotecryptolib/Threshold/ThresholdPrivateKey.py
#
#  For usage documentation of ThresholdPrivateKey.py, see, besides this 
#  file:
#    * plonevotecryptolib/tests/doctests/full_election_doctest.txt
#    * the documentation strings for the classes and methods of 
#      ThresholdPrivateKey.py
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
from plonevotecryptolib.Threshold.ThresholdPrivateKey import *
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

class TestThresholdPrivateKey(unittest.TestCase):
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
        # Adding the  trustees  commitments 
        for i in range(self.num_trustees):
           self.tSetUp.add_trustee_commitment(i, self.commitments[i])
         
        self.tpkey = self.tSetUp.generate_public_key()
            
    def test_privatekey_generation(self):
        """
        Create a new ThresholdPrivateKey, verify that is created correctly
        """
        
        privatekey = ThresholdPrivateKey(self.tSetUp.cryptosystem, 
                                         self.num_trustees,
                                         self.threshold, self.tpkey,
                                         self.trustees[0].private_key)
                                         
        # The values of the parameters must be the same we expect
        self.assertEquals(privatekey.cryptosystem, self.tSetUp.cryptosystem)
        self.assertEquals(privatekey.num_trustees, self.num_trustees)
        self.assertEquals(privatekey.threshold, self.threshold)
        self.assertEquals(privatekey.public_key, self.tpkey)
        self.assertEquals(privatekey._key, self.trustees[0].private_key)
                
    def test_partial_decryption(self):
        """
        Create a ciphertext with the threshold public key and decrypt it and 
        create others ciphertext to prove IncompatibleCiphertextError
        """

        tprk = self.tSetUp.generate_private_key(0, self.trustees[0].private_key)
        text_to_encrypt_dir = os.path.join(os.path.dirname(__file__), 
                                           "TestThresholdPrivateKey.resources")
        text_to_encrypt = os.path.join(text_to_encrypt_dir, "text_to_encrypt")
        text_encrypted = self.tpkey.encrypt_text(text_to_encrypt)
        
        # Decrypt the file created with our public key must be fine
        tprk.generate_partial_decryption(text_encrypted)
        
        # Create another ThresholdEcryptuonSetUp with other 1024 bits
        # cryptosys to create a cypthertext that cant be decrypted
        second_cryptosys_file = os.path.join(os.path.dirname(__file__), 
                                      "TestThresholdEncryptionSetUp.resources",
                                      "test1024bits_second.pvcryptosys")
        # Load the cryptosystem from file
        second_cryptosys = EGCryptoSystem.from_file(second_cryptosys_file)      
        secondtSetUp = ThresholdEncryptionSetUp(second_cryptosys, 
                                          self.num_trustees, self.threshold)
         # Adding the keys from trustees for 2ndsetUp
        for i in range(self.num_trustees):
            secondtSetUp.add_trustee_public_key(i, self.trustees[i].public_key)
        secondcommitments = []
        # Generate commitmes for trustees for 2ndsetUp
        for i in range(self.num_trustees):
            secondcommitments.append(secondtSetUp.generate_commitment()) 
        # Adding the secont trustees  commitments 
        for i in range(self.num_trustees):
            secondtSetUp.add_trustee_commitment(i, secondcommitments[i])
        # Generate secon cryptosis publickey
        secondtpkey = secondtSetUp.generate_public_key()
        # Encrypt the file with the secon cryptosis publickey
        secondtext_encrypted = secondtpkey.encrypt_text(text_to_encrypt)
        
        
        # Try to decryp something created with other ThresholdEcryptuonSetUp 
        # must raise IncompatibleCiphertextError
        
        self.assertRaises(IncompatibleCiphertextError, 
                         tprk.generate_partial_decryption, secondtext_encrypted)


        # Create another ThresholdEcryptuonSetUp with other 512 bits
        # cryptosys to create a cypthertext that cant be decrypted
        third_cryptosys_file = os.path.join(os.path.dirname(__file__), 
                                      "TestThresholdEncryptionSetUp.resources",
                                      "test512bits.pvcryptosys")
        # Load the cryptosystem from file
        third_cryptosys = EGCryptoSystem.from_file(third_cryptosys_file)      
        thirdtSetUp = ThresholdEncryptionSetUp(third_cryptosys, 
                                          self.num_trustees, self.threshold)
         # Adding the keys from trustees for 2ndsetUp
        for i in range(self.num_trustees):
            thirdtSetUp.add_trustee_public_key(i, self.trustees[i].public_key)
        thirdcommitments = []
        # Generate commitmes for trustees for 2ndsetUp
        for i in range(self.num_trustees):
            thirdcommitments.append(thirdtSetUp.generate_commitment()) 
        # Adding the secont trustees  commitments 
        for i in range(self.num_trustees):
            thirdtSetUp.add_trustee_commitment(i, thirdcommitments[i])
        # Generate secon cryptosis publickey
        thirdtpkey = thirdtSetUp.generate_public_key()
        # Encrypt the file with the secon cryptosis publickey
        thirdtext_encrypted = thirdtpkey.encrypt_text(text_to_encrypt)
        
        
        # Try to decryp something created with other ThresholdEcryptuonSetUp 
        # must raise IncompatibleCiphertextError
        
        self.assertRaises(IncompatibleCiphertextError, 
                         tprk.generate_partial_decryption, thirdtext_encrypted)

    def test_partial_decryption_w_task_monitor(self):
        """
        Test that partial decryption can be monitored using a TaskMonitor 
        object.
        """
        # Get a new task monitor and a counter
        task_monitor = TaskMonitor()
        partialDecryptionCounter = Counter()
        
        # Register a task monitor callback to increment the counter once 
        # for each 5% progress of partial decryption
        def partial_decryption_callback(tm):
            partialDecryptionCounter.increment()
        
        task_monitor.add_on_progress_percent_callback(
                            partial_decryption_callback, percent_span = 5.0)
        
        # Generate a partial decryption passing the task_monitor object
        
        tprk = self.tSetUp.generate_private_key(0, self.trustees[0].private_key)
        text_to_encrypt_dir = os.path.join(os.path.dirname(__file__), 
                                           "TestThresholdPrivateKey.resources")
        text_to_encrypt = os.path.join(text_to_encrypt_dir, "text_to_encrypt")
        text_encrypted = self.tpkey.encrypt_text(text_to_encrypt)        
        tprk.generate_partial_decryption(text_encrypted, task_monitor)
        
        
        # Check that the counter has been incremented 100/5 = 20 times
        self.assertEqual(partialDecryptionCounter.value, 20)

    def test_save_load_file(self):
        """
        Test that we can correctly save a ThresholdPrivateKey to a file and 
        load it back. 
        """
        # Get a new threshold private key object
        pkey = self.tSetUp.generate_private_key(0, self.trustees[0].private_key)
        
        # Get a temporary file object using tempfile
        (file_object, file_path) = tempfile.mkstemp()
        
        # We close the file descriptor since we will not be using it, instead 
        # PublicKey's methods take the filename and open/close the file as 
        # needed.
        # Note that using mkstemp() instead tempfile.TemporaryFile means the 
        # file remains in the filesystem even after it is closed.
        os.close(file_object)
        
        # Save the key using to_file(...)
        pkey.to_file(file_path)        
        # Load it back using ThresholdPrivateKey.from_file(...)
        recovered_key = ThresholdPrivateKey.from_file(file_path)
        # Check that parameters and keys match (and thus they're the same key)
        self.assertEqual(pkey.cryptosystem, recovered_key.cryptosystem)
        self.assertEqual(pkey.num_trustees, recovered_key.num_trustees)
        self.assertEqual(pkey.threshold, recovered_key.threshold)
        self.assertEqual(pkey.public_key.get_fingerprint(),
                         recovered_key.public_key.get_fingerprint())
        self.assertEqual(pkey._key, recovered_key._key)
        
        # Delete the temporary file
        os.remove(file_path)        
        
    def test_load_invalid_file(self):
        """
        Test that loading a threshold private key from a file in an invalid 
        format raises an appropriate exception.
        """
        # Construct the path to the directory where our invalid test files are 
        # located:
        invalid_files_dir = os.path.join(os.path.dirname(__file__), 
                                         "TestThresholdPrivateKey.resources",
                                         "invalid_tprivatekey_xml_files")
        
        # Add invalid private key files as needed                               
        for file_name in ["err_missing_pub_key_elem.pvpubkey",
                          "err_not_valid_number_elem.pvpubkey",
                          "err_prv_key_too_large.pvpubkey",
                          "err_pub_key_too_large.pvpubkey",
                          "err_par_pub_key_too_large.pvpubkey"]:
            inv_file = os.path.join(invalid_files_dir, file_name)
            self.assertRaises(InvalidPloneVoteCryptoFileError, 
                              ThresholdPrivateKey.from_file, inv_file)        
        

if __name__ == '__main__':
    unittest.main()  
