# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestBasicEncryption.py : Unit tests for basic encryption and decryption.
#
#  This file provides tests for the basic ElGammal encryption and decryption 
#  functions offered by plonevotecryptolib. This test file provides the main 
#  unit tests for multiple python modules in the plonevotecryptolib.* 
#  namespace, namely:
#
#   * plonevotecryptolib.PublicKey    (PublicKey.py)
#   * plonevotecryptolib.PrivateKey    (PrivateKey.py)
#   * plonevotecryptolib.Ciphertext    (Ciphertext.py)
#   * plonevotecryptolib.KeyPair    (KeyPair.py)
#
#  These modules are tested together because the functionality offered by them 
#  is so closely interrelated that testing them in isolation is both extremely 
#  hard, and not truly indicative of their real usage environment. For example, 
#  it makes little to no sense to test a class designed to represent encrypted 
#  data (Ciphertext) separately from the classes used to encrypt (PublicKey) 
#  and decrypt (PrivateKey) that same data.
#
#  For usage documentation of the classes tested in this file, see also:
#    * TODO: Add a doctest for basic ElGammal (cryptosys initialization,
#           key pair creation, encryption and decryption)
#    * plonevotecryptolib/tests/doctests/full_election_doctest.txt
#    * the documentation strings for the classes and methods of 
#      PublicKey.py, PrivateKey.py, Ciphertext.py and KeyPair.py
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
import os
import tempfile
import math
import xml.dom.minidom

# Third party library imports
import Crypto.Util.number

# Main library PloneVoteCryptoLib imports
import plonevotecryptolib.params as params
from plonevotecryptolib.PVCExceptions import *
from plonevotecryptolib.utilities.TaskMonitor import TaskMonitor
from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem
from plonevotecryptolib.PublicKey import PublicKey
from plonevotecryptolib.PrivateKey import PrivateKey
from plonevotecryptolib.Ciphertext import Ciphertext
from plonevotecryptolib.KeyPair import KeyPair

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
                                      "TestBasicEncryption.resources",
                                      "test1024bits.pvcryptosys")
        
        # Load the cryptosystem from file
        _cryptosys = EGCryptoSystem.from_file(cryptosys_file)
    
    # Return the cached cryptosystem 
    # (Note: this is the original reference, not a deepcopy, tests using the 
    #  cryptosystem object should treat it as read-only to preserve isolation)
    return _cryptosys

# ============================================================================
# The actual test cases:
# ============================================================================

class TestEncryptionDecryption(unittest.TestCase):
    """
    Test encryption and decryption functions.
    """
    
    def setUp(self):
        """
        Unit test setup method.
        """
        # Get the ElGamal cryptosystem to use
        self.cryptosystem = get_cryptosystem()
        
        # Generate a key pair
        key_pair = self.cryptosystem.new_key_pair()
        self.public_key = key_pair.public_key
        self.private_key = key_pair.private_key
        
        # A message used to for encryption/decryption
        self.message = "This string will be encrypted and then decrypted. It " \
                       "contains some non-ascii chars and control chars:\n\t" \
                       "ÄäÜüß ЯБГДЖЙŁĄŻĘĆŃŚŹ てすと ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃ."
    
    def test_encryption_decryption(self):
        """
        Test that a simple message can be encrypted and then decrypted.
        """
        # Use the public key to encrypt the message
        ciphertext = self.public_key.encrypt_text(self.message)
        
        # then use the private key to recover it
        recovered_message = self.private_key.decrypt_to_text(ciphertext)
        
        # Check that the message was recovered correctly
        self.assertEqual(recovered_message, self.message)
    
    def test_encryption_decryption_w_padding(self):
        """
        Test encryption and decryption with padding to a certain size
        """
        # Pad to 2 KB (given in bytes)
        PAD_TO_SIZE = 2*1024
        
        # Use the public key to encrypt the message
        ciphertext = self.public_key.encrypt_text(self.message, 
                                                  pad_to=PAD_TO_SIZE)
                                                  
        # Calculate the expected size of the ciphertext in blocks
        block_size = self.cryptosystem.get_nbits()
        
        # Each nbits-1 block of the message (+ padding) is converted to an 
        # nbits block in the ciphertext (to ensure all blocks of the message 
        # are \in {1,...,p-1}).
        expected_blocks = int(math.ceil((8.0*PAD_TO_SIZE)/(block_size-1)))
                                                  
        # Check that the length in blocks of the ciphertext is the expected one
        self.assertEqual(ciphertext.get_length(), expected_blocks)
        
        # then use the private key to recover it
        recovered_message = self.private_key.decrypt_to_text(ciphertext)
        
        # Check that the message was recovered correctly
        self.assertEqual(recovered_message, self.message)
    
    def test_encryption_decryption_w_padding_too_small(self):
        """
        Test encryption and decryption with padding to less than the message 
        length.
        """
        # Pad to 8 bytes (much smaller than message)
        PAD_TO_SIZE = 8
        
        # In this case, encryption should still work, pad_to indicates the 
        # MINIMUM size of the encrypted ciphertext, not a fixed limit.
        
        # Use the public key to encrypt the message
        ciphertext = self.public_key.encrypt_text(self.message, 
                                                  pad_to=PAD_TO_SIZE)
        
        # then use the private key to recover it
        recovered_message = self.private_key.decrypt_to_text(ciphertext)
        
        # Check that the message was recovered correctly
        self.assertEqual(recovered_message, self.message)
    
    def test_encryption_decryption_w_task_monitor(self):
        """
        Test that encryption and decryption can be monitored using a 
        TaskMonitor object.
        """
        # Get a new task monitor and two counters, one for encryption and one 
        # for decryption
        task_monitor = TaskMonitor()
        encryptionCounter = Counter()
        decryptionCounter = Counter()
        
        # Register a task monitor callback to increment encryptionCounter once 
        # for each 5% progress of encryption
        def encryption_callback(tm):
            encryptionCounter.increment()
        
        task_monitor.add_on_progress_percent_callback(encryption_callback, 
                                                      percent_span = 5.0)
        
        # Encrypt the test message, passing the task monitor
        ciphertext = self.public_key.encrypt_text(self.message, 
                                                  task_monitor=task_monitor)
        
        # Unregister the encryption callback from the monitor and register 
        # a callback to increment decryptionCounter once for each 5% progress 
        # of decryption.
        task_monitor.remove_callback(encryption_callback)
        
        def decryption_callback(tm):
            decryptionCounter.increment()
        
        task_monitor.add_on_progress_percent_callback(decryption_callback, 
                                                      percent_span = 5.0)
        
        # Decrypt the message, passing the task monitor:
        self.private_key.decrypt_to_text(ciphertext, task_monitor=task_monitor)
        
        # Check that both counters have been incremented 100/5 = 20 times
        self.assertEqual(encryptionCounter.value, 20)
        self.assertEqual(decryptionCounter.value, 20)
        
    def test_decryption_incompatible_cyphertext_error(self):
        """
        Test that attempting to decrypt a ciphertext with a private key that is 
        not the pair of the public key with which it was created raises an 
        IncompatibleCiphertextError exception.
        """
        # Use the public key to encrypt the message
        ciphertext = self.public_key.encrypt_text(self.message)
        
        # Generate a new key pair and take its private key
        other_key_pair = self.cryptosystem.new_key_pair()
        other_private_key = other_key_pair.private_key
        
        # This key should no be capable of decrypting the ciphertext and an 
        # error should be raised
        self.assertRaises(IncompatibleCiphertextError, 
                          other_private_key.decrypt_to_text, ciphertext)
        
    def test_decryption_incompatible_cyphertext_error_cryptosys_bits(self):
        """
        Test that attempting to decrypt a ciphertext with a private key 
        generated using a cryptosystem of a different bit size (nbits) than the 
        one of the public key used to encrypt the ciphertext raises an 
        IncompatibleCiphertextError exception.
        """
        # For coverage completeness (A different error message is raised when 
        # the problem is an incompatible size for the cryptosystem than for any 
        # other incompatible private key).
        
        # Use the public key to encrypt the message
        ciphertext = self.public_key.encrypt_text(self.message)
        
        # Construct a new 128 bits (terribly unsafe) cryptosystem
        other_cryptosys = EGCryptoSystem.new(nbits=128)
        
        # Generate a new key pair using this cryptosystem and take its private 
        # key
        other_key_pair = other_cryptosys.new_key_pair()
        other_private_key = other_key_pair.private_key
        
        # This key should no be capable of decrypting the ciphertext and an 
        # error should be raised
        self.assertRaises(IncompatibleCiphertextError, 
                          other_private_key.decrypt_to_text, ciphertext)
        
    def test_encrypt_message_to_large(self):
        """
        Test that attempting to encrypt a message larger than 16 Exabits 
        results in ValueError being raised.
        """
        # 16 Eb is the maximum size supported for plaintext to be encrypted. 
        # Since generating 16 Eb of data for this test is unfeasible, we 
        # instead will mock-up a fake BitStream class that reports having more  
        # than 16 Eb of data.
        # This class only implements the methods currently used by 
        # PublicKey.encrypt_bitstream(...). Should that method start using 
        # other BitStream methods, our fake bitstream will also need to be 
        # modified to simulate them.
        class ZeroedFakeBitStream:
            def __init__(self, reported_size):
                self.reported_size = reported_size
                self.pos = 0
            def get_length(self):
                return self.reported_size
            def get_current_pos(self):
                return self.pos
            def seek(self, pos):
                self.pos = pos
            def get_num(self, bit_length):
                return 0
        
        # Create a new ZeroedFakeBitStream with reported size 2**65 (32 Eb)
        huge_bs = ZeroedFakeBitStream(2**65)
        
        # Check that encrypt_bitstream raises a value error when given the 
        # "32 Eb bitstream"
        self.assertRaises(ValueError, 
                          self.public_key.encrypt_bitstream, huge_bs)
        

class TestPublicKeySerialization(unittest.TestCase):
    """
    Test that PublicKey objects can be serialized to and deserialized from file.
    """
    
    def setUp(self):
        """
        Unit test setup method.
        """
        # Get the ElGamal cryptosystem to use
        self.cryptosystem = get_cryptosystem()
        
    def test_get_fingerprint(self):
        """
        Test that PublicKey.get_fingerprint() always returns the same 
        fingerprint for the same PublicKey object and a different one for 
        another object.
        """
        # Create two public keys from the same cryptosystem
        public_key1 = self.cryptosystem.new_key_pair().public_key
        public_key2 = self.cryptosystem.new_key_pair().public_key
        
        # And a third from a different (insecure, 128bit) cryptosystem
        insecure_cryptosys = EGCryptoSystem.new(nbits=128)
        public_key3 = insecure_cryptosys.new_key_pair().public_key
        
        # Get each key's fingerprint
        pk1_fingerprint = public_key1.get_fingerprint()
        pk2_fingerprint = public_key2.get_fingerprint()
        pk3_fingerprint = public_key3.get_fingerprint()
        
        # Test that multiple calls to get_fingerprint() for the same PublicKey 
        # object always return the same fingerprint
        for i in range(0, 20):
            self.assertEqual(public_key1.get_fingerprint(), pk1_fingerprint)
            self.assertEqual(public_key2.get_fingerprint(), pk2_fingerprint)
            self.assertEqual(public_key3.get_fingerprint(), pk3_fingerprint)
            
        # Check that fingerprints from different PublicKey objects are 
        # different
        self.assertFalse(pk1_fingerprint == pk2_fingerprint)
        self.assertFalse(pk1_fingerprint == pk3_fingerprint)
        self.assertFalse(pk2_fingerprint == pk3_fingerprint)
        
        
    def test_save_load_file(self):
        """
        Test that we can correctly save a PublicKey to a file and load it 
        back. 
        """
        # Get a new public key object
        key = self.cryptosystem.new_key_pair().public_key
        
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
        recovered_key = PublicKey.from_file(file_path)
                                         
        # Get the fingerprint of the recovered key
        recovered_fingerprint = recovered_key.get_fingerprint()
        
        # Check that the fingerprints match (and thus they're the same key)
        self.assertEqual(recovered_fingerprint, original_fingerprint)
        
        # Also check that the == operator recognizes them as equal
        self.assertEqual(recovered_key, key)
        self.assertFalse(recovered_key != key)
        
        # Delete the temporary file
        os.remove(file_path)
                          
    def test_load_invalid_file(self):
        """
        Test that loading a public key from a file in an invalid format 
        raises an appropriate exception.
        """
        # Construct the path to the directory where our invalid test files are 
        # located:
        invalid_files_dir = os.path.join(os.path.dirname(__file__), 
                                         "TestBasicEncryption.resources",
                                         "invalid_publickey_xml_files")
        
        # Add invalid private key files as needed                               
        for file_name in ["err_missing_pub_key_elem.pvpubkey",
                          "err_not_number_prime_elem.pvpubkey",
                          "err_pub_key_too_large.pvpubkey"]:
            inv_file = os.path.join(invalid_files_dir, file_name)
            self.assertRaises(InvalidPloneVoteCryptoFileError, 
                              PublicKey.from_file, inv_file)
                              
    # TODO: Test loading a serialized ThresholdPublicKey
    # (Should work as soon as ThresholdPublicKey becomes serialize-enabled)
        

class TestPrivateKeySerialization(unittest.TestCase):
    """
    Test that PrivateKey objects can be serialized to and deserialized from file
    """
    
    def setUp(self):
        """
        Unit test setup method.
        """
        # Get the ElGamal cryptosystem to use
        self.cryptosystem = get_cryptosystem()
        
    def test_equality_inequality(self):
        """
        Test PrivateKey's equality (==) and inequality (!=) operators.
        """
        # Create two different private keys:
        key1 = self.cryptosystem.new_key_pair().private_key
        key2 = self.cryptosystem.new_key_pair().private_key
        
        # Each key is equal to itself
        self.assertTrue(key1 == key1)
        self.assertFalse(key1 != key1)
        self.assertTrue(key2 == key2)
        self.assertFalse(key2 != key2)
        
        # They are not equal one to the other
        self.assertTrue(key1 != key2)
        self.assertFalse(key1 == key2)
        
    def test_save_load_file(self):
        """
        Test that we can encrypt a message, save it to file, load it again and 
        decrypt it. 
        """
        # Get a new private key object
        key = self.cryptosystem.new_key_pair().private_key
        
        # Get a temporary file object using tempfile
        (file_object, file_path) = tempfile.mkstemp()
        
        # We close the file descriptor since we will not be using it, instead 
        # PrivateKey's methods take the filename and open/close the file as 
        # needed.
        # Note that using mkstemp() instead tempfile.TemporaryFile means the 
        # file remains in the filesystem even after it is closed.
        os.close(file_object)
        
        # Save the key using to_file(...)
        key.to_file(file_path)
        
        # Load it back using PrivateKey.from_file(...)
        recovered_key = PrivateKey.from_file(file_path)
        
        # Check that the recovered key is the same as the original key
        self.assertEqual(recovered_key, key)
        self.assertFalse(recovered_key != key)
        
        # Delete the temporary file
        os.remove(file_path)
                          
    def test_load_invalid_file(self):
        """
        Test that loading a private key from a file in an invalid format 
        raises an appropriate exception.
        """
        # Construct the path to the directory where our invalid test files are 
        # located:
        invalid_files_dir = os.path.join(os.path.dirname(__file__), 
                                         "TestBasicEncryption.resources",
                                         "invalid_privatekey_xml_files")
        
        # Add invalid private key files as needed                               
        for file_name in ["err_missing_priv_key_elem.pvprivkey",
                          "err_not_number_prime_elem.pvprivkey",
                          "err_priv_key_too_large.pvprivkey"]:
            inv_file = os.path.join(invalid_files_dir, file_name)
            self.assertRaises(InvalidPloneVoteCryptoFileError, 
                              PrivateKey.from_file, inv_file)
         
        

class TestCiphertextSerialization(unittest.TestCase):
    """
    Test that we can serialize a Ciphertext object to file and deserialize it 
    from file.
    """
    
    def setUp(self):
        """
        Unit test setup method.
        """
        # Get the ElGamal cryptosystem to use
        self.cryptosystem = get_cryptosystem()
        
        # Generate a key pair
        key_pair = self.cryptosystem.new_key_pair()
        self.public_key = key_pair.public_key
        self.private_key = key_pair.private_key
        
        # A message used to for encryption/decryption
        self.message = "This string will be encrypted and then decrypted. It " \
                       "contains some non-ascii chars and control chars:\n\t" \
                       "ÄäÜüß ЯБГДЖЙŁĄŻĘĆŃŚŹ てすと ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃ." 
        
    def test_equality_inequality(self):
        """
        Test Ciphertext's equality (==) and inequality (!=) operators.
        """
        # Create two different ciphertext (even if from the SAME plaintext):
        ciph1 = self.public_key.encrypt_text(self.message)
        ciph2 = self.public_key.encrypt_text(self.message)
        
        # Each ciphertext is equal to itself
        self.assertTrue(ciph1 == ciph1)
        self.assertFalse(ciph1 != ciph1)
        self.assertTrue(ciph2 == ciph2)
        self.assertFalse(ciph2 != ciph2)
        
        # They are not equal one to the other
        self.assertTrue(ciph1 != ciph2)
        self.assertFalse(ciph1 == ciph2)
        
    def test_get_fingerprint(self):
        """
        Test that Ciphertext.get_fingerprint() always returns the same 
        fingerprint for the same Ciphertext object and a different one for 
        another object.
        """
        # Create two ciphertext from the same public key and message
        ciph1 = self.public_key.encrypt_text(self.message)
        ciph2 = self.public_key.encrypt_text(self.message)
        
        # And a third from a different key and message
        new_public_key = self.cryptosystem.new_key_pair().public_key
        ciph3 = new_public_key.encrypt_text("New message")
        
        # Get each ciphertext's fingerprint
        ciph1_fingerprint = ciph1.get_fingerprint()
        ciph2_fingerprint = ciph2.get_fingerprint()
        ciph3_fingerprint = ciph3.get_fingerprint()
        
        # Test that multiple calls to get_fingerprint() for the same Ciphertext 
        # object always return the same fingerprint
        for i in range(0, 20):
            self.assertEqual(ciph1.get_fingerprint(), ciph1_fingerprint)
            self.assertEqual(ciph2.get_fingerprint(), ciph2_fingerprint)
            self.assertEqual(ciph3.get_fingerprint(), ciph3_fingerprint)
            
        # Check that fingerprints from different Ciphertext objects are 
        # different
        self.assertFalse(ciph1_fingerprint == ciph2_fingerprint)
        self.assertFalse(ciph1_fingerprint == ciph3_fingerprint)
        self.assertFalse(ciph2_fingerprint == ciph3_fingerprint)
        
    def test_save_load_file(self):
        """
        Test that we can correctly save a PrivateKey to a file and load it 
        back. 
        """
        # Use the public key to encrypt the message
        ciphertext = self.public_key.encrypt_text(self.message)
        
        # Get a temporary file object using tempfile
        (file_object, file_path) = tempfile.mkstemp()
        
        # We close the file descriptor since we will not be using it, instead 
        # Ciphertext's methods take the filename and open/close the file as 
        # needed.
        # Note that using mkstemp() instead tempfile.TemporaryFile means the 
        # file remains in the filesystem even after it is closed.
        os.close(file_object)
        
        # Save the ciphertext using to_file(...)
        ciphertext.to_file(file_path)
        
        # Load it back using Ciphertext.from_file(...)
        recovered_ciphertext = Ciphertext.from_file(file_path)
        
        # Check that the recovered ciphertext is recognized as equal to the 
        # original ciphertext
        self.assertEqual(recovered_ciphertext, ciphertext)
        self.assertFalse(recovered_ciphertext != ciphertext)
        
        # then use the private key to decrypt the deserialized ciphertext
        recovered_message = \
            self.private_key.decrypt_to_text(recovered_ciphertext)
        
        # Check that the message was recovered correctly
        self.assertEqual(recovered_message, self.message)
        
        # Delete the temporary file
        os.remove(file_path)
                          
    def test_load_invalid_file(self):
        """
        Test that loading a ciphertext from a file in an invalid format raises 
        an appropriate exception.
        """
        # Construct the path to the directory where our invalid test files are 
        # located:
        invalid_files_dir = os.path.join(os.path.dirname(__file__), 
                                         "TestBasicEncryption.resources",
                                         "invalid_ciphertext_xml_files")
        
        # Add invalid ciphertext files as needed                               
        for file_name in ["err_missing_enc_data.pvencrypted", 
                          "err_invalid_nbits.pvencrypted"]:
            inv_file = os.path.join(invalid_files_dir, file_name)
            self.assertRaises(InvalidPloneVoteCryptoFileError, 
                              Ciphertext.from_file, inv_file)


if __name__ == '__main__':
    unittest.main()
