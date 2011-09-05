# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestThresholdEncryptionSetUp.py : Unit tests for 
#                    plonevotecryptolib/Threshold/ThresholdEncryptionSetUp.py
#
#  For usage documentation of ThresholdEncryptionSetUp.py, see, besides this 
#  file:
#    * plonevotecryptolib/tests/doctests/full_election_doctest.txt
#    * the documentation strings for the classes and methods of 
#      ThresholdEncryptionSetUp.py
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

class TestThresholdEncryptionSetUp(unittest.TestCase):
    """
    Test the class: plonevotecryptolib.Threshold.ThresholdEncryptionSetUp.
    ThresholdEncryptionSetUp
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
        
    
    def test_commitment_generation(self):
        """
        Create a new ThresholdEncryptionSetUp, add the keys from trustees
        and generate a commitment from those keys.        
        """
        
        cryptosystem = get_cryptosystem()
        
        # Generate a new instance of ThresholdEncryptionSetUp
        tSetUp = ThresholdEncryptionSetUp(cryptosystem, 
                                          self.num_trustees, self.threshold)
                                          
        # Create another trustee to generate and prove errors
        errorTrustee = Trustee()
                                          
        # Must raise ValueError with invalid trustee value 
        self.assertRaises(ValueError, tSetUp.add_trustee_public_key, 
                                      -1, errorTrustee)
        self.assertRaises(ValueError, tSetUp.add_trustee_public_key, 
                                      6, errorTrustee)
        
        
        # Must raise ThresholdEncryptionSetUpStateError with an invalid amount
        # of trustee keys (0)
        self.assertRaises(ThresholdEncryptionSetUpStateError, 
                          tSetUp.generate_commitment)
        
        # Adding the first  self.num_trustees - 1 keys from trustees
        for i in range(self.num_trustees - 1):
           tSetUp.add_trustee_public_key(i, self.trustees[i].public_key)
           
        # Must raise ThresholdEncryptionSetUpStateError with an invalid amount
        # of trustee keys (self.num_trustees - 1)
        self.assertRaises(ThresholdEncryptionSetUpStateError, 
                          tSetUp.generate_commitment) 
                         
        # Add the las key from trustees 
        tSetUp.add_trustee_public_key(self.num_trustees - 1, 
                                self.trustees[self.num_trustees - 1].public_key)
           
        
        # Generate a commitment    
        commitment = tSetUp.generate_commitment()
        
        # We check the cryptosystem, trustees number and threshold from the
        # obtained commitment, must be the same we used to create the  
        # ThresholdEncryptionSetUp object 
        self.assertEqual(commitment.cryptosystem, cryptosystem)
        self.assertEqual(commitment.num_trustees, self.num_trustees)
        self.assertEqual(commitment.threshold, self.threshold)
        
        # public_coefficients must have self.threshold coefficients with the  
        # form cryptosystem.generator^c % cryptosystem.prime where c is a  
        # random number in Z_{q}^* (prime = 2q + 1).
        # We check theres is self.threshold coefficients and they are in 
        # Z_{p}^*
        self.assertEqual(len(commitment.public_coefficients), self.threshold)
        for coeff in commitment.public_coefficients:
            self.assertTrue(1 <= coeff < cryptosystem.get_prime())
        
        # encrypted_partial_private_keys has the values of a polynomial in 
        # Z_{q}^* in some point , encrypted with the private key of the 
        # correesponding trustee
        
        # There should be as many encrypted_partial_private_keys as trustees.
        self.assertEqual(len(commitment.encrypted_partial_private_keys), 
                         self.num_trustees)
        
        # Decrypt every partial private key and check that their values are in  
        # Z_{q}^*
        q = (cryptosystem.get_prime() - 1) / 2  # p = 2q + 1                
        for i in range(self.num_trustees):
            priv_key = self.trustees[i].private_key
            
            # Decrypt
            enc_pp_key = commitment.encrypted_partial_private_keys[i]
            bitstream = priv_key.decrypt_to_bitstream(enc_pp_key)
            bitstream.seek(0)
            pp_key = bitstream.get_num(cryptosystem.get_nbits())
            
            # Check the value myst be in Z_{q}^*
            self.assertTrue(1 <= pp_key < q)
            
    def test_commitmet_adding(self):    
        """
        Creates a new ThresholdEncryptionSetUp and try to add a trustee c
        commitment        
        """
        cryptosystem = get_cryptosystem()
        
        # Generate a new instance of ThresholdEncryptionSetUp
        tSetUp = ThresholdEncryptionSetUp(cryptosystem, 
                                          self.num_trustees, self.threshold)
                                         
        # Adding the keys from trustees
        for i in range(self.num_trustees):
            tSetUp.add_trustee_public_key(i, self.trustees[i].public_key)
        
        # Generate and add a valid commitment
        commitment = tSetUp.generate_commitment()   
        tSetUp.add_trustee_commitment(0, commitment)
        
        #The commitment for trustee 0 must be the same we just add
        self.assertEqual(tSetUp._trustees_commitments[0], commitment)
        
        # add_trustee_commitmnet must raise ValueError with invalid trustee  
        # values (-1 and self.num_trustees+1)
        self.assertRaises(ValueError, tSetUp.add_trustee_commitment,
                                     -1, commitment)
        self.assertRaises(ValueError, tSetUp.add_trustee_commitment, 
                                      self.num_trustees+1, commitment)
                                      
        # Change commitment.num_trustees value to try erros
        commitment.num_trustees = self.num_trustees +1
        # add_trustee_commitmnet must raise IncompatibleCommitmentError when
        # the commitment has diferent num_trustees value
        self.assertRaises(IncompatibleCommitmentError, 
                          tSetUp.add_trustee_commitment, 1, commitment)
                          

        # Change commitment.threshold value to try erros
        commitment.num_trustees = self.num_trustees
        commitment.threshold = self.threshold+1
        # add_trustee_commitmnet must raise IncompatibleCommitmentError when
        # the commitment has diferent theshold  value
        self.assertRaises(IncompatibleCommitmentError, 
                          tSetUp.add_trustee_commitment, 1, commitment)
                          
        # Test what happens with invalid cryptosystem
        # Create another cryptosystem
        second_cryptosys_file = os.path.join(os.path.dirname(__file__), 
                                      "TestThresholdEncryptionSetUp.resources",
                                      "test1024bits_second.pvcryptosys")
        # Load the cryptosystem from file
        second_cryptosys = EGCryptoSystem.from_file(second_cryptosys_file)
        commitment.threshold = self.threshold
        commitment.cryptosystem = second_cryptosys
        # Must raise IncompatibleCommitmentError with diferent cryptosys  
        self.assertRaises(IncompatibleCommitmentError, 
                          tSetUp.add_trustee_commitment, 1, commitment)
        
                          
    def test_get_fingerprint(self):    
        """
        Creates a new ThresholdEncryptionSetUp and generate commitments for 
        all trustees add them to the  ThresholdEncryptionSetUp
        an get a fingerpint
        """
        cryptosystem = get_cryptosystem()
        
        # Generate a new instance of ThresholdEncryptionSetUp
        tSetUp = ThresholdEncryptionSetUp(cryptosystem, 
                                          self.num_trustees, self.threshold)                         
        # Adding the keys from trustees
        for i in range(self.num_trustees):
            tSetUp.add_trustee_public_key(i, self.trustees[i].public_key)
        
        # Generate commitmes for trustees
        for i in range(self.num_trustees):
            self.commitments.append(tSetUp.generate_commitment()) 
            
        # get_fingerprint must raise ThresholdEncryptionSetUpStateError
        # if called without added commitments
        self.assertRaises(ThresholdEncryptionSetUpStateError, 
                          tSetUp.get_fingerprint)
                          
        # Adding the first  self.num_trustees - 1 commitments from trustees
        for i in range(self.num_trustees - 1):
           tSetUp.add_trustee_commitment(i, self.commitments[i])
           
        # get_fingerprint must raise ThresholdEncryptionSetUpStateError
        # if called without all added commitments
        self.assertRaises(ThresholdEncryptionSetUpStateError, 
                          tSetUp.get_fingerprint) 
                         
        # Add the last commitments from trustees 
        tSetUp.add_trustee_commitment(self.num_trustees - 1, 
                                self.commitments[self.num_trustees - 1])
                                
        # Create 2 fingerpints and they must match
        fingerprint = tSetUp.get_fingerprint()
        fingerprintb = tSetUp.get_fingerprint()
        self.assertEquals(fingerprint,fingerprintb)
        
        # We create a diferent ThresholdEncryptionSetUp to genera another 
        # fingerprint that should not match
        tSetUp2 = ThresholdEncryptionSetUp(cryptosystem, 
                                          self.num_trustees-1, self.threshold-1)                         
        for i in range(self.num_trustees-1):
            tSetUp2.add_trustee_public_key(i, self.trustees[i].public_key)
        commitments2 = []
        for i in range(self.num_trustees-1):
            commitments2.append(tSetUp2.generate_commitment()) 
        for i in range(self.num_trustees - 1):
           tSetUp2.add_trustee_commitment(i, commitments2[i])
        fingerprint2 = tSetUp2.get_fingerprint()
        
        # figerprints generate from diferent ThresholdEncryptionSetUp 
        # must be diferent
        self.assertNotEqual(fingerprint,fingerprint2)
           
    def test_generate_publickey(self):
        """
        Creates a new ThresholdEncryptionSetUp and generate commitments for 
        all trustees add them to the  ThresholdEncryptionSetUp
        and generate a public key
        """
        cryptosystem = get_cryptosystem()
        
        # Generate a new instance of ThresholdEncryptionSetUp
        tSetUp = ThresholdEncryptionSetUp(cryptosystem, 
                                          self.num_trustees, self.threshold)                         
        # Adding the keys from trustees
        for i in range(self.num_trustees):
            tSetUp.add_trustee_public_key(i, self.trustees[i].public_key)
        
        # Generate commitmes for trustees
        for i in range(self.num_trustees):
            self.commitments.append(tSetUp.generate_commitment()) 
            
        # generate_commitment must raise ThresholdEncryptionSetUpStateError
        # if called without added commitments
        self.assertRaises(ThresholdEncryptionSetUpStateError, 
                          tSetUp.generate_public_key)
                          
        # Adding the first  self.num_trustees - 1 commitments from trustees
        for i in range(self.num_trustees - 1):
           tSetUp.add_trustee_commitment(i, self.commitments[i])
           
        # generate_commitment must raise ThresholdEncryptionSetUpStateError
        # if called without all added commitments
        self.assertRaises(ThresholdEncryptionSetUpStateError, 
                          tSetUp.generate_public_key) 
                         
        # Add the last commitments from trustees 
        tSetUp.add_trustee_commitment(self.num_trustees - 1, 
                                self.commitments[self.num_trustees - 1])
                                
        publickey = tSetUp.generate_public_key()
        
        # The generated public key must have the same cryptosystem, trustees 
        # and threshold
        self.assertEqual(publickey.cryptosystem, cryptosystem)
        self.assertEqual(publickey.num_trustees, self.num_trustees)
        self.assertEqual(publickey.threshold, self.threshold)
        
        # Check that multiple calls generate the same public key
        publickey2 = tSetUp.generate_public_key()
        self.assertEqual(publickey2, publickey)
        self.assertEqual(publickey2.get_fingerprint(), 
                         publickey.get_fingerprint())

    def test_generate_keypar(self):
        """
        Creates a new ThresholdEncryptionSetUp and generate commitments for 
        all trustees add them to the  ThresholdEncryptionSetUp
        and generate a key par
        """
        cryptosystem = get_cryptosystem()
        
        # Generate a new instance of ThresholdEncryptionSetUp
        tSetUp = ThresholdEncryptionSetUp(cryptosystem, 
                                          self.num_trustees, self.threshold)                         
        # Adding the keys from trustees
        for i in range(self.num_trustees):
            tSetUp.add_trustee_public_key(i, self.trustees[i].public_key)
        
        # Generate commitmes for trustees
        for i in range(self.num_trustees):
            self.commitments.append(tSetUp.generate_commitment()) 
            
        # generate_key_pair must raise ThresholdEncryptionSetUpStateError
        # if called without added commitments
        self.assertRaises(ThresholdEncryptionSetUpStateError, 
                          tSetUp.generate_key_pair,
                          0,self.trustees[0].private_key)
                          
        # Adding the first  self.num_trustees - 1 commitments from trustees
        for i in range(self.num_trustees - 1):
           tSetUp.add_trustee_commitment(i, self.commitments[i])
           
        # generate_key_pair must raise ThresholdEncryptionSetUpStateError
        # if called without all added commitments
        self.assertRaises(ThresholdEncryptionSetUpStateError, 
                          tSetUp.generate_key_pair,
                          0,self.trustees[0].private_key)
                         
        # Add the last commitments from trustees 
        tSetUp.add_trustee_commitment(self.num_trustees - 1, 
                                self.commitments[self.num_trustees - 1])
                                
        # Must fail if the trustee doenst have his corresponding private_key
        self.assertRaises(InvalidCommitmentError,tSetUp.generate_key_pair,
                          0,self.trustees[1].private_key)
       
        #TODO:
        # How to test malicious commitmens or invalid ones                
        keypar = tSetUp.generate_key_pair(0,self.trustees[0].private_key)
        
        # Create a second ThresholdEcryptionSetUp to create a second
        # thresold ebcryption set up and generate errors
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
        
        # Must raise InvalidCommitmentError becouse we adding an invalid
        # commitment
        commitemp = tSetUp._trustees_commitments[0]
        tSetUp._trustees_commitments[0] = secondcommitments[0]     
        self.assertRaises(InvalidCommitmentError,tSetUp.generate_key_pair,
                          0,self.trustees[0].private_key)
        tSetUp._trustees_commitments[0] = commitemp
                          
        # Must Raise InvalidCommitmentError becouse we are modifying a
        # public coefficient from a trustee
        tSetUp._trustees_commitments[0].public_coefficients[0] = 2;
        self.assertRaises(InvalidCommitmentError,tSetUp.generate_key_pair,
                          0,self.trustees[0].private_key)                          
        
            
        
             
    def test_generate_privatekey(self):
        """
        Creates a new ThresholdEncryptionSetUp and generate commitments for 
        all trustees add them to the  ThresholdEncryptionSetUp
        and generate a private key
        """
        cryptosystem = get_cryptosystem()
        
        # Generate a new instance of ThresholdEncryptionSetUp
        tSetUp = ThresholdEncryptionSetUp(cryptosystem, 
                                          self.num_trustees, self.threshold)                         
        # Adding the keys from trustees
        for i in range(self.num_trustees):
            tSetUp.add_trustee_public_key(i, self.trustees[i].public_key)
        
        # Generate commitmes for trustees
        for i in range(self.num_trustees):
            self.commitments.append(tSetUp.generate_commitment()) 
            
        # generate_private_key must raise ThresholdEncryptionSetUpStateError
        # if called without added commitments
        self.assertRaises(ThresholdEncryptionSetUpStateError, 
                          tSetUp.generate_private_key,
                          0,self.trustees[0].private_key)
                          
        # Adding the first  self.num_trustees - 1 commitments from trustees
        for i in range(self.num_trustees - 1):
           tSetUp.add_trustee_commitment(i, self.commitments[i])
           
        # generate_private_key must raise ThresholdEncryptionSetUpStateError
        # if called without all added commitments
        self.assertRaises(ThresholdEncryptionSetUpStateError, 
                          tSetUp.generate_private_key,
                          0,self.trustees[0].private_key)
                         
        # Add the last commitments from trustees 
        tSetUp.add_trustee_commitment(self.num_trustees - 1, 
                                self.commitments[self.num_trustees - 1])
                                
        # Must fail if the trustee doenst have his corresponding private_key
        self.assertRaises(InvalidCommitmentError,tSetUp.generate_private_key,
                          0,self.trustees[1].private_key)
                     
        privatekey = tSetUp.generate_private_key(0,self.trustees[0].private_key)
        
        # The privatekey atributes must be the expected from  tSetUp
        self.assertTrue(privatekey.cryptosystem, cryptosystem)
        self.assertEqual(privatekey.num_trustees, self.num_trustees)
        self.assertEqual(privatekey.threshold, self.threshold)
        self.assertEqual(privatekey.public_key, 
                         tSetUp.generate_public_key()) 
        
             
if __name__ == '__main__':
    unittest.main()        
    
