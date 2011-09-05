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
        # Adding the first  trustees  commitments 
        for i in range(self.num_trustees):
           self.tSetUp.add_trustee_commitment(i, self.commitments[i])
         
        self.tpkey = ThresholdPublicKey(self.tSetUp.cryptosystem, 
                                  self.tSetUp._num_trustees, 
                                  self.tSetUp._threshold, 
                                  key, partial_public_keys)  
 
            
    def test_privatekey_generation(self):
        """
        Create a new ThresholdPrivateKey, verify that is created correctly
        """
        
        privatekey = ThresholdPrivateKey(self.tSetUp.crytosystem, 
                                         self.num_trustees,
                                         self.threshold, self.tpkey,
                                         self.trustees[0].private_key)
                                         
        # The values of the parameters must be the same we expect
        self.assertEquals(privatekey.cryptosystem, self.tSetUp.crytosystem)
        self.assertEquals(privatekey.num_trustees, self.num_trustees)
        self.assertEquals(privatekey.
