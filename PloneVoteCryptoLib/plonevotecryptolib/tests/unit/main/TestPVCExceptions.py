# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestSerialize.py : Unit tests for 
#                       plonevotecryptolib/PVCExceptions.py
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

# Main library PloneVoteCryptoLib imports
from plonevotecryptolib.PVCExceptions import *
    
# ============================================================================
# Test cases:
# ============================================================================

class TestPVCExceptions(unittest.TestCase):
    """
    Test the plonevotecryptolib.PVCExceptions module
    """        
        
    # Simply test all exception classes within PVCExceptions.py:
    
    def test_exceptions(self):
        """
        Test that all exceptions declared in PVCExceptions.py can be 
        constructed, raised and queried for an exception message.
        """        
        message = "My message: ñ(&(%%9_\n\t"
        
        # List of exceptions to test, accompanied by the list of the arguments 
        # to their constructors
        for ExceptionCls, args in \
                    [(ParameterError, (message)),
                     (ElectionSecurityError, (message)),
                     (KeyLengthTooLowError, (128, 2048, message)),
                     (KeyLengthNonBytableError, (127, message)),
                     (KeyLengthMismatch, (message)),
                     (NotASafePrimeError, (0, message)),
                     (NotAGeneratorError, (1, 0, message)),
                     (InvalidPloneVoteCryptoFileError, ("file.ext", message)),
                     (IncompatibleCiphertextError, (message)),
                     (IncompatibleReencryptionInfoError, (message)),
                     (IncompatibleCiphertextCollectionError, (message)),
                     (IncompatibleCiphertextCollectionMappingError, (message)),
                     (InvalidCiphertextCollectionMappingError, (message)),
                     (InvalidShuffilingProofError, (message)),
                     (ThresholdEncryptionSetUpStateError, (message)),
                     (IncompatibleCommitmentError, (message)),
                     (InvalidCommitmentError, (0, None, message))]:
        
            was_raised = False
            
            try:
                if(type(args) == tuple):    # single item tuple gets unpacked
                    raise ExceptionCls(*args)
                else:
                    raise ExceptionCls(args)
            except ExceptionCls, e:
                was_raised = True
                self.assertEqual(str(e), message)
                
            self.assertEqual(was_raised, True) 
         
        # Special cases:

        # EGCSUnconstructedStateError takes no custom error message, 
        # check only that it can be raised and its message read
        was_raised = False
        try:
            raise EGCSUnconstructedStateError()
        except EGCSUnconstructedStateError, e:
            was_raised = True
            self.assertTrue(len(str(e)) > 0)


if __name__ == '__main__':
    unittest.main()
