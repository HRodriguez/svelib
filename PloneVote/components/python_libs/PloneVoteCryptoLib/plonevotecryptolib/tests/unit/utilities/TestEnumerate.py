# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestEnumerate.py : Unit tests for plonevotecryptolib/utilities/Enumerate.py
#
#  For usage documentation of Enumerate.py, see the documentation strings for 
#  the classes and methods of Enumerate.py.
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
from plonevotecryptolib.utilities.Enumerate import Enumerate

class TestEnumerate(unittest.TestCase):
    """
    Test the class: plonevotecryptolib.utilities.Enumerate.Enumerate
    """
    
    def test_enumerate_basic(self):
        """
        Test enumerate basic behavior.
        """
        
        # Enumerate is a simple class that takes a sequence of strings as its 
        # arguments and returns an enumeration having those strings as keywords.
        # That is, o = Enumerate('A','B','C') gives us an object o with 
        # properties o.A, o.B and o.C, each with a distinct value.
        
        # First, lets check that we can construct an enumeration object:
        myEnum = Enumerate("Alpha","Beta","Gamma","Delta","Epsilon")
        
        # Check that the resulting object has the expected properties
        self.assertTrue(hasattr(myEnum, 'Alpha'))
        self.assertTrue(hasattr(myEnum, 'Beta'))
        self.assertTrue(hasattr(myEnum, 'Gamma'))
        self.assertTrue(hasattr(myEnum, 'Delta'))
        self.assertTrue(hasattr(myEnum, 'Epsilon'))
        
        # Check that storing elements of the enumeration and then checking for 
        # equality works as expected.
        allEnumValues = (myEnum.Alpha, myEnum.Beta, myEnum.Gamma, \
                         myEnum.Delta, myEnum.Epsilon)
        for enumVal in allEnumValues:
            val = enumVal
            self.assertEqual(val, enumVal)
        
        # Finally, we also must check that the values of the elements in the 
        # enumeration object are distinct/unique.
        # ie. o.X == o.Y iff 'X' == 'Y'
        self.assertNotEqual(myEnum.Alpha, myEnum.Beta)
        self.assertNotEqual(myEnum.Alpha, myEnum.Gamma)
        self.assertNotEqual(myEnum.Alpha, myEnum.Delta)
        self.assertNotEqual(myEnum.Alpha, myEnum.Epsilon)
        
        self.assertNotEqual(myEnum.Beta, myEnum.Alpha) # is == always symmetric?
        self.assertNotEqual(myEnum.Beta, myEnum.Gamma)
        self.assertNotEqual(myEnum.Beta, myEnum.Delta)
        self.assertNotEqual(myEnum.Beta, myEnum.Epsilon)
        
        self.assertNotEqual(myEnum.Gamma, myEnum.Alpha)
        self.assertNotEqual(myEnum.Gamma, myEnum.Beta)
        self.assertNotEqual(myEnum.Gamma, myEnum.Delta)
        self.assertNotEqual(myEnum.Gamma, myEnum.Epsilon)
        
        self.assertNotEqual(myEnum.Delta, myEnum.Alpha)
        self.assertNotEqual(myEnum.Delta, myEnum.Beta)
        self.assertNotEqual(myEnum.Delta, myEnum.Gamma)
        self.assertNotEqual(myEnum.Delta, myEnum.Epsilon)
        
        self.assertNotEqual(myEnum.Epsilon, myEnum.Alpha)
        self.assertNotEqual(myEnum.Epsilon, myEnum.Beta)
        self.assertNotEqual(myEnum.Epsilon, myEnum.Gamma)
        self.assertNotEqual(myEnum.Epsilon, myEnum.Delta)
        
     

if __name__ == '__main__':
    unittest.main()
