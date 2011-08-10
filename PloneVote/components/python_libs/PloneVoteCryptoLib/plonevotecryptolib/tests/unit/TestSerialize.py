# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestSerialize.py : Unit tests for 
#                       plonevotecryptolib/utilities/serialize.py
#
#  For usage documentation of serialize.py, see, besides this file:
#    * the documentation strings for the module, classes and methods in 
#      serialize.py
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

# Main library PloneVoteCryptoLib imports
import plonevotecryptolib.utilities.serialize as serialize
    
# ============================================================================
# Example structure definitions:
# ============================================================================

person_structure_definition = {
        "person" : (1, 1, {                 # Root element
            "names" : (1, 1, {              # 1 "names" node allowed, exactly
                "first" : (1, None),        # 1 or more first names allowed
                "middle" : (None),          # 0 or more middle names allowed
                "last" : (1, None)          # 1 or more last names allowed
            }),
            "age" : (1, 1, None)            # 1 age allowed, exactly
        }),
    }
    
# ============================================================================
# Test cases:
# ============================================================================

class TestSerialize(unittest.TestCase):
    """
    Test the plonevotecryptolib.utilities.serialize module
    """
    
    def setUp(self):
        """
        Test fixture set up code.
        
        1) Create a temporary empty file and store its filename in 
           self.filename 
        """
        # Get a temporary file object using tempfile
        (file_object, file_path) = tempfile.mkstemp()
        self.filename = file_path
        
        # Close the file descriptor.
        # Note that using mkstemp() instead tempfile.TemporaryFile means the 
        # file remains in the filesystem even after it is closed.
        os.close(file_object)
    
    def tearDown(self):  
        """
        Test fixture clean up code. 
        """  
        # Delete the temporary file
        os.remove(self.filename)
    
    def test_xml_serialize_deserialize_file(self):
        """
        Test that we can serialize some data to an XML file using XMLSerializer 
        and deserialize it back.
        """
        # Create a new XMLSerializer object using the person structure 
        # definition dictionary.
        xmlSerializer = serialize.XMLSerializer(person_structure_definition)
        
        # Use this XMLSerializer to serialize some valid person data into an 
        # XML file at self.filename
        data = {
            "person" : {
                "names" : {
                    "first" : "Pedro",           # Note: no middle name
                    "last" : [                   # Multiple last names
                        "Pérez",
                        "Hernández"
                    ]
                },
                "age" : "42"
            }
        }
        
        xmlSerializer.serialize_to_file(self.filename, data)
        
        # Recover the data from file using a new XMLSerializer with the same 
        # structure definition dictionary
        xmlSerializer2 = serialize.XMLSerializer(person_structure_definition)
        deserialized_data = xmlSerializer2.deserialize_from_file(self.filename)
        
        # Check that the recovered data is the same as that original written
        self.assertEqual(deserialized_data, data)
        


if __name__ == '__main__':
    unittest.main()
