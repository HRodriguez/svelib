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

# A (simplified) structure definition for a "person" object
person_structure_definition = {
        "person" : (1, 1, {                 # Root element
            "names" : (1, 1, {              # 1 "names" node allowed, exactly
                "first" : (1, None),        # 1 or more first names allowed
                "middle" : (None),          # 0 or more middle names allowed
                "last" : (1, None)          # 1 or more last names allowed
            }),
            "age" : (1, 1, None)            # 1 age allowed, exactly
        })
    }

# A structure definition for a collection of books  
books_structure_definition = {
        "book" : (1, {                      # 1 or more "book" elements
            "title" : (1, 1, None),         # 1 title allowed, exactly
            "author" : (1, None),           # 1 or more authors allowed
            "year" : (1, 1, None)           # 1 year allowed, exactly
        })
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
    
    def test_xml_serialize_deserialize_file_books(self):
        """
        Test that we can serialize some data to an XML file using XMLSerializer 
        and deserialize it back, using the books_structure_definition 
        structure definition dictionary.
        
        This structure definition tests a few features not tested when using 
        person_structure_definition, namely:
            * A structure that has no single root element (multiple 'book' 
              elements at root level) while XML requires a single root element.
            * A composite element that can have more than one occurrences.
        """
        # Create a new XMLSerializer object using the books structure 
        # definition dictionary.
        xmlSerializer = serialize.XMLSerializer(books_structure_definition)
        
        # Use this XMLSerializer to serialize some valid books data into an 
        # XML file at self.filename
        data = {
            "book" : [{
                    "title" : "Introduction to Algorithms",
                    "author" : ["Thomas H. Cormen",
                            "Charles E. Leiserson",
                            "Ronald L. Rivest",
                            "Clifford Stein"
                        ],
                    "year" : "1990"    
                },
                {
                    "title" : "Design Patterns",
                    "author" : ["Erich Gamma",
                            "Richard Helm",
                            "Ralph Johnson",
                            "John Vlissides"
                        ],
                    "year" : "1994"                
                }]
        }
        
        xmlSerializer.serialize_to_file(self.filename, data)
        
        # Recover the data from file using a new XMLSerializer with the same 
        # structure definition dictionary
        xmlSerializer2 = serialize.XMLSerializer(books_structure_definition)
        deserialized_data = xmlSerializer2.deserialize_from_file(self.filename)
        
        # Check that the recovered data is the same as that original written
        self.assertEqual(deserialized_data, data)
        
        # Also check that deserializing with the wrong structure definition 
        # results in an exception
        xmlSerializer3 = serialize.XMLSerializer(person_structure_definition)        
        self.assertRaises(serialize.InvalidSerializeDataError, 
                          xmlSerializer3.deserialize_from_file, self.filename)
    
        
    def test_xml_serialize_deserialize_string(self):
        """
        Test that we can serialize some data to an XML string using 
        XMLSerializer and deserialize it back.
        """
        # Create a new XMLSerializer object using the person structure 
        # definition dictionary.
        xmlSerializer = serialize.XMLSerializer(person_structure_definition)
        
        # Use this XMLSerializer to serialize some valid person data into an 
        # XML string
        data = {
            "person" : {
                "names" : {
                    "first" : "Jane",
                    "middle" : "Ann",
                    "last" : "Smith"
                },
                "age" : "99"
            }
        }
        
        serialized_data = xmlSerializer.serialize_to_string(data)
        
        # Deserialize the data using a new XMLSerializer with the same 
        # structure definition dictionary
        xmlSerializer2 = serialize.XMLSerializer(person_structure_definition)
        deserialized_data = \
            xmlSerializer2.deserialize_from_string(serialized_data)
        
        # Check that the recovered data is the same as that original written
        self.assertEqual(deserialized_data, data)
    
    def test_structure_definition_different_root_elements(self):
        """
        Test that serialization and deserialization work for a structure 
        definition dictionary that has multiple distinct elements at the root 
        level (no single root and no multiple roots with the same element name).
        """
        # Use the following sample structure definition
        structure_def = {
            "A" : (1, 1, None),
            "B" : (1, 1, None)
        }
        # And corresponding data
        data = {"A": "Test1", "B": "Test2"}
        
        # Create an XMLSerializer for a new structure definition and use it to 
        # serialize the corresponding data into a string
        xmlSerializer = serialize.XMLSerializer(structure_def)
        serialized_data = xmlSerializer.serialize_to_string(data)
        
        # Deserialize the data using a new XMLSerializer with the same 
        # structure definition dictionary
        xmlSerializer2 = serialize.XMLSerializer(structure_def)
        deserialized_data = \
            xmlSerializer2.deserialize_from_string(serialized_data)
        
        # Check that the recovered data is the same as that original written
        self.assertEqual(deserialized_data, data)
        
    
    def test_invalid_structure_definition_dictionaries(self):
        """
        Test that constructing a serializer object with an invalid structure 
        definition dictionary passed to its constructor results in 
        InvalidSerializeStructureDefinitionError being raised.
        """
        # Let's abbreviate the exception name:
        invStructErr = serialize.InvalidSerializeStructureDefinitionError
        
        # Invalid structure definition: not a dictionary
        # This one actually raises AttributeError, but may raise any exception
        inv_structure = object()
        self.assertRaises(Exception, serialize.XMLSerializer, inv_structure)
        
        # Invalid structure definition: none tuple or list values for keys
        inv_structure = {
            "root" : (1, 1, {
                "A" : "InvalidData",
                "B" : (1, 1, None) 
            }),
        }
        self.assertRaises(invStructErr, serialize.XMLSerializer, inv_structure)
        
        # Invalid structure definition: tuples with 0 elements
        inv_structure = {
            "root" : (1, 1, {
                "A" : (),
                "B" : (1, 1, None) 
            }),
        }
        self.assertRaises(invStructErr, serialize.XMLSerializer, inv_structure)
        
        # Invalid structure definition: tuples with > 3 elements
        inv_structure = {
            "root" : (1, 1, {
                "A" : (1, 1, None, None),
                "B" : (1, 1, None) 
            }),
        }
        self.assertRaises(invStructErr, serialize.XMLSerializer, inv_structure)
        
        # Invalid structure definition: negative min_occurrences & 
        # max_occurrences
        inv_structure = {
            "root" : (1, 1, {
                "A" : (-1, -1, None),
                "B" : (1, 1, None) 
            }),
        }
        self.assertRaises(invStructErr, serialize.XMLSerializer, inv_structure)
        
        # Invalid structure definition: min_occurrences > max_occurrences
        inv_structure = {
            "root" : (1, 1, {
                "A" : (3, 2, None),
                "B" : (1, 1, None) 
            }),
        }
        self.assertRaises(invStructErr, serialize.XMLSerializer, inv_structure)
        
        # Invalid structure definition: sub structure not None or a dict
        inv_structure = {
            "root" : (1, 1, {
                "A" : (1, 1, "InvalidData"),
                "B" : (1, 1, None) 
            }),
        }
        self.assertRaises(invStructErr, serialize.XMLSerializer, inv_structure)
        
    def test_invalid_data_dictionaries(self):
        """
        Test that passing data to a serializer object that doesn't match the 
        structure definition dictionary associated with that serializer 
        causes InvalidSerializeDataError to be raised.
        """
        # Let's abbreviate the exception name:
        invDataErr = serialize.InvalidSerializeDataError
        
        # Create a new XMLSerializer object using the person structure 
        # definition dictionary.
        xmlSerializer = serialize.XMLSerializer(person_structure_definition)
        
        # Invalid data: not a dictionary
        # This one actually raises AttributeError, but may raise any exception
        inv_data = object()
        self.assertRaises(Exception, xmlSerializer.serialize_to_string, 
                          inv_data)
        
        # Invalid data: not a dictionary, string
        # This one actually raises AttributeError, but may raise any exception
        inv_data = "Invalid Data"
        self.assertRaises(Exception, xmlSerializer.serialize_to_string, 
                          inv_data)
        
        # Invalid data: missing required element
        inv_data = {
            "person" : {
                "names" : {
                    "first" : "Jane",
                    "middle" : "Ann",
                    "last" : "Smith"
                }
            }
        }
        self.assertRaises(invDataErr, xmlSerializer.serialize_to_string, 
                          inv_data)
        
        # Invalid data: unknown element appears
        inv_data = {
            "person" : {
                "names" : {
                    "first" : "Jane",
                    "middle" : "Ann",
                    "last" : "Smith",
                    "nickname" : "R."
                },
                "age" : "99"
            }
        }
        self.assertRaises(invDataErr, xmlSerializer.serialize_to_string, 
                          inv_data)
        
        # Invalid data: invalid object
        inv_data = {
            "person" : {
                "names" : {
                    "first" : "Jane",
                    "middle" : "Ann",
                    "last" : 1459   # Not a string (!)
                },
                "age" : "99"
            }
        }
        self.assertRaises(invDataErr, xmlSerializer.serialize_to_string, 
                          inv_data)
        
        # Invalid data: invalid object inside a list
        inv_data = {
            "person" : {
                "names" : {
                    "first" : "Jane",
                    "middle" : "Ann",
                    "last" : ["Smith", [object()], "Watson"]
                },
                "age" : "99"
            }
        }
        self.assertRaises(invDataErr, xmlSerializer.serialize_to_string, 
                          inv_data)
        
        # Invalid data: string value for an element defined as composite
        inv_data = {
            "person" : {
                "names" : "Jane Ann Smith",
                "age" : "99"
            }
        }
        self.assertRaises(invDataErr, xmlSerializer.serialize_to_string, 
                          inv_data)
        
        # Invalid data: element occurs more times than max_occurrences
        inv_data = {
            "person" : {
                "names" : {
                    "first" : "Jane",
                    "middle" : "Ann",
                    "last" : "Smith"
                },
                "age" : ["99", "12"]
            }
        }
        self.assertRaises(invDataErr, xmlSerializer.serialize_to_string, 
                          inv_data)
        
        # Invalid data: element occurs less times than min_occurrences
        # this requires a different structure definition dictionary: 
        structure_def = {
            "root" : (1, 1, {
                "A" : (2, None), # 2 to infinite occurrences are valid
                "B" : (1, 1, None) 
            }),
        }
        inv_data = {
            "root" : {
                "A" : "13",
                "B" : "12"
            }
        }
        newSerializer = serialize.XMLSerializer(structure_def)
        self.assertRaises(invDataErr, newSerializer.serialize_to_string, 
                          inv_data)
        
        # Invalid data: string value for an element defined as composite in 
        # a list of composite elements
        # this requires a different structure definition dictionary: 
        structure_def = {
            "root" : (1, 1, {
                "A" : (1, { # 1 to infinite occurrences are valid
                    "C" : (1, 1, None)
                }),
                "B" : (1, 1, None) 
            }),
        }
        inv_data = {
            "root" : {
                "A" : [{
                        "C" : "13"
                    },
                    "15"
                ],
                "B" : "12"
            }
        }
        newSerializer = serialize.XMLSerializer(structure_def)
        self.assertRaises(invDataErr, newSerializer.serialize_to_string, 
                          inv_data)
                          
    def test_deserialize_xml_file_invalid_data(self):
        """
        Test that attempting to deserialize data from a file that contains 
        valid XML but that does not represent well-formed serialized data 
        results in an InvalidSerializeDataError being raised.
        """
        # Construct the path to the directory where our invalid test files are 
        # located:
        # __file__ is the file corresponding to this module (TestSerialize)
        invalid_files_dir = os.path.join(os.path.dirname(__file__), 
                                         "TestSerialize.resources",
                                         "invalid_serialize_xml_files")
        
        # All files use the person_structure_definition, lets create a 
        # serializer object for that structure:
        xmlSerializer = serialize.XMLSerializer(person_structure_definition)
        
        # Now, we attempt to use xmlSerializer to deserialize each of our 
        # invalid test files, checking that it raises an error.
        # The example files contain data that is badly-formed serialized data, 
        # not merely inconsistent with person_structure_definition.
        for file_name in ["err_dummy_root_without_inner_elements.xml",
                          "err_element_without_element_or_text_children.xml"]:
            inv_file = os.path.join(invalid_files_dir, file_name)
            self.assertRaises(serialize.InvalidSerializeDataError, 
                              xmlSerializer.deserialize_from_file, inv_file)
        
        
    ## =======================================================================
    ## Test exception classes:
    ## =======================================================================
    
    def test_serialize_dot_py_exceptions(self):
        """
        Test that all exceptions declared in serialize.py can be constructed, 
        raised and queried for an exception message.
        """
        # This test is here mostly for the sake of code coverage
        
        message = "My message: ñ(&(%%9_\n\t"
        for ExceptionCls in (serialize.InvalidSerializeDataError, 
                           serialize.InvalidSerializeStructureDefinitionError):
        
            was_raised = False
            
            try:
                raise ExceptionCls(message)
            except ExceptionCls, e:
                was_raised = True
                self.assertEqual(str(e), message)
                
            self.assertEqual(was_raised, True)
        


if __name__ == '__main__':
    unittest.main()
