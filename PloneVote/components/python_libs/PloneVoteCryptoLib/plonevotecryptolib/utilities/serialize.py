# -*- coding: utf-8 -*-
#
#  serialize.py : A general serializer module for PloneVoteCryptoLib
#
#  serialize.py provides a generic API that allows storing and retriving 
#  formated representations of objects, together with specific serializers for 
#  particular storage formats (e.g. XMLSerializer)
#
#  Both the structure of the serialized data and its values are provided to 
#  this module as (a restricted subset of) dictionary objects.
#
#  (See module docstring below for more information)
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

# Module level documentation #TODO
"""serialize.py : A general serializer module for PloneVoteCryptoLib

Example serialize structure definition dictionary:
    
    structure_definition = {
        "person" : (1, 1, {                 # Root element
            "names" : (1, 1, {              # 1 "names" node allowed, exactly
                "first" : (1, None),        # 1 or more first names allowed
                "middle" : (None),          # 0 or more middle names allowed
                "last" : (1, None)          # 1 or more last names allowed
            }),
            "age" : (1, 1, None)            # 1 age allowed, exactly
        }),
    }

Example matching serializable data:

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
"""

# ============================================================================
# Imports and constant definitions:
# ============================================================================

import xml.dom.minidom

__all__ = ["XMLSerializer", "InvalidSerializeStructureDefinitionError"]

DEFAULT_ROOT_ELEMENT_NAME = "SerializedDataRoot"

# ============================================================================
# Exception classes:
# ============================================================================

class InvalidSerializeStructureDefinitionError(Exception):
	"""
	Raised when an invalid structure definition dictionary is encountered.
	
	This exception is raised when an invalid serialize structure definition 
	dictionary is passed as an argument to any of the functions, methods and 
	constructors of the serialize module that take a structure definition 
	dictionary.
	
	See module level documentation for what constitutes a valid serialize 
	structure definition dictionary. Whenever anything else is passed as an 
	argument, when a structure definition dictionary is expected instead, 
	either TypeError or this exception may (and should eventually) be raised.
	
	The message obtained by this exception's string method may contain 
	additional information about the specific problem encountered.
	"""
    
	def __str__(self):
		return self.msg

	def __init__(self, msg):
		"""
		Create a new InvalidSerializeStructureDefinitionError exception.
		"""
		self.msg = msg

class InvalidSerializeDataError(Exception):
	"""
	Raised when invalid serializable data is encountered.
	
	This exception is raised when an invalid serializable data dictionary for a 
	given structure definition dictionary is encountered. For example, when the 
	serialize_to_file or serialize_to_string methods of a serializer object are 
	passed a data dictionary that does not match the structure definition 
	dictionary given when creating the serializer instance.
	
	See module level documentation for what constitutes valid serializable data 
	for a given serialize structure definition dictionary.
	
	Note that the methods that raise this exception may instead raise TypeError 
	when given a value for the serializable data dictionary that cannot be 
	valid serializable data for any possible structure definition dictionary.
	
	The message obtained by this exception's string method may contain 
	additional information about the specific problem encountered.
	"""
    
	def __str__(self):
		return self.msg

	def __init__(self, msg):
		"""
		Create a new InvalidSerializeDataError exception.
		"""
		self.msg = msg

# ============================================================================
# Helper functions:
# ============================================================================

def _parse_schema_tuple(schema_tuple):
    """
    Parse a structure definition schema tuple, completing the missing values.
    
    This function takes a tuple in the format of the value part of an item  
    inside a structure definition dictionary. That is, a tuple of any of the  
    following forms:
        (x, y, SN)
        (x, SN)
        (SN)
         SN
    where: x is the minimum number of elements with a given name allowed, y is 
    the maximum number of elements with that same name and SN is the definition 
    of the elements with that name, expressed as either None (meaning the 
    element should contain a textual/string value) or a structure definition 
    dictionary for a non-leaf element definition.
    
    The result of this function is that same tuple in (x, y, SN) form, where x 
    and y have the default values if they were missing from the input tuple. 
    
    The default value for x (min instances required) is 0
    
    The default value for y (max instances allowed) is 0 (meaning any number of 
    instances allowed)
    
    Arguments:
        schema_tuple::tuple -- The definition schema tuple in (x, y, SN), 
                               (x, SN), (SN) or SN form (see above description).
    
    Returns:
        schema_tuple::tuple -- The definition schema tuple in (x, y, SN) format.
        
    Throws:
        InvalidSerializeStructureDefinitionError    -- 
            If the given schema tuple does not correspond to the value part of 
            an item inside a valid structure definition dictionary.
    """
    # python will actually unpack a tuple with a single element, so we check 
    # that the type of schema_tuple is actually tuple. If not, we treat the 
    # value as if it where the single element of a tuple (e.g. (None) instead 
    # of None).
    if(type(schema_tuple) is not tuple):
        min_occurrences = 0
        max_occurrences = 0
        sub_sd_node = schema_tuple
    elif(len(schema_tuple) == 1):
        min_occurrences = 0
        max_occurrences = 0
        sub_sd_node = schema_tuple[0]
    elif(len(schema_tuple) == 2):
        min_occurrences = schema_tuple[0]
        max_occurrences = 0
        sub_sd_node = schema_tuple[1]
    elif(len(schema_tuple) == 3):
        min_occurrences = schema_tuple[0]
        max_occurrences = schema_tuple[1]
        sub_sd_node = schema_tuple[2]
    else:
        raise InvalidSerializeStructureDefinitionError(\
            "Tuple %s has too many values and cannot be a schema tuple for a " \
            "valid serialize structure definition dictionary. Valid schema " \
            "tuples have between 1 and 3 values. For more information, see " \
            "the documentation for the serialize module." % str(schema_tuple))
       
    return (min_occurrences, max_occurrences, sub_sd_node)

def _check_validate_structure(sd_node):
    """
    Validate a serialize structure definition dictionary.
    
    This function (recursively) validates a serialize structure definition 
    dictionary. Given a valid structure definition dictionary, this function 
    does nothing. Otherwise, it raises InvalidSerializeStructureDefinitionError.
    
    Arguments:
        sd_node::dict   -- A structure definition dictionary we wish to 
                           validate. (Can be the "root" of the dictionary or 
                           any sub-definition of a non-leaf element, which have 
                           the same format).
      
    Throws:
        InvalidSerializeStructureDefinitionError    -- 
            If sd_node is anything other than a valid structure definition 
            dictionary.
    """
    for name, schema in sd_node.items():
        
        (min_occurrences, max_occurrences, sub_sd_node) = \
                                        _parse_schema_tuple(schema)
            
        if(max_occurrences < 0 or min_occurrences < 0):
            raise InvalidSerializeStructureDefinitionError(\
                "Error in serialize structure definition dictionary for key " \
                "%s: min_occurrences is %d, max_occurrences is %d. " \
                "A serialize structure definition dictionary must never " \
                "define a key where min_occurrences and/or max_occurrences " \
                "have negative values." % name, max_occurrences, min_ocurrences)
        
        if(max_occurrences != 0 and max_occurrences < min_occurrences):
            raise InvalidSerializeStructureDefinitionError(\
                "Error in serialize structure definition dictionary for key " \
                "%s: min_occurrences is %d, max_occurrences is %d. " \
                "A serialize structure definition dictionary must never " \
                "define a key where min_occurrences is greater than " \
                "max_occurrences." % name, max_occurrences, min_ocurrences)
        
        if(sub_sd_node is None):
            pass    
        elif(type(sub_sd_node) is dict):
            _check_validate_structure(sub_sd_node)
        else:
            raise InvalidSerializeStructureDefinitionError(\
                "Error in serialize structure definition dictionary for key " \
                "%s: object of type %s encountered as the corresponding " \
                "element's definition. An element definition inside a " \
                "serialize structure definition dictionary must be " \
                "either None (indicating a string/text element) or another " \
                "structure definition dictionary indicating a composite " \
                "sub-structure. For more information, see the documentation " \
                "for the serialize module." % name, str(type(sub_sd_node)))
    

def _check_data_matches_structure(sd_node, data_node):
    """
    Check that the given data matches the given structure definition dictionary.
    
    This function takes a serialize structure definition dictionary (which is 
    assumed to be valid) and a serializable data dictionary. If the 
    serializable data matches the structure definition dictionary, this 
    function does nothing. Otherwise, it raises InvalidSerializeDataError.
    
    See module level documentation for a description of how a serializable data 
    dictionary matching a given serialize structure definition dictionary 
    should be constructed.
    
    Arguments:
        sd_node::dict   -- A structure definition dictionary, which is assumed 
                           to be valid (ie. passes _check_validate_structure)
        data_node::dict -- A serializable data dictionary for which we wish to 
                           check if it matches the given structure definition 
                           dictionary (sd_node).
      
    Throws:
        InvalidSerializeDataError    -- 
            If data_node is anything other than a valid serializable data 
            dictionary matching the structure definition dictionary sd_node.
    """
    # First, lets check that all keys in the data have a corresponding 
    # definition in the structure dictionary:
    for key in data_node.keys():
        if(not sd_node.has_key(key)):
            # Construct the basic error message
            error_msg = "The given data doesn't match the corresponding " \
                "serialize structure definition dictionary. An element named " \
                "\"%s\" appears in the data, but it is not defined in the " \
                "structure definition dictionary at the same level. Defined " \
                "elements in the structure definition dictionary at the " \
                "current level are: " % key
            # Append the list of valid elements at the current level
            valid_elements = sd_node.keys()
            for i in range(0, len(valid_elements) - 1):
                error_msg += valid_elements[i] + ", "
            error_msg += valid_keys[len(valid_elements) - 1] + "."
            # Raise the exception
            raise InvalidSerializeDataError(error_msg)
    
    # Now, for each definition in the structure dictionary at the current level:
    for name, schema in sd_node.items():
    
        (min_occurrences, max_occurrences, sub_sd_node) = \
                                        _parse_schema_tuple(schema)
                                        
        # Check if the name appears in the data:
        if(not data_node.has_key(name)):
            if(min_occurrences == 0):
                # If the schema allows for 0 occurrences of this key, 
                # just continue
                continue
            else: 
                # Otherwise, this is an error
                raise InvalidSerializeDataError(\
                    "The given data doesn't match the corresponding " \
                    "serialize structure definition dictionary. The element " \
                    "\"%s\" is required by the structure definition, but was " \
                    "not found in the data." % name)
                
        # Here the name should appear in the data, lets get its value
        value = data_node[name]
        
        # Get the number of actual occurrences of the schema name
        if(type(value) is list):
            occurrences = len(value)
        else:
            occurrences = 1
            
        # Check that this is a valid number of occurrences
        if(max_occurrences != 0 and not
           (min_occurrences <= occurrences <= max_occurrences)):
           
            if(max_occurrences == 0):
                max_occ_str = "infinite"
            else:
                max_occ_str = str(max_occurrences)
            
            raise InvalidSerializeDataError(\
                "The given data doesn't match the corresponding serialize " \
                "structure definition dictionary. According the structure " \
                "definition, the element \"%s\" must occur between %d and %d " \
                "times. But %d occurrences of that element where found in " \
                "the data." % name, min_occurrences, max_occ_str, occurrences)
        
        # Two cases: either sub_sd_node is None and thus this is a "leaf" of  
        # the structure dictionary, or sub_sd_node is another structure 
        # definition dictionary
        if(sub_sd_node == None):
            # Two cases: either value is a string or a list of strings, both 
            # are fine. No other type is allowed.
            if(type(value) is str):
                pass
            elif(type(value) is list):
                for s in value:
                    if(type(s) is not str):
                        raise InvalidSerializeDataError(\
                            "The given data doesn't match the corresponding " \
                            "serialize structure definition dictionary. " \
                            "According the structure definition, element " \
                            "\"%s\" is a leaf element and thus its value " \
                            "must be a string. The data has the value %s for " \
                            "this element." % name, s)
            else:
                # Invalid value type for a data dictionary
                raise InvalidSerializeDataError(\
                    "The given data doesn't match the corresponding serialize "\
                    "structure definition dictionary. According the structure "\
                    "definition, element \"%s\" is a leaf element and thus " \
                    "its value must be a string. The data has the value %s " \
                    "for this element." % name, value)
        else:
            # Two cases: either value is a dictionary or a list of dictionaries
            if(type(value) is dict):
                # call this function recursively for sub_sd_node and value
                _check_data_matches_structure(sub_sd_node, value)
            elif(type(value) is list):
                for v_element in value:
                    if(type(v_element) is dict):
                        _check_data_matches_structure(sub_sd_node, v_element)
                    else:
                        raise InvalidSerializeDataError(\
                            "The given data doesn't match the corresponding " \
                            "serialize structure definition dictionary. " \
                            "According the structure definition, element " \
                            "\"%s\" is a composite element and thus its value "\
                            "must be a dictionary matching the element's " \
                            "structure definition. The data has the value %s " \
                            "for this element." % name, v_element)
            else:
                # Invalid value type for a data dictionary
                raise InvalidSerializeDataError(\
                    "The given data doesn't match the corresponding serialize "\
                    "structure definition dictionary. According the structure "\
                    "definition, element \"%s\" is a composite element and " \
                    "thus its value must be a dictionary matching the " \
                    "element's structure definition. The data has the value " \
                    "%s for this element." % name, value)

# ============================================================================
# Main (non-exception) classes:
# ============================================================================  

class BaseSerializer:
    """
    The (abstract) base class for all serializer objects.
    
    A serializer is an object that can serialize and deserialize data matching 
    a given structure definition dictionary into a particular format. This 
    class provides some shared basic infrastructure required by all concrete 
    serializers.
    
    BaseSerializer objects should never be used directly. For usable 
    serializer classes see XMLSerializer and JSONSerializer.
    """
    
    def _check_data(self, data):
        """
        Check the given serializable data dictionary against this serializer 
        object's structure definition dictionary.
        
        Arguments:
            data::dict -- A serializable data dictionary for which we wish 
                          to check if it matches this serializer object's 
                          structure definition dictionary.
      
        Throws:
            InvalidSerializeDataError    -- 
                If data is anything other than a valid serializable data 
                dictionary matching the structure definition dictionary
                associated with this BaseSerializer instance.
        """
        _check_data_matches_structure(self.structure_definition, data)
    
    def __init__(self, structure_definition):
        """
        Construct a serializer for data matching the given structure definition.
        
        Arguments:
            structure_definition::dict  -- The structure definition dictionary 
                                           that defines the data accepted by 
                                           this serializer.
      
        Throws:
            InvalidSerializeStructureDefinitionError    -- 
                If structure_definition is anything other than a valid 
                structure definition dictionary.
        """
        _check_validate_structure(structure_definition)
        self.structure_definition = structure_definition

        
class XMLSerializer(BaseSerializer):
    """
    A serializer object for serializing/deserializing data as XML.
    
    XMLSerializer can be used to serialize data to and deserialize data from an 
    XML file. The structure definition dictionary passed to the constructor of 
    an XMLSerializer object translates into the acceptable XML schema in which 
    serialized data will be encoded and which will be accepted for 
    deserialization.
    
    Use serialize_to_file to store data matching the structure definition into 
    an XML file.
    
    Use deserialize_from_file to recover data matching the structure definition 
    from an existing XML file.
    """
    
    def _write_to_dom_element(self, xml_document, parent_node, element_name, 
                              element_value):
        """
        Construct and write a new XML DOM element from the given data.
        
        This method writes a new XML element with name element_name under 
        parent_node inside xml_document. Then it writes the contents of 
        element_value inside that newly created element.
        
        How the contents of the element are written depends on the type of 
        element_value:
            * If element_value is a string, then it is written as the textual 
              contents of the element.
            * If element_value is a serializable data dictionary, then each 
              element of the dictionary is recursively written under the newly 
              created element.
            * If element_value is a list, each element of the list is treated 
              as the contents of a different XML element, all with name 
              element_name and under parent_node.
        
        Arguments:
            xml_document::xml.dom.minidom.Document  --
                The XML document to which the data is being written.
            parent_node::xml.dom.minidom.Element    --
                The parent XML node/element under which the current element 
                should be written. Should be an element of xml_document.
            element_name::string    -- The name of the element to write.
            element_value::(string|dict|list)   -- 
                The contents of the element to write.
        
        Note:
            parent_node may also be the same as xml_document, indicating that 
            the element to write will be the root element of the document.                
        """
        # Three options: element_value is either a dictionary, a list or a 
        # string
        if(type(element_value) is dict):
            # We first create a single new element named element_name under 
            # parent_node.
            element = xml_document.createElement(element_name)
            parent_node.appendChild(element)
            
            # Then we write the data in element_value recursively under this 
            # element.
            for child_name, child_value in element_value.items():
                self._write_to_dom_element(xml_document, element, child_name, 
                                           child_value)
                
        elif(type(element_value) is list):
            # We repeat this call, with the same parent and element_name for  
            # each value inside the list
            # (list means "these are all different elements with the same name")
            for single_ev in element_value:
                assert (type(single_ev) is not list), \
                    "The given data dictionary does not match the format " \
                    "for data dictionaries."
                self._write_to_dom_element(xml_document, parent_node, 
                                           element_name, single_ev)

        else:
            # element_value must then be a string.
            # We first create a single new element named element_name under 
            # parent_node.
            element = xml_document.createElement(element_name)
            parent_node.appendChild(element)
            
            # Then, we write element_value as that new element's text contents
            element.appendChild(xml_document.createTextNode(element_value))
        
    def serialize_to_dom(self, data):
        """
        Serialize the given data as an XML document object.
        
        Arguments:
            data::dict  -- A serializable data dictionary (see module level 
                           documentation).
                           
        Returns:
            doc::xml.dom.minidom.Document   -- 
                An XML document representing the given data serialized into 
                XML format.
        
        Throws:
            InvalidSerializeDataError   -- 
                If data is not a serializable data dictionary corresponding to 
                the structure definition dictionary associated with this 
                serializer object.
        """
        self._check_data(data)
        doc = xml.dom.minidom.Document()
        
        # Valid XML must have a single document-level root element.
        # Two cases: Either the structure definition has a single root element, 
        # or there are multiple top level elements.
        # For consistency, we use structure_definition and not the actual data.
        # The structure definition may have multiple (optional) top level 
        # elements, while particular instances of the data include just one.
        structure_has_single_root = True
        if(len(self.structure_definition) != 1):
            # More than one different root element allowed by structure def
            structure_has_single_root = False
        else:
            root_element_def_tuple = self.structure_definition.items()[0][1]
            (min_occurrences, max_occurrences, sd_node) = \
                            _parse_schema_tuple(root_element_def_tuple)
            if(max_occurrences > 1):
                # More than one root element of the same kind allowed by 
                # structure def
                structure_has_single_root = False
            
        
        if(structure_has_single_root):
            # Use the top level element of the structure as the document's 
            # root.
            root_element_name, root_element_value = data.items()[0]
            self._write_to_dom_element(doc, doc, root_element_name, 
                                       root_element_value)
        else:
            # Create a dummy root element for the document and then write the 
            # structure's top level elements within this dummy element.
            root_element = doc.createElement(DEFAULT_ROOT_ELEMENT_NAME)
            doc.appendChild(root_element)
            for element_name, element_value in data.items():
                self._write_to_dom_element(doc, root_element, element_name, 
		                                   element_value)

        return doc
        
    def serialize_to_file(self, filename, data):
        """
        Serialize the given data into a new XML file.
        
        Arguments:
            filename::string    -- The name of the file to which to write the 
                                   XML representation of data.
            data::dict  -- A serializable data dictionary (see module level 
                           documentation).
        
        Throws:
            InvalidSerializeDataError   -- 
                If data is not a serializable data dictionary corresponding to 
                the structure definition dictionary associated with this 
                serializer object.
        """
        xml_document = self.serialize_to_dom(data)
        file_object = open(filename, "w")
        file_object.write(xml_document.toprettyxml())
        file_object.close()
        
    def serialize_to_string(self, data):
        """
        Serialize the given data as XML and return it in string form.
        
        Arguments:
            data::dict  -- A serializable data dictionary (see module level 
                           documentation).
                           
        Returns:
            result::string  -- 
                An string representing the given data serialized into XML.
        
        Throws:
            InvalidSerializeDataError   -- 
                If data is not a serializable data dictionary corresponding to 
                the structure definition dictionary associated with this 
                serializer object.
        """
        xml_document = self.serialize_to_dom(data)
        return xml_document.toprettyxml()

        
class JSONSerializer(BaseSerializer):
    """
    """
        
    def serialize_to_file(self, filename, data):
        """
        """
        
    def serialize_to_string(self, data):
        """
        """
