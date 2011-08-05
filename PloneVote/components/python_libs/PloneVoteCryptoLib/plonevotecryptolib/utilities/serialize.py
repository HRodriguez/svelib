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

import xml.dom.minidom

DEFAULT_ROOT_ELEMENT_NAME = "SerializedDataRoot"

def _parse_schema_tuple(schema_tuple):
    """
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
        raise InvalidSerializeStructureDefinitionError() #TODO
       
    return (min_occurrences, max_occurrences, sub_sd_node)

def _check_validate_structure(sd_node):
    """
    """
    for name, schema in sd_node.items():
        
        (min_occurrences, max_occurrences, sub_sd_node) = \
                                        _parse_schema_tuple(schema)
            
        if(max_occurrences < 0 or min_occurrences < 0):
            raise InvalidSerializeStructureDefinitionError() #TODO
        
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
            raise InvalidSerializeStructureDefinitionError() #TODO
    

def _check_data_matches_structure(sd_node, data_node):
    """
    """
    # First, lets check that all keys in the data have a corresponding 
    # definition in the structure dictionary:
    for key in data_node.keys():
        if(not sd_node.has_key(key)):
            raise InvalidSerializeDataError() #TODO
    
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
                raise InvalidSerializeDataError() #TODO
                
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
            raise InvalidSerializeDataError() #TODO
        
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
                        raise InvalidSerializeDataError() #TODO
            else:
                # Invalid value type for a data dictionary
                raise InvalidSerializeDataError() #TODO
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
                        raise InvalidSerializeDataError() #TODO
            else:
                # Invalid value type for a data dictionary
                raise InvalidSerializeDataError() #TODO
    

class BaseSerializer:
    """
    """
    
    def _check_data(self, data):
        """
        """
        _check_data_matches_structure(self.structure_definition, data)
    
    def __init__(self, structure_definition):
        """
        """
        _check_validate_structure(structure_definition)
        self.structure_definition = structure_definition

        
class XMLSerializer(BaseSerializer):
    """
    """
    
    def _write_to_dom_element(self, xml_document, parent_node, element_name, 
                              element_value):
        """
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
        
    def _serialize_to_dom(self, data):
        """
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
        """
        xml_document = self._serialize_to_dom(data)
        file_object = open(filename, "w")
        file_object.write(xml_document.toprettyxml())
        file_object.close()
        
    def serialize_to_string(self, data):
        """
        """
        xml_document = self._serialize_to_dom(data)
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
