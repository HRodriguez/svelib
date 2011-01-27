# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  ThresholdPublicKey.py : 
#  A public key generated in a threshold encryption scheme.
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

import xml.dom.minidom

from plonevotecryptolib.PublicKey import PublicKey
from plonevotecryptolib.PVCExceptions import InvalidPloneVoteCryptoFileError

class ThresholdPublicKey(PublicKey):
	"""
	A public key generated in a threshold encryption scheme.
	
	This class is compatible with the PublicKey class and inherits from it.
	It adds some metadata about the threshold encryption scheme and changes its 
	format on file slightly, but otherwise it presents the same methods and 
	properties that PublicKey and can be used to encrypt data without any 
	knowledge of the threshold decryption or key set-up process.
	
	Attributes:
		cryptosystem::EGCryptoSystem	-- The ElGamal cryptosystem in which 
										   this key is defined.
		num_trustees::int	-- Total number of trustees in the threshold scheme.
							   (the n in "k of n"-decryption)
		threshold::int	-- Minimum number of trustees required to decrypt 
						   threshold  encrypted messages. 
						   (the k in "k of n"-decryption)
	"""
	
	def __init__(self, cryptosystem, num_trustees, threshold, public_key_value):
		"""
		Creates a new threshold public key. Should not be invoked directly.
		
		Instead of using this constructor from outside of PloneVoteCryptoLib, 
		please use ThresholdEncryptionSetUp.generate_public_key().
		
		Arguments:
			(see class attributes for cryptosystem, num_trustees and threshold)
			public_key_value::long		-- The actual value of the public key
									(g^P(0) mod p, see ThresholdEncryptionSetUp)
		"""
		PublicKey.__init__(self, cryptosystem, public_key_value)
		self.num_trustees = num_trustees
		self.threshold = threshold
	
	# Check if overriding a _method is O.K., as well as using _key directly.
	# (This two clases are expected to be kept coupled and in the same library, 
	# so it's not as if the API can chance by surprise under our feet)	
	def _to_xml(self):
		"""
		Returns an xml document containing a representation of this public key.
		
		Returns:
			doc::xml.dom.minidom.Document
		"""
		doc = xml.dom.minidom.Document()
		root_element = doc.createElement("PloneVotePublicKey")
		# This is a threshold public key, as opposed to a single one
		root_element.setAttribute("type", "threshold")
		root_element.setAttribute("trustees", str(self.num_trustees))
		root_element.setAttribute("threshold", str(self.threshold))
		doc.appendChild(root_element)
		
		key_element = doc.createElement("PublicKey")
		key_str = hex(self._key)[2:]		# Remove leading '0x'
		if(key_str[-1] == 'L'): 
			key_str = key_str[0:-1]			# Remove trailing 'L'
		key_element.appendChild(doc.createTextNode(key_str))
		root_element.appendChild(key_element)
		
		cs_scheme_element = self.cryptosystem.to_dom_element(doc)
		root_element.appendChild(cs_scheme_element)
		
		return doc
	
	@classmethod
	def from_file(cls, filename):
		"""
		Loads a threshold public key from file.
		"""
		doc = xml.dom.minidom.parse(filename)
		
		# Check root element
		if(len(doc.childNodes) != 1 or 
			doc.childNodes[0].nodeType != doc.childNodes[0].ELEMENT_NODE or
			doc.childNodes[0].localName != "PloneVotePublicKey"):
			
			raise InvalidPloneVoteCryptoFileError(filename, 
				"A PloneVoteCryptoLib stored public key file must be an " \
				"XML file with PloneVotePublicKey as its root element.")	
		
		root_element = doc.childNodes[0]
		
		# Verify that we are dealing with a threshold public key.
		type_attribute = root_element.getAttribute("type")
		if(type_attribute == "threshold"):
			pass # this is the expected case
		else:
			raise InvalidPloneVoteCryptoFileError(filename, "Expected a " \
				"threshold public key. Key type was: %s." % type_attribute)
		
		# Get and check the trustees and threshold attributes
		num_trustees_attribute = root_element.getAttribute("trustees")
		try:
			num_trustees = int(num_trustees_attribute, 10)
		except ValueError:
			raise InvalidPloneVoteCryptoFileError(filename, 
				"A PloneVoteCryptoLib stored threshold public key file must " \
				"have a \"trustees\" attribute on its root element with a " \
				"numerical value. The given file has: %s" % \
				num_trustees_attribute)
		
		
		threshold_attribute = root_element.getAttribute("threshold")
		try:
			threshold = int(threshold_attribute, 10)
		except ValueError:
			raise InvalidPloneVoteCryptoFileError(filename, 
				"A PloneVoteCryptoLib stored threshold public key file must " \
				"have a \"threshold\" attribute on its root element with a " \
				"numerical value. The given file has: %s" % \
				threshold_attribute)
				
		if(num_trustees < threshold):
			raise InvalidPloneVoteCryptoFileError(filename, 
				"The metadata for the public key given in the file is " \
				"invalid (could the file be corrupt?). " \
				"The theshold of trustees required for decryption in a " \
				"threshold encryption set-up must be less or equal than the " \
				"total number of trustees.")
		
		(cryptosystem, key) = PublicKey._parse_root_element(root_element)
		
		# Construct and return the PublicKey object
		return cls(cryptosystem, num_trustees, threshold, key)
