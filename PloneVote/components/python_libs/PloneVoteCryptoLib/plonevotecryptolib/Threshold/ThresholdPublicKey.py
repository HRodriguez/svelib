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

import Crypto.Hash.SHA256	# sha256 is not available in python 2.4 standard lib

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
	
	def get_fingerprint(self):
		# We override this PublicKey method to add partial public keys to the 
		# input of the hash function to create the fingerprint.
		fingerprint = Crypto.Hash.SHA256.new()
		fingerprint.update(hex(self.cryptosystem.get_nbits()))
		fingerprint.update(hex(self.cryptosystem.get_prime()))
		fingerprint.update(hex(self.cryptosystem.get_generator()))
		fingerprint.update(hex(self._key))
		for partial_public_key in self._partial_public_keys:
			fingerprint.update(hex(partial_public_key))
		return fingerprint.hexdigest()
	
	def get_partial_public_key(self, trustee):
		"""
		Retrieve the partial public key for the given trustee.
		
		The partial public key for trustee i is g^P(i). This value is used for 
		verification of the partial decryptions created by said trustee.
		
		Instead of using this values from outside of PloneVoteCryptoLib, 
		please use ThresholdDecryptionCombinator to verify and combine partial 
		decryptions.
		
		Arguments:
			trustee::int	-- The number of the trustee for which we wish to 
							   obtain the partial public key.
		"""
		return self._partial_public_keys[trustee - 1]
	
	def __init__(self, cryptosystem, num_trustees, threshold, 
				 public_key_value, verification_partial_public_keys):
		"""
		Creates a new threshold public key. Should not be invoked directly.
		
		Instead of using this constructor from outside of PloneVoteCryptoLib, 
		please use ThresholdEncryptionSetUp.generate_public_key().
		
		Arguments:
			(see class attributes for cryptosystem, num_trustees and threshold)
			public_key_value::long		-- The actual value of the public key
								(g^2P(0) mod p, see ThresholdEncryptionSetUp)
			verification_partial_public_keys::long[]
					-- A series of "partial public keys" (g^P(i) for each 
					   trustee i), used for partial decryption verification.
					   Note that the key for trustee i must be on index i-1 of
					   the array.
		"""
		PublicKey.__init__(self, cryptosystem, public_key_value)
		
		# Some checks:
		if(threshold > num_trustees):
			raise ValueError("Invalid parameters for the threshold public key:"\
							 " threshold must be smaller than the total number"\
							 " of trustees. Got num_trustees=%d, threshold=%d" \
							 % (num_trustees, threshold))
		
		if(len(verification_partial_public_keys) != num_trustees):
			raise ValueError("Invalid parameters for the threshold public key:"\
							 " a verification partial public for each trustee "\
							 "must be included.")
			
		self.num_trustees = num_trustees
		self.threshold = threshold
		self._partial_public_keys = verification_partial_public_keys
	
	
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
		
		# Include verification partial public keys
		partial_pub_keys_element = \
						doc.createElement("VerificationPartialPublicKeys")
		for trustee in range(1, self.num_trustees + 1):
			part_pub_key = self.get_partial_public_key(trustee)
			part_pub_key_element = doc.createElement("PartialPublicKey")
			part_pub_key_element.setAttribute("trustee", str(trustee))
			part_pub_key_str = hex(part_pub_key)[2:]	# Remove leading '0x'
			if(key_str[-1] == 'L'): 
				part_pub_key_str = part_pub_key_str[0:-1] # Remove trailing 'L'
			text_node = doc.createTextNode(part_pub_key_str)
			part_pub_key_element.appendChild(text_node)
			partial_pub_keys_element.appendChild(part_pub_key_element)
			
			
		root_element.appendChild(partial_pub_keys_element)
		
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
		
		#TODO: Load partial public keys from the xml.
		
		# Construct and return the PublicKey object
		return cls(cryptosystem, num_trustees, threshold, key)
