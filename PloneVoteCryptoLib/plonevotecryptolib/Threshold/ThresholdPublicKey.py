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

# ============================================================================
# Imports and constant definitions:
# ============================================================================

import xml.dom.minidom

import Crypto.Hash.SHA256  # sha256 is not available in python 2.4 standard lib

from plonevotecryptolib.PublicKey import PublicKey, \
                                     PublicKey_serialize_structure_definition

from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem
from plonevotecryptolib.PVCExceptions import InvalidPloneVoteCryptoFileError
import plonevotecryptolib.utilities.serialize as serialize
# ============================================================================

# ============================================================================
# Classes:
# ============================================================================

class ThresholdPublicKey(PublicKey):
    """
    A public key generated in a threshold encryption scheme.
    
    This class is compatible with the PublicKey class and inherits from it.
    It adds some metadata about the threshold encryption scheme and changes its 
    format on file slightly, but otherwise it presents the same methods and 
    properties that PublicKey and can be used to encrypt data without any 
    knowledge of the threshold decryption or key set-up process.
    
    Attributes:
        cryptosystem::EGCryptoSystem    -- The ElGamal cryptosystem in which 
                                           this key is defined.
        num_trustees::int    -- Total number of trustees in the threshold scheme.
                               (the n in "k of n"-decryption)
        threshold::int    -- Minimum number of trustees required to decrypt 
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
            trustee::int    -- The number of the trustee for which we wish to 
                               obtain the partial public key.
        """
        return self._partial_public_keys[trustee]
    
    def __init__(self, cryptosystem, num_trustees, threshold, 
                 public_key_value, verification_partial_public_keys):
        """
        Creates a new threshold public key. Should not be invoked directly.
        
        Instead of using this constructor from outside of PloneVoteCryptoLib, 
        please use ThresholdEncryptionSetUp.generate_public_key().
        
        Arguments:
            (see class attributes for cryptosystem, num_trustees and threshold)
            public_key_value::long        -- The actual value of the public key
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

        
    def to_file(self, filename, SerializerClass=serialize.XMLSerializer):
        """
        Saves this threshold public key to a file.
        
        Arguments:
            filename::string    -- The path to the file in which to store the 
                                   serialized ThresholdPublicKey object.
            SerializerClass::class --
                The class that provides the serialization. XMLSerializer by 
                default. Must inherit from serialize.BaseSerializer and provide 
                an adequate serialize_to_file method.
                Note that often the same class used to serialize the data must 
                be used to deserialize it.
                (see utilities/serialize.py documentation for more information)
        """
        # Create a new serializer object for the PublicKey structure definition
        serializer = SerializerClass(PublicKey_serialize_structure_definition)
        
        # Helper function to translate large numbers to their hexadecimal 
        # string representation
        def num_to_hex_str(num):
            hex_str = hex(num)[2:]              # Remove leading '0x'
            if(hex_str[-1] == 'L'): 
                hex_str = hex_str[0:-1]         # Remove trailing 'L'
            return hex_str
        
        # Generate a serializable data dictionary matching the definition:
        prime_str = num_to_hex_str(self.cryptosystem.get_prime())
        generator_str = num_to_hex_str(self.cryptosystem.get_generator())
        
        verification_data_list = []
        for i in range(self.num_trustees):
            verification_pk_data = {
                "key" : num_to_hex_str(self._partial_public_keys[i]),
                "trustee" : str(i)
            }
            verification_data_list.append(verification_pk_data)
            
        data = {
            "PloneVotePublicKey" : {
                "PublicKey" : num_to_hex_str(self._key),
                "CryptoSystemScheme" : {
                    "nbits" : str(self.cryptosystem.get_nbits()),
                    "prime" : prime_str,
                    "generator" : generator_str
                },
                "ThresholdKeyInfo" : {
                    "NumTrustees" : str(self.num_trustees),
                    "Threshold" : str(self.threshold),
                    "PartialPublicKey" : verification_data_list
                }
            }
        }
        
        # Use the serializer to store the data to file
        serializer.serialize_to_file(filename, data)
    

    @classmethod
    def from_file(cls, filename, SerializerClass=serialize.XMLSerializer):
        """
        Loads an instance of ThresholdPublicKey from the given file.
        
        Arguments:
            filename::string    -- The name of a file containing the threshold 
                                   public key in serialized form.
            SerializerClass::class --
                The class that provides the deserialization. XMLSerializer by 
                default. Must inherit from serialize.BaseSerializer and provide 
                an adequate deserialize_from_file method.
                Note that often the same class used to serialize the data must 
                be used to deserialize it.
                (see utilities/serialize.py documentation for more information)
        
        Throws:
            InvalidPloneVoteCryptoFileError -- If the file is not a valid 
                                               PloneVoteCryptoLib stored 
                                               public key file.
        """
        # Create a new serializer object for the PublicKey structure definition
        serializer = SerializerClass(PublicKey_serialize_structure_definition)
        
        # Deserialize the ThresholdPublicKey instance from file
        try:
            data = serializer.deserialize_from_file(filename)
        except serialize.InvalidSerializeDataError, e:
            # Convert the exception to an InvalidPloneVoteCryptoFileError
            raise InvalidPloneVoteCryptoFileError(filename, 
                "File \"%s\" does not contain a valid threshold public key. " \
                "The following error occurred while trying to deserialize " \
                "the file contents: %s" % (filename, str(e)))
                
        # Verify that we are dealing with a threshold public key and not a 
        # single public key.
        if(not \
           data["PloneVotePublicKey"].has_key("ThresholdKeyInfo")):
            raise InvalidPloneVoteCryptoFileError(filename, 
                "File \"%s\" does not contain a valid threshold public key. " \
                "Instead it contains a single (non-threshold) public key" \
                % filename)
                
        # Helper function to decode numbers from strings and 
        # raise an exception if the string is not a valid number.
        # (value_name is used only to construct the exception string).
        def str_to_num(num_str, base, value_name):
            try:
                return int(num_str, base)
            except ValueError:
                raise InvalidPloneVoteCryptoFileError(filename, 
                    "File \"%s\" does not contain a valid threshold public " \
                    "key. The stored value for %s is not a valid integer in " \
                    "base %d representation." % (filename, value_name, base))
                    
        # Get the values from the deserialized data
        inner_elems = data["PloneVotePublicKey"]["CryptoSystemScheme"]
        nbits = str_to_num(inner_elems["nbits"], 10, "nbits")
        prime = str_to_num(inner_elems["prime"], 16, "prime")
        generator = str_to_num(inner_elems["generator"], 16, "generator")
        
        pub_key = str_to_num(data["PloneVotePublicKey"]["PublicKey"], 
                                  16, "PublicKey")
       
        threshold_info = data["PloneVotePublicKey"]["ThresholdKeyInfo"]
        
        num_trustees = \
                    str_to_num(threshold_info["NumTrustees"], 10, "NumTrustees")
        threshold = \
                    str_to_num(threshold_info["Threshold"], 10, "Threshold")
        
        pp_keys = threshold_info["PartialPublicKey"]
        partial_public_keys = [None for o in pp_keys]
        for pp_key in pp_keys:
            trustee = str_to_num(pp_key["trustee"], 10, "trustee")
            key_val = str_to_num(pp_key["key"], 16, "key")
            partial_public_keys[trustee] = key_val
            
        
        # Check the loaded values
        if(not (1 <= pub_key <= prime - 2)):
            raise InvalidPloneVoteCryptoFileError(filename, 
                "File \"%s\" does not contain a valid public key. The value " \
                "of the public key given in the file does not match the " \
                "indicated cryptosystem. Could the file be corrupt?" % filename)
                
        for pp_key in partial_public_keys:
            if(not (1 <= pp_key <= prime - 2)):
                raise InvalidPloneVoteCryptoFileError(filename, 
                    "File \"%s\" does not contain a valid public key. The " \
                    "value of at least one of the partial public keys given " \
                    "in the file does not match the indicated cryptosystem. " \
                    "Could the file be corrupt?" % filename)
        
        # Construct the cryptosystem object
        cryptosystem = EGCryptoSystem.load(nbits, prime, generator)
        
        # Construct and return the PublicKey object
        return cls(cryptosystem, num_trustees, threshold, pub_key, 
                   partial_public_keys)
