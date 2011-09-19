# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  ThresholdPublicKey.py : 
#  A private key generated in a threshold encryption scheme.
#
#  Multiple threshold private keys are required in order to decrypt a 
#  ciphertext encrypted in a threshold encryption scheme.
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

# secure version of python's random:
from Crypto.Random.random import StrongRandom
import Crypto.Hash.SHA256    # sha256 is not available in python 2.4 standard lib

from plonevotecryptolib.Threshold.ThresholdPublicKey import ThresholdPublicKey
from plonevotecryptolib.Threshold.PartialDecryption import PartialDecryption, \
                                                    PartialDecryptionBlock, \
                                                    PartialDecryptionBlockProof

from plonevotecryptolib.PVCExceptions import InvalidPloneVoteCryptoFileError, \
                                             IncompatibleCiphertextError
import plonevotecryptolib.utilities.serialize as serialize
from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem

# ============================================================================
    
ThresholdPrivateKey_serialize_structure_definition = {
    "PloneVoteThresholdPrivateKey" : (1, 1, {    # Root element
        "PrivateKey" : (1, 1, None),    # exactly 1 PrivateKey element
        "CryptoSystemScheme" : (1, 1, { # 1 cryptosystem element, containing:
            "nbits" : (1, 1, None),     # exactly 1 nbits element
            "prime" : (1, 1, None),     # exactly 1 prime element
            "generator" : (1, 1, None)  # exactly 1 generator element
         }),
         "ThresholdKeyInfo" : (1, 1, {  # exactile 1 occurrences
            "NumTrustees" : (1, 1, None), #num of trustees
            "Threshold" : (1, 1, None),   #threshold
            "ThresholdPublicKey" : (1,1,None), #  1 ThresholdPublicKey element
            "PartialPublicKey" : (1, {  # 1 or more PartialPublicKey elements
                "key" : (1, 1, None),    # exactly 1 key element
                "trustee" : (1, 1, None) # exactly one trustee element
             })
         })
    })
}

# ============================================================================
# Classes:
# ============================================================================

class ThresholdPrivateKey:
    """
    A private key generated in a threshold encryption scheme.
    
    Multiple threshold private keys are required in order to decrypt a 
    ciphertext encrypted in a threshold encryption scheme. Because of this, the 
    interface and usage of this class is significantly different from that of 
    PrivateKey (which is why this class is not a subclass of PrivateKey).
    
    Note that multiple threshold private keys are associated with each 
    threshold public key, one for each trustee. This again in contrast with 
    simple private/public keys which are paired.
    
    Attributes:
        cryptosystem::EGCryptoSystem    -- The ElGamal cryptosystem in which 
                                           this key is defined.
        num_trustees::int    -- Total number of trustees in the threshold scheme.
                               (the n in "k of n"-decryption)
        threshold::int    -- Minimum number of trustees required to decrypt 
                           threshold  encrypted messages. 
                           (the k in "k of n"-decryption)
        public_key::ThresholdPublicKey    -- The threshold public key to which 
                                           this threshold private key is 
                                           associated.
    """
    
    def __init__(self, cryptosystem, num_trustees, threshold, 
                 threshold_public_key, private_key_value):
        """
        Creates a new threshold private key. Should not be invoked directly.
        
        Instead of using this constructor from outside of PloneVoteCryptoLib, 
        please use ThresholdEncryptionSetUp.generate_private_key() or 
        ThresholdEncryptionSetUp.generate_key_pair().
        
        Arguments:
            (see class attributes for cryptosystem, num_trustees and threshold)
            threshold_public_key::ThresholdPublicKey    -- 
                                The threshold public key to which this 
                                threshold private key is associated.
            private_key_value::long        -- The actual value of the private key
                            (P(j) for trustee j, see ThresholdEncryptionSetUp)
        """
        self.cryptosystem = cryptosystem
        self.num_trustees = num_trustees
        self.threshold = threshold
        self.public_key = threshold_public_key
        self._key = private_key_value
    
    def generate_partial_decryption(self, ciphertext, task_monitor=None, 
                                    force=False):
        """
        Generates a partial decryption for the given ciphertext.
        
        Arguments:
            ciphertext::Ciphertext    -- An encrypted Ciphertext object.
            task_monitor::TaskMonitor    -- A task monitor for this task.
            force:bool    -- Set this to true if you wish to force a decryption 
                           attempt, even when the ciphertext's stored public key
                           fingerprint does not match that of the public key 
                           associated with this private key.
        
        Returns:
            partial_decryption::PartialDecryption    -- A partial decryption of 
                                                       the given ciphertext 
                                                       generated with this 
                                                       threshold private key.
        
        Throws:
            IncompatibleCiphertextError -- The given ciphertext does not appear 
                                           to be decryptable with the selected 
                                           private key.
        """
        # Check that the public key fingerprint stored in the ciphertext 
        # matches the public key associated with this private key.
        if(not force):
            if(ciphertext.nbits != self.cryptosystem.get_nbits()):
                raise IncompatibleCiphertextError("The given ciphertext is " \
                        "not decryptable with the selected private key: " \
                        "incompatible cryptosystem/key sizes.")
            
            if(ciphertext.pk_fingerprint != self.public_key.get_fingerprint()):
                raise IncompatibleCiphertextError("The given ciphertext is " \
                        "not decryptable with the selected private key: " \
                        "public key fingerprint mismatch.")
        
        nbits = self.cryptosystem.get_nbits()
        prime = self.cryptosystem.get_prime()
        generator = self.cryptosystem.get_generator()
        key = self._key
        
        # Remember that prime is of the form p = 2*q + 1, with q prime.
        # (By construction, see EGCryptoSystem)
        q = (prime - 1)/2
        
        # We will need a random number generator for the proofs of partial 
        # decryption.
        random = StrongRandom()
        
        # New empty partial decryption
        partial_decryption = PartialDecryption(nbits)
        
        # Check if we have a task monitor and register with it
        if(task_monitor != None):
            # One tick per block
            ticks = ciphertext.get_length()
            partial_decrypt_task_mon = \
                task_monitor.new_subtask("Generate partial decryption", 
                                         expected_ticks = ticks)
        
        # For each (gamma,delta) component in the ciphertext, generate one  
        # partial decryption block (with proof):
        for gamma, delta in ciphertext:
        
            # To calculate the value of the block, elevate gamma to the 
            # threshold private key. That is block.value = g^{rP(i)} for each 
            # nbits block of original plaintext.
            value = pow(gamma, key, prime)
            
            # Generate the partial decryption proof for the block as a
            # Zero-Knowledge Discrete Logarithm Equality Test for 
            # log_{g}(g^{2P(j)}) == log_{gamma}(block^2)
            # (See PartialDecryptionBlockProof and [TODO: Add reference] for 
            # more information.)
            
            # Select a random s in Z_{q}^{*}
            s = random.randint(1, q - 1)
            
            # a = g^{s} mod p
            a = pow(generator, s, prime)
            
            # b = gamma^{s} mod p
            b = pow(gamma, s, prime)
            
            # c is SHA256(a, b, g^{2*P(j)}, block.value) the challenge
            # (We must use g^{2*P(j)} and not g^{P(j)}, because the first is 
            # considered as the partial public key of trustee j and the value 
            # of the later is unavailable at decryption combination time).
            sha256 =  Crypto.Hash.SHA256.new()
            sha256.update(hex(a))
            sha256.update(hex(b))
            sha256.update(hex(pow(generator, 2*key, prime)))
            sha256.update(hex(value))
            c = int(sha256.hexdigest(),16)
            
            # t = s + 2P(j)*c mod p-1 (P(j): trustee j's threshold private key)
            # (p - 1 since it is in the exponent and we are already adding the 2
            # factor in 2P(j))
            t = (s + 2*key*c) % (prime - 1)
            
            # Generate the PartialDecryptionBlockProof as (a, b, t)
            proof = PartialDecryptionBlockProof(a, b, t)
            
            # Generate the block as (value, proof) and add it to the partial 
            # decryption object.
            block = PartialDecryptionBlock(value, proof)
            partial_decryption.add_partial_decryption_block(block)
            
            # Update task progress
            if(task_monitor != None): partial_decrypt_task_mon.tick()
        
        return partial_decryption
            
        
    def to_file(self, filename, SerializerClass=serialize.XMLSerializer):
        """
        Saves this threshold private key to a file.
        
        Arguments:
            filename::string    -- The path to the file in which to store the 
                                   serialized ThresholdPrivateKey object.
            SerializerClass::class --
                The class that provides the serialization. XMLSerializer by 
                default. Must inherit from serialize.BaseSerializer and provide 
                an adequate serialize_to_file method.
                Note that often the same class used to serialize the data must 
                be used to deserialize it.
                (see utilities/serialize.py documentation for more information)
        """
        # Create a new serializer object for the PrivateKey structure definition
        serializer = \
             SerializerClass(ThresholdPrivateKey_serialize_structure_definition)
        
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
                "key" : num_to_hex_str(self.public_key._partial_public_keys[i]),
                "trustee" : str(i)
            }
            verification_data_list.append(verification_pk_data)
            
        data = {
            "PloneVoteThresholdPrivateKey" : {
                "PrivateKey" : num_to_hex_str(self._key),
                "CryptoSystemScheme" : {
                    "nbits" : str(self.cryptosystem.get_nbits()),
                    "prime" : prime_str,
                    "generator" : generator_str
                },
                "ThresholdKeyInfo" : {
                    "NumTrustees" : str(self.num_trustees),
                    "Threshold" : str(self.threshold),
                    "ThresholdPublicKey" : num_to_hex_str(self.public_key._key),
                    "PartialPublicKey" : verification_data_list
                }
            }
        }
        
    
        # Use the serializer to store the data to file
        serializer.serialize_to_file(filename, data)
 
    @classmethod
    def from_file(cls, filename, SerializerClass=serialize.XMLSerializer):
        """
        Loads an instance of ThresholdPrivateKey from the given file.
        
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
        serializer = SerializerClass(
                             ThresholdPrivateKey_serialize_structure_definition)
        
        # Deserialize the ThresholdPrivateKey instance from file
        try:
            data = serializer.deserialize_from_file(filename)
        except serialize.InvalidSerializeDataError, e:
            # Convert the exception to an InvalidPloneVoteCryptoFileError
            raise InvalidPloneVoteCryptoFileError(filename, 
                "File \"%s\" does not contain a valid threshold private key. " \
                "The following error occurred while trying to deserialize " \
                "the file contents: %s" % (filename, str(e)))
                
        # Helper function to decode numbers from strings and 
        # raise an exception if the string is not a valid number.
        # (value_name is used only to construct the exception string).
        def str_to_num(num_str, base, value_name):
            try:
                return int(num_str, base)
            except ValueError:
                raise InvalidPloneVoteCryptoFileError(filename, 
                    "File \"%s\" does not contain a valid threshold private " \
                    "key. The stored value for %s is not a valid integer in " \
                    "base %d representation." % (filename, value_name, base))
                         
        # Get the values from the deserialized data
        inner_elems = data["PloneVoteThresholdPrivateKey"]["CryptoSystemScheme"]
        nbits = str_to_num(inner_elems["nbits"], 10, "nbits")
        prime = str_to_num(inner_elems["prime"], 16, "prime")
        generator = str_to_num(inner_elems["generator"], 16, "generator")
        
        prv_key = str_to_num(data["PloneVoteThresholdPrivateKey"]["PrivateKey"], 
                                  16, "PrivateKey")
        threshold_info = \
                        data["PloneVoteThresholdPrivateKey"]["ThresholdKeyInfo"]
        num_trustees = \
                    str_to_num(threshold_info["NumTrustees"], 10, "NumTrustees")
        threshold = \
                    str_to_num(threshold_info["Threshold"], 10, "Threshold")
        pub_key = str_to_num(threshold_info["ThresholdPublicKey"], 
                                  16, "PublicKey")
        pp_keys = threshold_info["PartialPublicKey"]
        partial_public_keys = [None for o in pp_keys]
        for pp_key in pp_keys:
            trustee = str_to_num(pp_key["trustee"], 10, "trustee")
            key_val = str_to_num(pp_key["key"], 16, "key")
            partial_public_keys[trustee] = key_val
            
        
        # Check the loaded values
        if(not (1 <= prv_key <= prime - 2)):
            raise InvalidPloneVoteCryptoFileError(filename, 
                "File \"%s\" does not contain a valid threshold private key."\
                "The value of the private key given in the file does" \
                "not match the indicated cryptosystem. Could the file be" \
                "corrupt?" % filename)
                
        if(not (1 <= pub_key <= prime - 2)):
            raise InvalidPloneVoteCryptoFileError(filename, 
                "File \"%s\" does not contain a valid threshold private key."\
                "The value of the threshold public key given in the file does" \
                "not match the indicated cryptosystem. Could the file be" \
                "corrupt?" % filename)
                
        for pp_key in partial_public_keys:
            if(not (1 <= pp_key <= prime - 2)):
                raise InvalidPloneVoteCryptoFileError(filename, 
                    "File \"%s\" does not contain a valid threshold private "\
                    "key. The value of at least one of the partial public  " \
                    "keys given in the file does not match the indicated " \
                    "cryptosystem.  Could the file be corrupt?" % filename)
        
        # Construct the cryptosystem object
        cryptosystem = EGCryptoSystem.load(nbits, prime, generator)
        
        # Contruct the Threshold Public Key
        threshold_public_key = ThresholdPublicKey(cryptosystem, num_trustees, threshold, pub_key, 
                   partial_public_keys)
                   
        # Construct and return the ThresholdPrivateKey object
        
        return cls(cryptosystem, num_trustees, threshold, 
                 threshold_public_key, prv_key)
