# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  PublicKey.py : The private key class.
#
#  Used for data decryption.
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

from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem, EGStub
from plonevotecryptolib.PublicKey import PublicKey
from plonevotecryptolib.Ciphertext import Ciphertext
from plonevotecryptolib.PVCExceptions import InvalidPloneVoteCryptoFileError
from plonevotecryptolib.PVCExceptions import IncompatibleCiphertextError
from plonevotecryptolib.utilities.BitStream import BitStream

class PrivateKey:
    """
    An ElGamal private key object used for decryption.
    
    Attributes:
        cryptosystem::EGCryptoSystem    -- The ElGamal cryptosystem in which 
                                           this key is defined.
        public_key::PublicKey    -- The associated public key.
    """
    
    def __eq__(self, other):
        """
        Implements PrivateKey equality.
        """
        if((other.cryptosystem == self.cryptosystem) and  
           (other.public_key == self.public_key) and  
           (other._key == self._key)):
            return True
        else:
            return False
    
    def __ne__(self, other):
        """
        Implements PrivateKey inequality.
        """
        return not self.__eq__(other)
    
    def __init__(self, cryptosystem, public_key, private_key_value):
        """
        Creates a new private key. Should not be invoked directly.
        
        Instead of using this constructor from outside of PloneVoteCryptoLib, 
        please use the class methods EGCryptoSystem.new_key_pair() or 
        PrivateKey.from_file(file).
        
        Arguments:
            cryptosystem::EGCryptoSystem-- The ElGamal cryptosystem in which 
                                           this key is defined.
            public_key::PublicKey        -- The associated public key.
            private_key_value::long        -- The actual value of the private key.
        """
        self.cryptosystem = cryptosystem
        self.public_key = public_key
        self._key = private_key_value
        
    def decrypt_to_bitstream(self, ciphertext, task_monitor=None, force=False):
        """
        Decrypts the given ciphertext into a bitstream.
        
        If the bitstream was originally encrypted with PublicKey.encrypt_X(), 
        then this method returns a bitstream following the format described 
        in Note 001 of the Ciphertext.py file:
            [size (64 bits) | message (size bits) | padding (X bits) ]
        
        Arguments:
            ciphertext::Ciphertext    -- An encrypted Ciphertext object.
            task_monitor::TaskMonitor    -- A task monitor for this task.
            force:bool    -- Set this to true if you wish to force a decryption 
                           attempt, even when the ciphertext's stored public key
                           fingerprint does not match that of the public key 
                           associated with this private key.
        
        Returns:
            bitstream::Bitstream    -- A bitstream containing the unencrypted 
                                       data.
        
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
        
        # We read and decrypt the ciphertext block by block
        # See "Handbook of Applied Cryptography" Algorithm 8.18
        bitstream = BitStream()
        
        block_size = self.cryptosystem.get_nbits() - 1
        prime = self.cryptosystem.get_prime()
        key = self._key
        
        # Check if we have a task monitor and register with it
        if(task_monitor != None):
            # One tick per block
            ticks = ciphertext.get_length()
            decrypt_task_mon = \
                task_monitor.new_subtask("Decrypt data", expected_ticks = ticks)
        
        for gamma, delta in ciphertext:
            assert max(gamma, delta) < 2**(block_size + 1), \
                "The ciphertext object includes blocks larger than the " \
                "expected block size."
            m = (pow(gamma, prime - 1 - key, prime) * delta) % prime
            bitstream.put_num(m, block_size)
            
            if(task_monitor != None): decrypt_task_mon.tick()
            
        return bitstream
            
    
    def decrypt_to_text(self, ciphertext, task_monitor=None, force=False):
        """
        Decrypts the given ciphertext into its text contents as a string
        
        This method assumes that the ciphertext contains an encrypted stream of 
        data in the format of Note 001 of the Ciphertext.py file, were message 
        contains string information (as opposed to a binary format).
            [size (64 bits) | message (size bits) | padding (X bits) ]
        
        Arguments:
            ciphertext::Ciphertext    -- An encrypted Ciphertext object, 
                                       containing data in the above format.
            task_monitor::TaskMonitor    -- A task monitor for this task.
            force:bool    -- Set to true if you wish to force a decryption 
                           attempt, even when the ciphertext's stored public key
                           fingerprint does not match that of the public key 
                           associated with this private key.
        
        Returns:
            string::string    -- Decrypted message as a string.
        
        Throws:
            IncompatibleCiphertextError -- The given ciphertext does not appear 
                                           to be decryptable with the selected 
                                           private key.
        """
        bitstream = self.decrypt_to_bitstream(ciphertext, task_monitor, force)
        bitstream.seek(0)
        length = bitstream.get_num(64)
        return bitstream.get_string(length)
        
    def _to_xml(self):
        """
        Returns an xml document containing a representation of this private key.
        
        Returns:
            doc::xml.dom.minidom.Document
        """
        doc = xml.dom.minidom.Document()
        root_element = doc.createElement("PloneVotePrivateKey")
        doc.appendChild(root_element)
        
        priv_key_element = doc.createElement("PrivateKey")
        priv_key_str = hex(self._key)[2:]        # Remove leading '0x'
        if(priv_key_str[-1] == 'L'): 
            priv_key_str = priv_key_str[0:-1]        # Remove trailing 'L'
        priv_key_element.appendChild(doc.createTextNode(priv_key_str))
        root_element.appendChild(priv_key_element)
        
        pub_key_element = doc.createElement("PublicKey")
        pub_key_str = hex(self.public_key._key)[2:]        # Remove leading '0x'
        if(pub_key_str[-1] == 'L'): 
            pub_key_str = pub_key_str[0:-1]        # Remove trailing 'L'
        pub_key_element.appendChild(doc.createTextNode(pub_key_str))
        root_element.appendChild(pub_key_element)
        
        cs_scheme_element = self.cryptosystem.to_dom_element(doc)
        root_element.appendChild(cs_scheme_element)
        
        return doc
        
    def to_file(self, filename):
        """
        Saves this private key to a file.
        """
        doc = self._to_xml()
        
        file_object = open(filename, "w")
        file_object.write(doc.toprettyxml())
        file_object.close()
        
    @classmethod
    def from_file(cls, filename):
        """
        Loads a private key from file.
        """
        doc = xml.dom.minidom.parse(filename)
        
        # Check root element
        if(len(doc.childNodes) != 1 or 
            doc.childNodes[0].nodeType != doc.childNodes[0].ELEMENT_NODE or
            doc.childNodes[0].localName != "PloneVotePrivateKey"):
            
            raise InvalidPloneVoteCryptoFileError(filename, 
                "A PloneVoteCryptoLib stored private key file must be an " \
                "XML file with PloneVotePrivateKey as its root element.")    
        
        root_element = doc.childNodes[0]
        
        cs_scheme_element = pub_key_element = priv_key_element = None
        
        # Retrieve individual "tier 2" nodes
        for node in root_element.childNodes:
            if node.nodeType == node.ELEMENT_NODE:
                if node.localName == "PublicKey":
                    pub_key_element = node
                elif node.localName == "PrivateKey":
                    priv_key_element = node
                elif node.localName == "CryptoSystemScheme":
                    cs_scheme_element = node
                    
        # Check CryptoSystemScheme node
        if(cs_scheme_element == None):
            raise InvalidPloneVoteCryptoFileError(filename, 
                "A PloneVoteCryptoLib stored public key file must contain " \
                "a CryptoSystemScheme element")
        
        # Parse the inner CryptoSystemScheme element using the parser defined
        # in EGStub
        (nbits, prime, generator) = \
                    EGStub.parse_crytosystem_scheme_xml_node(cs_scheme_element)    
        
        # Check the public key information
        if(pub_key_element == None):
            raise InvalidPloneVoteCryptoFileError(filename, 
                "The PloneVoteCryptoLib stored private key file must contain " \
                "a <PublicKey> element, with the value of the public key " \
                " inside it.")
                
        if(len(pub_key_element.childNodes) != 1 or 
            pub_key_element.childNodes[0].nodeType != pub_key_element.childNodes[0].TEXT_NODE):
            
            raise InvalidPloneVoteCryptoFileError(filename, 
                "The PloneVoteCryptoLib stored private key file must contain " \
                "a <PublicKey> element, with the value of the public key " \
                " inside it.")
        
        pub_key_str = pub_key_element.childNodes[0].data.strip()  # trim spaces
        pub_key = int(pub_key_str, 16)
        
        if(not (0 <= pub_key < prime)):
            raise InvalidPloneVoteCryptoFileError(filename, 
                "The value of the public key given in the file is invalid " \
                "for the indicated cryptosystem (could the file be corrupt?).")
        
        # Check the private key information
        if(priv_key_element == None):
            raise InvalidPloneVoteCryptoFileError(filename, 
                "The PloneVoteCryptoLib stored private key file must contain " \
                "a <PrivateKey> element, with the value of the private key " \
                " inside it.")
                
        if(len(priv_key_element.childNodes) != 1 or 
            priv_key_element.childNodes[0].nodeType != priv_key_element.childNodes[0].TEXT_NODE):
            
            raise InvalidPloneVoteCryptoFileError(filename, 
                "The PloneVoteCryptoLib stored private key file must contain " \
                "a <PrivateKey> element, with the value of the private key " \
                " inside it.")
        
        priv_key_str = priv_key_element.childNodes[0].data.strip() # trim spaces
        priv_key = int(priv_key_str, 16)
        
        if(not (1 <= priv_key <= prime - 2)):
            raise InvalidPloneVoteCryptoFileError(filename, 
                "The value of the private key given in the file is invalid " \
                "for the indicated cryptosystem (could the file be corrupt?).")
        
        # Construct the cryptosystem object
        cryptosystem = EGCryptoSystem.load(nbits, prime, generator)
        
        # Construct the PublicKey object
        public_key = PublicKey(cryptosystem, pub_key)
        
        # Construct and return the PrivateKey object
        return cls(cryptosystem, public_key, priv_key)
