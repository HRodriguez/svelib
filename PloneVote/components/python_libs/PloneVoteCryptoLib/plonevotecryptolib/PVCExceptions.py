# -*- coding: utf-8 -*-
#
#  PVCExceptions.py : Custom exceptions used by PloneVoteCryptoLib.
#
#  Part of the PloneVote cryptographic library (PloneVoteCryptoLib)
#
#  Originally written by: Lazaro Clapp
#
# ===================================================================
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
# ===================================================================

class ParameterError(Exception):
    """
    Parameter error exception.
    
    The base exception for when invalid parameters are fed to the 
    PloneVoteCryptoLib public classes and methods.

    Attributes:
        msg::string	-- explanation of the error
    """

    def __init__(self, msg):
    	"""Create a new ParameterError exception
    	
    	Arguments:
        	msg::string	-- explanation of the error
    	"""
        self.msg = msg


class KeyLengthTooLowError(ParameterError):
    """
    Key length (or cryptosystem bit size) too low exception.
    
    Exception raised when the length of the keys or the size in bits given 
    for the cryptosystem fall below the minimum allowed and thus may not be 
    secure enough. 
    
    (This minimum can be configured in params)

    Attributes:
    	given_size::int		-- the (invalid) key or cryptosystem bit size  
    				 	  	   requested by the user
    	minimum_size::int	-- the minimum key or cryptosystem bit size allowed
        msg::string			-- explanation of the error
    """

    def __init__(self, given_size, minimum_size, msg):
    	"""Create a new KeyLengthTooLowError exception
    	
    	Arguments:
			given_size::int		-- the (invalid) key or cryptosystem bit size  
						 	  	   requested by the user
			minimum_size::int	-- the minimum key or cryptosystem bit size 
								   allowed
		    msg::string			-- explanation of the error
    	"""
    	self.given_size = given_size
    	self.minimum_size = minimum_size
        ParameterError.__init__(self, msg)


class KeyLengthNonBytableError(ParameterError):
    """
    Key length (or cryptosystem bit size) is not expressible in bytes.
    
    Exception raised when the length of the keys or the size in bits given 
    for the cryptosystem is not a multiple of 8 and thus the resulting 
    cryptosystem cannot easily encrypt and decrypt byte arrays. Currently,
    key sizes that are not expressible in whole bytes are not permitted by 
    PloneVoteCryptoLib. 

    Attributes:
    	given_size::int		-- the (invalid) key or cryptosystem bit size  
    				 	  	   requested by the user
        msg::string			-- explanation of the error
    """

    def __init__(self, given_size, msg):
    	"""Create a new KeyLengthNonBytableError exception
    	
    	Arguments:
			given_size::int		-- the (invalid) key or cryptosystem bit size  
						 	  	   requested by the user
		    msg::string			-- explanation of the error
    	"""
    	self.given_size = given_size
        ParameterError.__init__(self, msg)


class NotASafePrimeError(ParameterError):
    """
    Given number is not a safe prime.
    
    Exception raised when a number claimed to be a safe prime for an ElGamal 
    scheme is not really a safe prime. 

    Attributes:
    	num::int	-- the given number
        msg::string	-- explanation of the error
    """

    def __init__(self, num, msg):
    	"""Create a new NotASafePrimeError exception
    	
    	Arguments:
    		num::int	-- the given number
		    msg::string	-- explanation of the error
    	"""
    	self.num = num
        ParameterError.__init__(self, msg)


class NotAGeneratorError(ParameterError):
    """
    Given number is not a generator.
    
    Exception raised when a number claimed to be a generator for an ElGamal 
    scheme with a certain prime is not really a generator. 

    Attributes:
    	prime::int	-- the prime defining the Z_{p}^{*} cyclic group of which 
    				   a generator was sought
    	num::int	-- the given number
        msg::string	-- explanation of the error
    """

    def __init__(self, prime, num, msg):
    	"""Create a new NotAGeneratorError exception
    	
    	Arguments:
			prime::int	-- the prime defining the Z_{p}^{*} cyclic group of  
						   which a generator was sought
			num::int	-- the given number
		    msg::string	-- explanation of the error
    	"""
    	self.prime = prime
    	self.num = num
        ParameterError.__init__(self, msg)


