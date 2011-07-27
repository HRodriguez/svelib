# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestBitStream.py : Unit tests for plonevotecryptolib/utilities/BitStream.py
#
#  For usage documentation of BitStream.py, see:
#    * plonevotecryptolib/tests/doctests/bitstream_usage_doctest.txt
#    * the documentation strings for the classes and methods of BitStream.py
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

import unittest
import random
from plonevotecryptolib.utilities.BitStream import BitStream, \
                                                   NotEnoughBitsInStreamError, \
                                                   SeekOutOfRangeError

class TestBitStream(unittest.TestCase):
    """
    Test the class: plonevotecryptolib.utilities.BitStream.BitStream
    """
    
    ## =======================================================================
    ## Basic initialization tests:
    ## =======================================================================
    
    def test_bitstream_constructor(self):
        """
        Test that creating an empty bitstream succeeds.
        """
        bitstream = BitStream()
        # An empty bitstream has length 0 ...
        self.assertEqual(bitstream.get_length(), 0)
        # ...and has its current position marker at position 0.
        self.assertEqual(bitstream.get_current_pos(), 0)
    
    ## =======================================================================
    ## put_num & get_num tests:
    ## =======================================================================
    
    def test_num_basic(self):
        """
        Test basic put_num and get_num behavior
        """
        bitstream = BitStream()
        
        # Some parameters
        num_sizes = [4,8,16,32,64,128,256,2839]
        num_writes = 10
        nums = []
        
        # Add num_writes integers of each size to nums:
        for i in range(0,len(num_sizes)):
            max_val = 2**num_sizes[i] - 1
            nums.append([])
            for j in range(0,num_writes):
                # append a random number between 0 and max_val, inclusive
                nums[i].append(random.randint(0, max_val))
                 
        # Write all values in nums to the stream
        for i in range(0,len(num_sizes)):
            for j in range(0,num_writes):
                bitstream.put_num(nums[i][j], num_sizes[i])
                
        # Go back to start of the stream
        bitstream.seek(0)
        
        # Sanity check:
        expected_length = 0
        for num_size in num_sizes: expected_length += num_size * num_writes
        self.assertEqual(bitstream.get_length(), expected_length)
                
        # Read them back and compare
        for i in range(0,len(num_sizes)):
            for j in range(0,num_writes):
                n = bitstream.get_num(num_sizes[i])
                self.assertEqual(n, nums[i][j])
                
    def test_num_read_part(self):
        """
        Test that we can read only some bits of a large number and interpret 
        them as a shorter number with the expected value.
        """
        bitstream = BitStream()
        
        # Store a 64-bit integer in the stream.
        num = int('00000000000000110101011001010011'
                  '00101100001000101000100110101111', 2)
        bitstream.put_num(num, 64)
        
        # Get it as 8-bit numbers
        bitstream.seek(0)
        self.assertEqual(bitstream.get_num(8),int('00000000',2))
        self.assertEqual(bitstream.get_num(8),int('00000011',2))
        self.assertEqual(bitstream.get_num(8),int('01010110',2))
        self.assertEqual(bitstream.get_num(8),int('01010011',2))
        self.assertEqual(bitstream.get_num(8),int('00101100',2))
        self.assertEqual(bitstream.get_num(8),int('00100010',2))
        self.assertEqual(bitstream.get_num(8),int('10001001',2))
        self.assertEqual(bitstream.get_num(8),int('10101111',2))
        
        # Get it as 16-bit numbers
        bitstream.seek(0)
        self.assertEqual(bitstream.get_num(16),int('0000000000000011',2))
        self.assertEqual(bitstream.get_num(16),int('0101011001010011',2))
        self.assertEqual(bitstream.get_num(16),int('0010110000100010',2))
        self.assertEqual(bitstream.get_num(16),int('1000100110101111',2))
        
        # Get it as 32-bit numbers
        bitstream.seek(0)
        self.assertEqual(bitstream.get_num(32),
                         int('00000000000000110101011001010011',2))
        self.assertEqual(bitstream.get_num(32),
                         int('00101100001000101000100110101111',2))
                
    def test_num_write_part(self):
        """
        Test that we can write a large number piece by piece and read it as 
        whole number.
        """
        bitstream = BitStream()
        
        # Store a 64-bit integer in the stream.
        num = int('00000000000000110101011001010011'
                  '00101100001000101000100110101111', 2)
        
        # ... in 8-bit, 16-bit and 32-bit increments        
        bitstream.put_num(int('00000000',2), 8)
        bitstream.put_num(int('0000001101010110',2), 16)
        bitstream.put_num(int('01010011001011000010001010001001',2), 32)        
        bitstream.put_num(int('10101111',2), 8)
        
        # Get it as a single 64-bit number
        bitstream.seek(0)
        self.assertEqual(bitstream.get_num(64),num)
                
    def test_put_num_non_integer(self):
        """
        Test that put_num raises an exception when passed non integer values as 
        its num argument.
        """
        bitstream = BitStream()
        self.assertRaises(TypeError, bitstream.put_num, "gato", 16)
        self.assertRaises(TypeError, bitstream.put_num, 0.1, 16)
        self.assertRaises(TypeError, bitstream.put_num, [1,'a',3], 16)
        self.assertRaises(TypeError, bitstream.put_num, object(), 16)
                
    def test_put_num_non_integer_length(self):
        """
        Test that put_num raises an exception when passed non integer values as 
        its bit_length argument.
        """
        bitstream = BitStream()
        self.assertRaises(TypeError, bitstream.put_num, 23, "gato")
        self.assertRaises(TypeError, bitstream.put_num, 23, 12.1)
        self.assertRaises(TypeError, bitstream.put_num, 23, [1,'a',3])
        self.assertRaises(TypeError, bitstream.put_num, 23, object())
                
    def test_put_num_negative(self):
        """
        Test that put_num raises an exception when passed negative integer 
        values as its num argument.
        """
        bitstream = BitStream()
        val = random.randint(-2**15+1,-1)
        self.assertRaises(ValueError, bitstream.put_num, val, 16)
                
    def test_put_num_negative_length(self):
        """
        Test that put_num raises an exception when passed negative integer 
        values as its bit_length argument.
        """
        bitstream = BitStream()
        val = random.randint(-128,-1)
        self.assertRaises(ValueError, bitstream.put_num, 23, val)
        
    def test_put_num_wrong_bit_length(self):
        """
        Test that put_num raises an exception when given incompatible num and 
        bit_length arguments (ie. num >= 2**bit_length)
        """
        bitstream = BitStream()
        self.assertRaises(ValueError, bitstream.put_num, 2**16, 16)
        val = random.randint(2**64+1,2**128)
        self.assertRaises(ValueError, bitstream.put_num, val, 64)
        
    
    ## =======================================================================
    ## seek tests:
    ## =======================================================================
    
    def test_seek_basic(self):
        """
        Use seek to read data at different points in the bitstream.
        """
        bitstream = BitStream()
        
        # Store a 64-bit integer in the stream.
        num = int('00000000000000110101011001010011'
                  '00101100001000101000100110101111', 2)
        bitstream.put_num(num, 64)
        
        # Get the 0th, 3rd, 5th and 6th bytes of the stream
        # First in forwards order
        bitstream.seek(0)
        self.assertEqual(bitstream.get_num(8),int('00000000',2))
        bitstream.seek(3*8)
        self.assertEqual(bitstream.get_num(8),int('01010011',2))
        bitstream.seek(5*8)
        self.assertEqual(bitstream.get_num(8),int('00100010',2))
        self.assertEqual(bitstream.get_num(8),int('10001001',2))
        # Then in backwards order
        bitstream.seek(6*8)
        self.assertEqual(bitstream.get_num(8),int('10001001',2))
        bitstream.seek(5*8)
        self.assertEqual(bitstream.get_num(8),int('00100010',2))
        bitstream.seek(3*8)
        self.assertEqual(bitstream.get_num(8),int('01010011',2))
        bitstream.seek(0)
        self.assertEqual(bitstream.get_num(8),int('00000000',2))
        
    def test_seek_beyond_eos(self):
        """
        Test that seeking beyond the end of the bitstream results in an 
        exception raised.
        """
        bitstream = BitStream()
        self.assertRaises(SeekOutOfRangeError, bitstream.seek, 1) # empty stream
        
        # Store a 64-bit integer in the stream.
        num = int('00000000000000110101011001010011'
                  '00101100001000101000100110101111', 2)
        bitstream.put_num(num, 64)
        
        # Test seeking past 64 bits
        self.assertRaises(SeekOutOfRangeError, bitstream.seek, 65)
        self.assertRaises(SeekOutOfRangeError, bitstream.seek, 
                          random.randint(66,2**128))
        
    def test_seek_negative_position(self):
        """
        Test that seeking to a negative position raises an error.
        """
        bitstream = BitStream()
        self.assertRaises(SeekOutOfRangeError, bitstream.seek, -1)
        
        
    
    ## =======================================================================
    ## put_byte & get_byte tests:
    ## =======================================================================
        
        
    
    ## =======================================================================
    ## Other tests:
    ## =======================================================================

    def test_bit_dump_string(self):
        """
        This method tests that put_bit_dump_string's and get_bit_dump_string's 
        basic functionality. Is important that this test passes as many 
        following tests assume that get_bit_dump_string and put_bit_dump_string 
        work reliably.
        """
        bitstream = BitStream()
        
        # Generate a random string of bits, ie: ('0' | '1')*
        num_bits = 50        
        bits = ""
        for i in range(0,num_bits):
            bits += random.choice(('0','1')) # inefficient, but ok for a test.
            
        # Put those bits in the BitStream...
        bitstream.put_bit_dump_string(bits)
        
        # ...and get them back
        bitstream.seek(0)
        read_bits = bitstream.get_bit_dump_string(len(bits))
        
        # Check that the bits were recovered correctly
        self.assertEqual(read_bits, bits)
        

if __name__ == '__main__':
    unittest.main()
