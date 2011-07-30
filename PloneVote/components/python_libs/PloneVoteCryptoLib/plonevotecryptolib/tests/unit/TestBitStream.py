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
import string
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
        
    def test_get_num_beyond_eos(self):
        """
        Test than trying to read beyond the end of the stream raises an 
        exception when calling get_num(...).
        """
        bitstream = BitStream()
        
        # Store a 64-bit integer in the stream.
        num = int('00000000000000110101011001010011'
                  '00101100001000101000100110101111', 2)
        bitstream.put_num(num, 64)
        
        # Check that trying to read 65 bits from the beginning of the stream
        # raises NotEnoughBitsInStreamError
        bitstream.seek(0)
        self.assertRaises(NotEnoughBitsInStreamError, bitstream.get_num, 65)
        # An invalid read call should not move the position indicator.
        self.assertEquals(bitstream.get_current_pos(), 0)
        
        # Check that trying to read 33 bits from the middle of the stream 
        # (pos = 32) raises NotEnoughBitsInStreamError
        bitstream.seek(32)
        self.assertRaises(NotEnoughBitsInStreamError, bitstream.get_num, 33)
        # An invalid read call should not move the position indicator.
        self.assertEquals(bitstream.get_current_pos(), 32)
        
        # Check that trying to read a single bit while at the end of the stream
        # raises NotEnoughBitsInStreamError
        bitstream.seek(64)
        self.assertRaises(NotEnoughBitsInStreamError, bitstream.get_num, 1)
        # An invalid read call should not move the position indicator.
        self.assertEquals(bitstream.get_current_pos(), 64)
        
    def test_get_num_zero_bits(self):
        """
        Test that reading zero bits from the stream as a number results in 
        getting the number 0.
        """
        bitstream = BitStream()
        self.assertEquals(bitstream.get_num(0), 0)
        
        # Store a 64-bit integer in the stream.
        num = int('00000000000000110101011001010011'
                  '00101100001000101000100110101111', 2)
        bitstream.put_num(num, 64)
        
        bitstream.seek(0)
        self.assertEquals(bitstream.get_num(0), 0)
        
    
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
        # An invalid seek(...) call should not move the position indicator.
        self.assertEqual(bitstream.get_current_pos(), 0)
        
        # Store a 64-bit integer in the stream.
        num = int('00000000000000110101011001010011'
                  '00101100001000101000100110101111', 2)
        bitstream.put_num(num, 64)
        
        # Test seeking past 64 bits
        self.assertRaises(SeekOutOfRangeError, bitstream.seek, 65)
        self.assertRaises(SeekOutOfRangeError, bitstream.seek, 
                          random.randint(66,2**128))
                          
        # An invalid seek(...) call should not move the position indicator.
        self.assertEqual(bitstream.get_current_pos(), 64)
        
    def test_seek_negative_position(self):
        """
        Test that seeking to a negative position raises an error.
        """
        bitstream = BitStream()
        self.assertRaises(SeekOutOfRangeError, bitstream.seek, -1)
        # An invalid seek(...) call should not move the position indicator.
        self.assertEqual(bitstream.get_current_pos(), 0)
        
        
    
    ## =======================================================================
    ## put_byte & get_byte tests:
    ## =======================================================================
        
    def test_byte_basic(self):
        """
        Test basic put_byte and get_byte behavior.
        """
        bitstream = BitStream()
        
        # Put a couple of bytes in the stream:
        
        bytes = [ 12,	# 00001100
	              222,	# 11011110
	              145,	# 10010001
	              42,	# 00101010
	              0,	# 00000000
	              255]	# 11111111
	              
        for byte in bytes:
            bitstream.put_byte(byte)
            
        # Sanity check:
        self.assertEquals(bitstream.get_length(),len(bytes)*8)
        self.assertEquals(bitstream.get_current_pos(),len(bytes)*8)
        
        # Read the bytes back from the stream
        bitstream.seek(0)
        for byte in bytes:
            self.assertEquals(bitstream.get_byte(), byte)
            
        # Read some bits from the stream, interpreting them as bytes, but 
        # without restricting ourselves to 8-bit aligned bytes
        # e.g. read the "byte" defined by bits #4 to #12
        bitstream.seek(4)
        self.assertEquals(bitstream.get_byte(), 205) # 11001101
        bitstream.seek(19)
        self.assertEquals(bitstream.get_byte(), 137) # 10001001
                
    def test_put_byte_non_integer(self):
        """
        Test that put_byte raises an exception when passed non integer values  
        as its argument.
        """
        bitstream = BitStream()
        self.assertRaises(TypeError, bitstream.put_byte, "gato")
        self.assertRaises(TypeError, bitstream.put_byte, 0.1)
        self.assertRaises(TypeError, bitstream.put_byte, [1,'a',3])
        self.assertRaises(TypeError, bitstream.put_byte, object())
                
    def test_put_byte_negative(self):
        """
        Test that put_byte raises an exception when passed negative integer   
        values as its argument.
        """
        bitstream = BitStream()
        val = random.randint(-2**8+1,-1)
        self.assertRaises(ValueError, bitstream.put_byte, val)
    
    def test_put_byte_to_big(self):
        """
        Test that put_byte raises an exception when passed any integer value 
        > 255 as its argument.
        """
        bitstream = BitStream()
        self.assertRaises(ValueError, bitstream.put_byte, 256)
        val = random.randint(2**8+1,2**32)
        self.assertRaises(ValueError, bitstream.put_byte, val)
    
    def test_get_byte_beyond_eos(self):
        """
        Test that trying to read beyond the end of the stream raises an 
        exception when calling get_byte(...).
        """
        bitstream = BitStream()
        
        self.assertRaises(NotEnoughBitsInStreamError, bitstream.get_byte)
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),0)
        
        bitstream.put_byte(14)
        bitstream.seek(1)
        # Read a single bit beyond EOS
        self.assertRaises(NotEnoughBitsInStreamError, bitstream.get_byte)
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),1)
        
        
    
    ## =======================================================================
    ## put_string & get_string tests:
    ## =======================================================================
        
    def test_string_ascii(self):
        """
        Test basic put_string and get_string behavior, using ASCII strings.
        """
        bitstream = BitStream()
        string1 = "Test string "    # 12 chars/bytes
        string2 = "using only ASCII characters (0-126):\n\t" # 38 chars/bytes
        string3 = "Hello World!"    # 12 chars/bytes
        
        # Store our message in 3 writes
        bitstream.put_string(string1)
        bitstream.put_string(string2)
        bitstream.put_string(string3)
        
        # Sanity check:
        self.assertEquals(bitstream.get_length(),(12+38+12)*8)
        self.assertEquals(bitstream.get_current_pos(),(12+38+12)*8)
        
        # Retrieve our message in 2 reads
        bitstream.seek(0)
        self.assertEquals(bitstream.get_string(29*8),    # read 29 bytes
                          "Test string using only ASCII ")
        self.assertEquals(bitstream.get_string(33*8),    # read 33 bytes
                          "characters (0-126):\n\tHello World!")
        
    def test_string_utf8(self):
        """
        Test basic put_string and get_string support for UTF-8 strings.
        """
        bitstream = BitStream()
        string1 = "ÄäÜüß"    # 5 chars, 10 bytes
        string2 = "ЯБГДЖЙŁĄŻĘĆŃŚŹ" # 14 chars, 28 bytes
        string3 = "てすとｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃ"    # 22 chars, 66 bytes
        
        # Store our message in 3 writes
        bitstream.put_string(string1)
        bitstream.put_string(string2)
        bitstream.put_string(string3)
        
        # Sanity check:
        self.assertEquals(bitstream.get_length(),(10+28+66)*8)
        self.assertEquals(bitstream.get_current_pos(),(10+28+66)*8)
        
        # Retrieve the whole message
        bitstream.seek(0)
        self.assertEquals(bitstream.get_string(bitstream.get_length()),    
                          "ÄäÜüßЯБГДЖЙŁĄŻĘĆŃŚŹてすとｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃ")
        
    def test_string_unicode(self):
        """
        Test basic put_string and get_string support for python unicode objects.
        """
        bitstream = BitStream()
        unicode_string = u"ÄäÜüßЯБГДЖЙŁĄŻĘĆŃŚŹてすとｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃ"
        bitstream.put_string(unicode_string)
        bitstream.seek(0)
        # Note: the string is read back as a "normal" UTF-8 string, unicode
        #       type information is not stored in the bitstream.
        self.assertEquals(bitstream.get_string(bitstream.get_length()),    
                          "ÄäÜüßЯБГДЖЙŁĄŻĘĆŃŚŹてすとｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃ")
                          
    def test_string_character_zero(self):
        """
        Test that we are handling character zero ('\\0') correctly.
        """
        bitstream = BitStream()
        bitstream.put_string("Evil \0String.") # 13 chars/bytes
        self.assertEquals(bitstream.get_length(),13*8)
        bitstream.seek(0)
        self.assertEquals(bitstream.get_string(bitstream.get_length()),    
                          "Evil \0String.")
                
    def test_put_string_wrong_type(self):
        """
        Test that put_string raises an exception when passed non string values 
        as its argument.
        """
        bitstream = BitStream()
        self.assertRaises(TypeError, bitstream.put_string, 23234)
        self.assertRaises(TypeError, bitstream.put_string, 0.1)
        self.assertRaises(TypeError, bitstream.put_string, [1,'a',3])
        self.assertRaises(TypeError, bitstream.put_string, object())
        
    def test_get_string_non_bytable_size(self):
        """
        Test that calling get_string with a bit_length that is not a multiple 
        of 8 raises an exception.
        That is, we cannot read partial bytes as string data.
        """
        bitstream = BitStream()
        bitstream.put_string("Hello World!")
        bitstream.seek(0)
        
        self.assertRaises(ValueError, bitstream.get_string, 18)
        
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),0)
    
    def test_get_string_utf8_read_partial_characters(self):
        """
        Test that it is possible to read "partial" utf-8 characters from the 
        bitstream and that concatenation restores the full character/glyph.
        """
        bitstream = BitStream()
        string = "てすとｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃ" # 22 chars, 66 bytes
        bitstream.put_string(string)
        bitstream.seek(0)
        
        # First read 32 bytes
        readString = bitstream.get_string(32*8)
        self.assertEquals(readString,"てすとｱｲｳｴｵｶｷ\xef\xbd") 
        # Now read the rest
        readString += bitstream.get_string(34*8)
        self.assertEquals(readString,"てすとｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃ") 
    
    def test_get_string_beyond_eos(self):
        """
        Test that trying to read beyond the end of the stream raises an 
        exception when calling get_string(...).
        """
        bitstream = BitStream()
        
        self.assertRaises(NotEnoughBitsInStreamError, bitstream.get_string, 1)
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),0)
        
        bitstream.put_string("Hello World!")    # 12 chars/bytes
        bitstream.seek(0)
        # Read beyond EOS
        self.assertRaises(NotEnoughBitsInStreamError, bitstream.get_string, 
                          13*8)
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),0)
        
    def test_get_string_zero_bits(self):
        """
        Test that reading zero bits from the stream as a string results in  
        getting the empty string: \"\".
        """
        bitstream = BitStream()
        self.assertEquals(bitstream.get_string(0), "")
        
        # Store a string in the stream.
        bitstream.put_string("Hello World!")
        
        bitstream.seek(0)
        self.assertEquals(bitstream.get_string(0), "")
        
    
    ## =======================================================================
    ## put_bit_dump_string & get_bit_dump_string:
    ## =======================================================================

    def test_bit_dump_string_basic(self):
        """
        This method tests put_bit_dump_string's and get_bit_dump_string's 
        basic functionality.
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
                
    def test_put_bit_dump_string_wrong_type(self):
        """
        Test that put_bit_dump_string raises an exception when passed non 
        string values as its argument.
        """
        bitstream = BitStream()
        self.assertRaises(TypeError, bitstream.put_bit_dump_string, 23234)
        self.assertRaises(TypeError, bitstream.put_bit_dump_string, 0.1)
        self.assertRaises(TypeError, bitstream.put_bit_dump_string, object())
                
    def test_put_bit_dump_string_invalid_format(self):
        """
        Test that put_bit_dump_string raises an exception when passed any 
        string not of the form ('0'|'1')*
        """
        bitstream = BitStream()
        
        # Try some fixed examples
        self.assertRaises(ValueError, bitstream.put_bit_dump_string, "23234")
        self.assertRaises(ValueError, bitstream.put_bit_dump_string, "Hello")
        self.assertRaises(ValueError, bitstream.put_bit_dump_string, "0101 0")
        self.assertRaises(ValueError, bitstream.put_bit_dump_string, "ｹｺｻｼｽ")
        
        # Generate a random string conforming to ('0'|'1')* except for one 
        # (ascii) character.
        num_bits = 50
        pos_wrong_char = random.randint(1,48)
        r_invalid_bit_string = ""
        
        for i in range(0,pos_wrong_char):
            r_invalid_bit_string += random.choice(('0','1'))
            
        r_invalid_bit_string += \
            random.choice(string.letters + "23456789_-/\\" + string.whitespace)
            
        for i in range(0,num_bits - pos_wrong_char - 1):
            r_invalid_bit_string += random.choice(('0','1'))
        
        # Try the randomly generated example
        self.assertRaises(ValueError, bitstream.put_bit_dump_string, 
                          r_invalid_bit_string)
                          
        # Calls that throw exceptions should not alter the contents or position 
        # of the bitstream:
        self.assertEquals(bitstream.get_length(),0)
        self.assertEquals(bitstream.get_current_pos(),0) 
    
    def test_get_bit_dump_string_beyond_eos(self):
        """
        Test that trying to read beyond the end of the stream raises an 
        exception when calling get_bit_dump_string(...).
        """
        bitstream = BitStream()
        
        self.assertRaises(NotEnoughBitsInStreamError, 
                          bitstream.get_bit_dump_string, 1)
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),0)
        
        bitstream.put_bit_dump_string("0001110101") # 10 bits
        bitstream.seek(0)
        # Read beyond EOS
        self.assertRaises(NotEnoughBitsInStreamError, 
                          bitstream.get_bit_dump_string, 11)
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),0)
        
    def test_get_bit_dump_string_zero_bits(self):
        """
        Test that reading zero bits from the stream as a bit dump string 
        results in getting the empty string: \"\".
        """
        bitstream = BitStream()
        self.assertEquals(bitstream.get_bit_dump_string(0), "")
        
        # Store some bits in the stream.
        bitstream.put_bit_dump_string("0001110101") # 10 bits
        
        bitstream.seek(0)
        self.assertEquals(bitstream.get_bit_dump_string(0), "")
        
    
    ## =======================================================================
    ## put_hex & get_hex:
    ## =======================================================================

    def test_hex_basic(self):
        """
        This method tests put_hex's and get_hex's basic functionality.
        """
        bitstream = BitStream()
        
        # Generate a random string of hex digits, ie: ('0'-'9'|'a'-'f'|'A'-'F')*
        valid_hex_digits = "0123456789abcdefABCDEF"
        num_digits = 50        
        digits = ""
        for i in range(0,num_digits):
            digits += random.choice(valid_hex_digits)
            
        # Put those digits in the BitStream...
        bitstream.put_hex(digits)
        
        # ...and get them back
        bitstream.seek(0)
        read_digits = bitstream.get_hex(len(digits)*4) # 1 hex digit == 4 bits
        
        # Check that the hexadecimal digits were recovered correctly
        # Note that case information may be lost. Comparison must be case 
        # insensitive (ie. 'a9Bc' and 'A9bC' are equal)
        self.assertEqual(read_digits.lower(), digits.lower())
                
    def test_put_hex_wrong_type(self):
        """
        Test that put_hex raises an exception when passed non string values as 
        its argument.
        """
        bitstream = BitStream()
        self.assertRaises(TypeError, bitstream.put_hex, 23234)
        self.assertRaises(TypeError, bitstream.put_hex, 0.1)
        self.assertRaises(TypeError, bitstream.put_hex, object())
                
    def test_put_hex_invalid_format(self):
        """
        Test that put_hex raises an exception when passed any string not of the 
        form ('0'-'9'|'a'-'f'|'A'-'F')*
        """
        bitstream = BitStream()
        
        # Try some fixed examples
        self.assertRaises(ValueError, bitstream.put_hex, "aF92G2")
        self.assertRaises(ValueError, bitstream.put_hex, "Hello")
        self.assertRaises(ValueError, bitstream.put_hex, "3354 F")
        self.assertRaises(ValueError, bitstream.put_hex, "ｹｺｻｼｽ")
        
        # Generate a random string conforming to ('0'-'9'|'a'-'f'|'A'-'F')* 
        # except for one (ascii) character.
        valid_hex_digits = "0123456789abcdefABCDEF"
        num_digits = 50
        pos_wrong_char = random.randint(1,48)
        r_invalid_hex_string = ""
        
        for i in range(0,pos_wrong_char):
            r_invalid_hex_string += random.choice(valid_hex_digits)
        
        non_hex_char = "0"
        while(non_hex_char in valid_hex_digits): 
            non_hex_char = \
               random.choice(string.letters + string.digits + string.whitespace)
        
        r_invalid_hex_string += non_hex_char
            
        for i in range(0,num_digits - pos_wrong_char - 1):
            r_invalid_hex_string += random.choice(valid_hex_digits)
        
        # Try the randomly generated example
        self.assertRaises(ValueError, bitstream.put_hex, r_invalid_hex_string)
                          
        # Calls that throw exceptions should not alter the contents or position 
        # of the bitstream:
        self.assertEquals(bitstream.get_length(),0)
        self.assertEquals(bitstream.get_current_pos(),0)
        
    def test_get_hex_invalid_length(self):
        """
        Test that trying to read a number of bits that is not a multiple of 4 
        as hex data raises an exception.
        """
        bitstream = BitStream()
        bitstream.put_hex("DfF7CE69fF5478A") # 15 digits, 60 bits
        bitstream.seek(0)
        self.assertRaises(ValueError, 
                          bitstream.get_hex, 47) # read 11.75 hex digits?
    
    def test_get_hex_beyond_eos(self):
        """
        Test that trying to read beyond the end of the stream raises an 
        exception when calling get_hex(...).
        """
        bitstream = BitStream()
        
        self.assertRaises(NotEnoughBitsInStreamError, 
                          bitstream.get_hex, 1)
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),0)
        
        bitstream.put_hex("DfF7CE69fF5478A") # 15 digits, 60 bits
        bitstream.seek(0)
        # Read beyond EOS
        self.assertRaises(NotEnoughBitsInStreamError, 
                          bitstream.get_hex, 61)
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),0)
        
    def test_get_hex_zero_bits(self):
        """
        Test that reading zero bits from the stream as hex data results in 
        getting the empty string: \"\".
        """
        bitstream = BitStream()
        self.assertEquals(bitstream.get_hex(0), "")
        
        # Store some hex data in the stream.
        bitstream.put_hex("DfF7CE69fF5478A") # 15 digits, 60 bits
        
        bitstream.seek(0)
        self.assertEquals(bitstream.get_hex(0), "")
        
    
    ## =======================================================================
    ## put_base64 & get_base64:
    ## =======================================================================

    def test_base64_basic(self):
        """
        This method tests put_base64's and get_base64's basic functionality.
        """
        bitstream = BitStream()
        
        # We use the Base64 Test Vectors defined in RFC4648.
        # http://www.ietf.org/rfc/rfc4648.txt
        test_vectors = [("",""),
                        ("f","Zg=="),
                        ("fo","Zm8="),
                        ("foo","Zm9v"),
                        ("foob","Zm9vYg=="),
                        ("fooba","Zm9vYmE="),
                        ("foobar","Zm9vYmFy")]
        
        # STEP 1:
        # For each test vector, we write its value to the bitstream as a string 
        # then read it as base64 data.
        for (str_val, base64_val) in test_vectors:
            vector_bit_length = len(str_val)*8
            bitstream.put_string(str_val)
            bitstream.seek(0)
            self.assertEquals(bitstream.get_base64(vector_bit_length),
                              base64_val)
            bitstream.seek(0)
            
        # NOTE that we are overwriting multiple times our bitstream, this is 
        # also a feature of BitStream we are testing in this test case.
        
        # STEP 2:
        # For each test vector, we write its value to the bitstream as base64  
        # data, then read it as string *and* base64 data.
        for (str_val, base64_val) in test_vectors:
            vector_bit_length = len(str_val)*8
            bitstream.put_base64(base64_val)
            bitstream.seek(0)
            self.assertEquals(bitstream.get_string(vector_bit_length),
                              str_val)
            bitstream.seek(0)
            self.assertEquals(bitstream.get_base64(vector_bit_length),
                              base64_val)
            bitstream.seek(0)
        
        # STEP 3:
        # For each test vector, we write its value to a NEW bitstream as base64  
        # data, and make sure the length of the stream is the expected one.
        for (str_val, base64_val) in test_vectors:
            vector_bit_length = len(str_val)*8
            new_bs = BitStream()
            new_bs.put_base64(base64_val)
            self.assertEquals(new_bs.get_length(), vector_bit_length)
            self.assertEquals(new_bs.get_current_pos(), vector_bit_length)
                
    def test_put_base64_wrong_type(self):
        """
        Test that put_base64 raises an exception when passed non string values 
        as its argument.
        """
        bitstream = BitStream()
        self.assertRaises(TypeError, bitstream.put_base64, 23234)
        self.assertRaises(TypeError, bitstream.put_base64, 0.1)
        self.assertRaises(TypeError, bitstream.put_base64, object())
                
    def test_put_base64_invalid_format(self):
        """
        Test that put_base64 raises an exception when passed invalid base64 
        data strings.
        """
        bitstream = BitStream()
        
        # Try some fixed examples.
        # Random examples are harder to generate for base64 than for hex or 
        # binary.
        # Also, base64 has a few interesting invalid cases that are hard to 
        # hit at random.
        self.assertRaises(ValueError, bitstream.put_base64, "3354 F")
        self.assertRaises(ValueError, bitstream.put_base64, "ｹｺｻｼｽ")
        self.assertRaises(ValueError, bitstream.put_base64, "Zm9ñYmE=")
        self.assertRaises(ValueError, bitstream.put_base64, "Zm9vYm=E")
        self.assertRaises(ValueError, bitstream.put_base64, "e==")
        self.assertRaises(ValueError, bitstream.put_base64, "a=")
        self.assertRaises(ValueError, bitstream.put_base64, "Zm9==")
        self.assertRaises(ValueError, bitstream.put_base64, "Zm9")
        self.assertRaises(ValueError, bitstream.put_base64, "Zm=")
        self.assertRaises(ValueError, bitstream.put_base64, "Zm")
        self.assertRaises(ValueError, bitstream.put_base64, "Zm9vYg=")
        self.assertRaises(ValueError, bitstream.put_base64, "==")
        
    def test_get_base64_invalid_length(self):
        """
        Test that trying to read a number of bits that is not a multiple of 8 
        as base64 data raises an exception.
        """
        bitstream = BitStream()
        bitstream.put_base64("Zm9vYmE=") # 40 bits
        bitstream.seek(0)
        self.assertRaises(ValueError, 
                          bitstream.get_base64, 26) # read 3.25 bytes?
    
    def test_get_base64_beyond_eos(self):
        """
        Test that trying to read beyond the end of the stream raises an 
        exception when calling get_base64(...).
        """
        bitstream = BitStream()
        
        self.assertRaises(NotEnoughBitsInStreamError, 
                          bitstream.get_base64, 8)
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),0)
        
        bitstream.put_base64("Zm9vYmE=") # 40 bits
        bitstream.seek(0)
        # Read beyond EOS
        self.assertRaises(NotEnoughBitsInStreamError, 
                          bitstream.get_base64, 48)
        # Current position should not have been changed
        self.assertEquals(bitstream.get_current_pos(),0)
        
    def test_get_base64_zero_bits(self):
        """
        Test that reading zero bits from the stream as base64 data results in 
        getting the empty string: \"\".
        """
        bitstream = BitStream()
        self.assertEquals(bitstream.get_base64(0), "")
        
        # Store some base64 data in the stream.
        bitstream.put_base64("Zm9vYmE=") # 40 bits
        
        bitstream.seek(0)
        self.assertEquals(bitstream.get_base64(0), "")
        
    
    ## =======================================================================
    ## put_bitstream_copy:
    ## =======================================================================
        
    def test_put_bitstream_copy(self):
        """
        Test the basic functionality of the put_bitstream_copy method.
        """
        bitstream1 = BitStream()
        bitstream1.put_string("This is bitstream1")
        bitstream2 = BitStream()
        bitstream2.put_string("This is bitstream2")
        bitstream3 = BitStream()
        # bitstream3 remains empty
        bitstream4 = BitStream()
        bitstream4.put_string("This is bitstream4")
        
        # copy the full contents of bitstream2 to the end of bitstream1
        bitstream2.seek(0)
        bitstream1.put_bitstream_copy(bitstream2)
        self.assertEquals(bitstream2.get_current_pos(), bitstream2.get_length())
        
        # check the contents of bitstream1
        bitstream1.seek(0)
        self.assertEquals(bitstream1.get_string(bitstream1.get_length()),
                          "This is bitstream1This is bitstream2")
                          
        # copy the full contents of bitstream3 (aka. nothing) to the end of 
        # bitstream4
        bitstream3.seek(0)
        bitstream4.put_bitstream_copy(bitstream3)
        
        # check the contents of bitstream4
        bitstream4.seek(0)
        self.assertEquals(bitstream4.get_string(bitstream4.get_length()),
                          "This is bitstream4")
                          
        # copy the contents of bitstream4 from the position 8 onwards
        bitstream4.seek(8*8)
        bitstream1.put_bitstream_copy(bitstream4)
        self.assertEquals(bitstream4.get_current_pos(), bitstream4.get_length())
        
        # check the contents of bitstream1
        bitstream1.seek(0)
        self.assertEquals(bitstream1.get_string(bitstream1.get_length()),
                          "This is bitstream1This is bitstream2bitstream4")
        
            
    def test_put_bitstream_copy_self(self):
        """
        Test using the put_bitstream_copy method with the same BitStream object 
        as origin and destination.
        """
        bitstream = BitStream()
        
        # Generate a random string of bits, ie: ('0' | '1')*
        num_bits = 50        
        bits = ""
        for i in range(0,num_bits):
            bits += random.choice(('0','1')) # inefficient, but ok for a test.
            
        # Put those bits in the BitStream...
        bitstream.put_bit_dump_string(bits)
        
        # ... copy the bitstream into itself at any point:
        bitstream.seek(random.randint(0,50))
        bitstream.put_bitstream_copy(bitstream)
        
        # Check that the bitstream was unchanged by the previous operation:
        # (overwriting data with the same data is the same as doing nothing,
        # except that the current position is changed to the end of the stream)
        self.assertEquals(bitstream.get_length(),num_bits)
        self.assertEquals(bitstream.get_current_pos(),num_bits)
        bitstream.seek(0)
        read_bits = bitstream.get_bit_dump_string(bitstream.get_length())
        self.assertEqual(read_bits, bits)
        
    
    ## =======================================================================
    ## Other BitStream tests:
    ## =======================================================================
    
    def test_multiformat_write_multiformat_read(self):
        """
        This test writes numeric, byte and string data to a stream and then 
        reads the whole stream as binary, hex and base64 data, ensuring that 
        the output is the expected one in each case. 
        """
        # Write a number, 2 bytes and a string
        bitstream = BitStream()
        bitstream.put_num(10438341575639894917, 64)
        bitstream.put_byte(230)
        bitstream.put_byte(191)
        bitstream.put_string("ÄäÜüßTestЯБГДЖЙŁĄŻStringĘĆŃŚŹてす" \
                                 "とｱｲｳｴｵｶｷｸ4234ｹｺｻｼｽｾｿﾀﾁﾂﾃ")
        
        # Read in binary, hex and base64 formats
        expected_bits = \
            "1001000011011100011100000101101110111100001101010000101110000101" \
            "1110011010111111110000111000010011000011101001001100001110011100" \
            "1100001110111100110000111001111101010100011001010111001101110100" \
            "1101000010101111110100001001000111010000100100111101000010010100" \
            "1101000010010110110100001001100111000101100000011100010010000100" \
            "1100010110111011010100110111010001110010011010010110111001100111" \
            "1100010010011000110001001000011011000101100000111100010110011010" \
            "1100010110111001111000111000000110100110111000111000000110011001" \
            "1110001110000001101010001110111110111101101100011110111110111101" \
            "1011001011101111101111011011001111101111101111011011010011101111" \
            "1011110110110101111011111011110110110110111011111011110110110111" \
            "1110111110111101101110000011010000110010001100110011010011101111" \
            "1011110110111001111011111011110110111010111011111011110110111011" \
            "1110111110111101101111001110111110111101101111011110111110111101" \
            "1011111011101111101111011011111111101111101111101000000011101111" \
            "1011111010000001111011111011111010000010111011111011111010000011"
        expected_hex = \
            "90dc705bbc350b85e6bfc384c3a4c39cc3bcc39f54657374d0afd091d093d094" \
            "d096d099c581c484c5bb537472696e67c498c486c583c59ac5b9e381a6e38199" \
            "e381a8efbdb1efbdb2efbdb3efbdb4efbdb5efbdb6efbdb7efbdb834323334ef" \
            "bdb9efbdbaefbdbbefbdbcefbdbdefbdbeefbdbfefbe80efbe81efbe82efbe83"
        expected_base64 = \
            "kNxwW7w1C4Xmv8OEw6TDnMO8w59UZXN00K/QkdCT0JTQltCZxYHEhMW7U3RyaW5n" \
            "xJjEhsWDxZrFueOBpuOBmeOBqO+9se+9su+9s++9tO+9te+9tu+9t++9uDQyMzTv" \
            "vbnvvbrvvbvvvbzvvb3vvb7vvb/vvoDvvoHvvoLvvoM="
            
        bitstream.seek(0)
        self.assertEquals( \
                    bitstream.get_bit_dump_string(bitstream.get_length()),
                    expected_bits)
        bitstream.seek(0)
        self.assertEquals(bitstream.get_hex(bitstream.get_length()).lower(),
                          expected_hex)
        bitstream.seek(0)
        self.assertEquals(bitstream.get_base64(bitstream.get_length()),
                          expected_base64)
    
    def test_stress(self):
        """
        Stress test BitStream by writings lots of numbers of different bit 
        sizes and reading them back.
        """
        # num_writes = 10000
        num_writes = 1000
        min_bit_length = 1
        max_bit_length = 8192
        
        # Generate the numbers
        nums = []
        total_bit_length = 0
        for i in range(0, num_writes):
            bit_length = random.randint(min_bit_length, max_bit_length)
            total_bit_length += bit_length
            val = random.randint(0, 2**bit_length - 1)
            nums.append({"bit_length" : bit_length, "value" : val})
            
        # Write them to a BitStream object
        bitstream = BitStream()
        for num in nums:
            bitstream.put_num(num["value"], num["bit_length"])
            
        # Check the BitStream length and current position
        self.assertEquals(bitstream.get_length(),total_bit_length)
        self.assertEquals(bitstream.get_current_pos(),total_bit_length)
        
        # Read all numbers back
        bitstream.seek(0)
        for num in nums:
            self.assertEquals(bitstream.get_num(num["bit_length"]),num["value"])
        
        
    ## =======================================================================
    ## Test exception classes:
    ## =======================================================================
    
    def test_bitstream_dot_py_exceptions(self):
        """
        Test that all exceptions declared in BitStream.py can be constructed, 
        raised and queried for an exception message.
        """
        # This test is here mostly for the sake of code coverage
        
        message = "My message: ñ(&(%%9_\n\t"
        for ExceptionCls in (NotEnoughBitsInStreamError, SeekOutOfRangeError):
        
            was_raised = False
            
            try:
                raise ExceptionCls(message)
            except ExceptionCls, e:
                was_raised = True
                self.assertEqual(str(e), message)
                
            self.assertEqual(was_raised, True)
     

if __name__ == '__main__':
    unittest.main()
