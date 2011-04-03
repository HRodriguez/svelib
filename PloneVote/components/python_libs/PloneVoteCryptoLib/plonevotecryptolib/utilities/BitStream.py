# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  BitStream.py : A class representing a sequence of bits
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

__all__ = ["BitStream", "NotEnoughBitsInStreamError"]

_CELL_SIZE = 32

# The mapping from six bit binary number to character in a safe Base64 encoding 
# The encoding uses the same characters as in RFC3548.
_base64_encoding_table = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', \
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', \
	'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', \
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', \
	'3', '4', '5', '6', '7', '8', '9', '+', '/']

_base64_decoding_table = {}
for i in range(0,64):
	_base64_decoding_table[_base64_encoding_table[i]] = i


class NotEnoughBitsInStreamError(Exception):
	"""
	An exception raised whenever the user requests more bits from a BitStream 
	(via get_num, get_string, get_byte, etc) than the number of bits left in 
	the stream from the current position to its end.
	"""
	
	def __str__(self):
		return self.msg
	
	def __init__(self, msg):
		"""
		Constructs a new NotEnoughBitsInStreamError
		"""
		self.msg = msg

class BitStream:
	"""
	A class representing a sequence of bits
	
	Data can be added to the bitstream as integers of any given bit size and 
	retrieved as well n-bits at a time as n bit integers. Convenience methods 
	are provided to add and encode arbitrary strings and base64 data into the 
	bitstream and retrieve that data in either encoding.
	
	The seek(bit) method is used to change position within the stream. Note 
	that adding data at the middle of an already created stream will overwrite 
	existing bits, not insert the data.
	"""
	
	def get_length(self):
		"""
		Get the full length of the bitstream in bits
		"""
		return (len(self._cells) - 1)*self._cell_size + self._last_cell_last_bit
	
	def get_current_pos(self):
		"""
		Return the current bit within the bitstream.
		
		Any get_X method will begin reading the stream from the bit 
		returned by this method.
		"""
		return self._current_cell*self._cell_size + self._current_cell_bit
	
	def __init__(self):
		"""
		Construct a new bitstream
		"""
		self._cell_size = _CELL_SIZE
		self._cell_max = 2**self._cell_size	# each cell can store integers in [0, self._cell_max)
		self._cells = [0]
		self._current_cell = 0	# cell including the current position
		self._current_cell_bit = 0	# current bit position within the current cell
		self._last_cell_last_bit = 0 # last used bit in the last cell
	
	def seek(self, pos):
		"""
		Move to the desired position within the stream.
		
		Arguments:
			pos::int	-- The position to which we wish to seek in the stream.
						   (given in bits)
		"""
		if(pos > self.get_length()):
			raise IndexError("Seeking after the bitstream's end is not " \
							 "permitted.")
		
		self._current_cell = pos / self._cell_size
		self._current_cell_bit = pos % self._cell_size
		
		assert self._current_cell < len(self._cells), "Cannot seek beyond end of stream."
		
	def _update_length(self):
		"""
		Check if the current position has moved past the length of the stream 
		and update the length accordingly.
		"""
		if((self._current_cell == (len(self._cells) - 1)) and 
			(self._current_cell_bit > self._last_cell_last_bit)):
			self._last_cell_last_bit = self._current_cell_bit
			
	def _insert_in_cell(self, num, cell_num, start_bit, end_bit):
		"""
		Insert num at the cell_num cell, between the bits start_bit and end_bit 
		from right to left.
		"""
		# Be very careful with off-by-one errors if modifying this code.
		assert num < 2**(end_bit - start_bit + 1), "The number does not fit in the given cell fragment."
		
		clear_mask = (self._cell_max - 1)	# 111111111111111
		clear_mask ^= (2**(self._cell_size - start_bit) - 1)	# 111110000000000 if start_bit=6 
		clear_mask |= (2**(self._cell_size - end_bit - 1) - 1)			# 111110000011111 if end_bit=10
		
		# Clear the desired space in the cell
		self._cells[cell_num] = (self._cells[cell_num] & clear_mask) % self._cell_max
		
		# Now insert num into the cleared space
		num = num << (self._cell_size - end_bit - 1)
		self._cells[cell_num] = (self._cells[cell_num] | num) % self._cell_max
	
	def put_num(self, num, bit_length):
		"""
		Append the given integer (bit_length)-bits representation to the stream.
		
		Arguments:
			num::(int|long)	-- The number we wish to append to the bitstream.
			bit_length::int	-- The number of bits we wish to use to represent 
							   num before adding it to the stream.
		"""
		limit_num_size = 2**bit_length
		if(num >= limit_num_size):
			raise ValueError("The given integer (%d) is not representable as " \
							 "a %d bits long binary sequence." % \
							 (num, bit_length))
		
		current_cell_space_left = self._cell_size - self._current_cell_bit
		
		# If the number fits in the current cell, we put it there and are done:
		if(bit_length <= current_cell_space_left):
			start_bit = self._current_cell_bit
			end_bit = self._current_cell_bit + bit_length - 1
			self._insert_in_cell(num, self._current_cell, start_bit, end_bit)
			self._current_cell_bit += bit_length
			
			# Update length if needed
			self._update_length()
				
			return
		
		# If the number is larger than the current space left in the cell
		# lets fill the current cell first:
		leading_unaligned_bits = num >> (bit_length - current_cell_space_left)
		start_bit = self._current_cell_bit
		end_bit = self._cell_size - 1
		self._insert_in_cell(leading_unaligned_bits, self._current_cell, 
							 start_bit, end_bit)
		
		# Now lets fill all aligned cells:
		remaining_bit_length = bit_length - current_cell_space_left
		full_cells = remaining_bit_length / self._cell_size
		
		# Remove unaligned trailing bits to ease calculations
		# Remember to store them in order to append them at the end
		trailing_bit_length = remaining_bit_length % self._cell_size
		trailing_bits = num % 2**(trailing_bit_length)
		num = num >> trailing_bit_length
		
		# Add extra cells if needed
		while(len(self._cells) <= self._current_cell + full_cells):
			self._cells.append(0)
			self._last_cell_last_bit = 0
		
		# Write full cells
		for c in range(1, full_cells + 1):
			# displace and take the last _cell_size bits 
			# (displacement goes from full_cells - 1 to 0 in cells.)
			displacement = self._cell_size * (full_cells - c)
			cell_bits = (num >> displacement) % self._cell_max
			self._cells[self._current_cell + c] = cell_bits
		
		# Update the current cell
		self._current_cell += (full_cells + 1)
		if(self._current_cell >= len(self._cells)): # == should be enough
			self._cells.append(0)
			self._last_cell_last_bit = 0
		
		# Append the trailing unaligned bits
		if(trailing_bit_length > 0):
			start_bit = 0
			end_bit = trailing_bit_length - 1
			self._insert_in_cell(trailing_bits, self._current_cell, 
								 start_bit, end_bit)
			self._current_cell_bit = trailing_bit_length
		
		# Check whether the length of the stream must also be updated
		self._update_length()
		
	
	def get_num(self, bit_length):
		"""
		Retrieve the next bit_length bits of the stream as a number.
		
		Arguments:
			bit_length::int	-- The number of bits we wish to pull from the 
							   stream.
		
		Returns:
			num::(int|long)	-- The number represented by the pulled bits, 
							   interpreted as a binary sequence.
		"""
		if(bit_length > self.get_length() - self.get_current_pos()):
			raise NotEnoughBitsInStreamError("Not enough bits in the bitstream.")
		
		limit_num_size = 2**bit_length
		num = 0
		bits = bit_length
		
		# Are there enough bits in the current cell to satisfy the request?
		bits_left_in_current_cell = self._cell_size - self._current_cell_bit
		if(bits <= bits_left_in_current_cell):
			displacement = bits_left_in_current_cell - bits
			num = (self._cells[self._current_cell] >> displacement) % limit_num_size
			self._current_cell_bit +=  bits
			return num
		
		# If not, pull out all remaining bits from the current cell and advance 
		# the position
		num += (self._cells[self._current_cell] % 2**bits_left_in_current_cell)
		bits -= bits_left_in_current_cell
		self._current_cell += 1
		self._current_cell_bit = 0
		
		# Now copy aligned cells
		while(bits >= self._cell_size):
			num = (num << self._cell_size) | self._cells[self._current_cell]
			bits -= self._cell_size
			self._current_cell += 1
			
		# Finally add the trailing bits from the last cell
		if(bits > 0):
			displacement = self._cell_size - bits
			trailing_bits = (self._cells[self._current_cell] >> displacement) % 2**bits
			num = (num << bits) | trailing_bits
			self._current_cell_bit = bits
		
		return num
		
	
	def put_byte(self, byte):
		"""
		Put the given byte in the stream.
		
		If the current position points to the end of the stream, the byte 
		will be appended, otherwise it will overwrite existing data, starting 
		from the current position.
		"""
		self.put_num(byte, 8)
	
	def get_byte(self):
		"""
		Get the next byte from the stream.
		"""
		return self.get_num(8)
	
	def put_string(self, string):
		"""
		Put the given string into the bitstream, this will automatically encode 
		the string. This works for ascii/UTF-8 python strings, not unicode 
		strings.
		
		If the current position points to the end of the stream, the string 
		will be appended, otherwise it will overwrite existing data, starting 
		from the current position.
		"""
		for char in string:
			self.put_byte(ord(char))
			
	def get_string(self, bit_length):
		"""
		Retrieve the next bit_length bits from the stream as a string.
		
		This will retrieve the next bit_length bits from the stream, 
		interpreting them as a string in local python encoding. The main use of 
		this method is to recover strings added to the stream with put_string. 
		Note that the length of string to recover must be given in bits, not 
		characters, and that python strings may include characters that are 
		represented by a variable number of bits (ie. 1 or 2 byte chars).
		"""
		if(bit_length > self.get_length() - self.get_current_pos()):
			raise NotEnoughBitsInStreamError("Not enough bits in the bitstream.")
		
		if(bit_length % 8 != 0):
			raise ValueError("Valid string data must have a length that is " \
							 "multiple of 8 bits, since characters are made  " \
							 "from one or more bytes.")
		
		s = ""
		bytes = bit_length / 8
		for b in range(0, bytes):
			s += chr(self.get_byte())
		
		return s
	
	def put_base64(self, base64_data):
		"""
		Put the given base64 encoded data into the BitStream.
		
		The format of the base64 encoded data should match that defined by 
		RFC3548, including padding characters ("=") which are used subtract 
		padding bits from the base64 representation as indicated in that RFC.
		
		Please note that base64 data must always contain a multiple of eight 
		bits (that is, must be byte aligned). This is because the padding 
		scheme of RFC3548 assumes data organized in bytes as the input to any 
		base64 encoder.
		
		Arguments:
			base64_data::string	-- Arbitrary binary data encode in base64.
		"""
		length = len(base64_data) * 6
		# Remove padding:
		if(base64_data[-1] == "="):
			if(base64_data[-2] == "="):
				# Remove two BYTES of padding
				length -= 16
			else:
				# Remove one BYTE of padding
				length -= 8
		
		# Check resulting length (ie. to guard against things like "a==")
		if(length < 0):
			raise ValueError("The given string is not valid base64 encoded " \
							  "data.")
		if(length % 8 != 0):
			raise ValueError("The given string is not valid base64 encoded " \
							  "data: base64 encoded data must be a multiple " \
							  "of eight bits in length before encoding. The " \
							  "given data would be %d bits long once decoded " \
							  "from base64")
		
		# Decode and insert a character at a time.
		# (This is likely seriously inefficient, but early optimization is the 
		# O(sqrt(n)) of all evil, so lets not get bitshifty here unless we need 
		# to)
		bit_pos = 0	# The current bit position in the base64 data
		while(bit_pos < length):
			c = base64_data[bit_pos / 6]
			try:
				val = _base64_decoding_table[c]
			except KeyError:
				raise ValueError("The given string is not valid base64 " \
							  "encoded data. Character \'%s\' is not a valid " \
							  "base64 code point" % c)
				
			if(length - bit_pos >= 6):
				# Copy whole character
				self.put_num(val, 6)
			else:
				# Part of that character is 0's padding, copy only the 
				# non-padding part of the character.
				padding_bits = (bit_pos + 6) - length
				assert 0 < padding_bits, "padding_bits should never be negative"
				val = val >> padding_bits
				self.put_num(val, 6 - padding_bits)
			
			bit_pos += 6
	
	def get_base64(self, bit_length):
		"""
		Retrieve the given amount of data from the BitStream, encoded in base64.
		
		The format of the base64 encoded data matches that defined by RFC3548.
		This includes padding characters ("=") if the requested amount of bits 
		of data is not a multiple of 24.
		
		Arguments:
			bit_length::int	-- The amount of data to return as base64. Must be 
							   a multiple of 8 (byte aligned), to comply with 
							   RFC3548's specification about the input to 
							   base64 encoders.
		
		Returns:
			base64::string	-- The next bit_length bits in the stream, encoded 
							   in base64.
		"""
		if(bit_length > (self.get_length() - self.get_current_pos())):
			raise NotEnoughBitsInStreamError("Not enough bits in the bitstream.")
			
		if(bit_length % 8 != 0):
			raise ValueError("The number of bits to be retrieved as base64 " \
							  "encoded data must be a multiple of 8. This in " \
							  "order to satisfy RFC3548 and its padding " \
							  "specification, which require input to a base64 "\
							  "encoder be given in whole bytes.")
		
		base64_data = ""
		
		# Calculate needed padding, in bits
		remainder = bit_length % 24
		if(remainder == 0):
			padding_bits = 0
		else:
			padding_bits = 24 - remainder
		
		# Get all complete characters, without need for padding
		for i in range(0, bit_length / 6):
			base64_data += _base64_encoding_table[self.get_num(6)]
		
		# Get "partial character" bits
		remaining_bit_length = bit_length % 6
		if(remaining_bit_length > 0):
			val = self.get_num(remaining_bit_length)
			displacement = 6 - remaining_bit_length
			val = val << displacement
			base64_data += _base64_encoding_table[val]
			padding_bits -= displacement
		
		# Pad
		assert padding_bits % 6 == 0, "padding_bits must be a multiple of 6 " \
							  "bits in order to be translatable into base64 " \
							  "encoded characters of padding."
							  
		padding_chars = padding_bits / 6
		for i in range(0, padding_chars):
			base64_data += "="
			
		return base64_data
				

	def put_bitstream_copy(self, bitstream):
		"""
		Copy the contents of another bitstream in this at the current position.
		
		Given another bitstream, copy its contents, from its current position 
		to its end, into this one. Start writing this data at the current 
		position of this stream.
		
		Arguments:
			bitstream::BitStream  -- the bitstream from which to copy the data.
		"""
		to_copy = bitstream.get_length() - bitstream.get_current_pos()
		
		for step_size in [4096, 512, 64, 8, 1]:
			while(to_copy >= step_size):
				self.put_num(bitstream.get_num(step_size), step_size)
				to_copy -= step_size


	def put_bit_dump_string(self, bit_dump_str):
		"""
		Put the given bits into the BitStream.
		
		NOTE: This method is intended for testing and debugging and is likely 
		to be very inefficient compared to using put_byte or put_num, for 
		example.
		
		This method receives a string representing a sequence of bits 
		(ie. "0010110001") and inserts those bits into the BitStream at the 
		current position.
		
		Arguments:
			bit_dump_str::string  -- a string representing a sequence of bits.
								(must only contain the characters '0' and '1')
		"""
		# We first check that the string represents a valid sequence of bits
		for char in bit_dump_str:
			if(char not in ('0','1')):
				 raise ValueError("The string given to put_bit_dump_string " \
								"must represent a sequence of 0's and 1's. " \
								"Invalid character \'%s\' encountered while " \
								"reading from string." % char)
		
		# Only then we insert it into the bit stream, one bit at a time
		for char in bit_dump_str:
			if(char == '0'):
				self.put_num(0, 1)
			elif(char == '1'):
				self.put_num(1, 1)
			else:
				assert False, "The string should be a valid sequence of " \
							"\'0\'s and \'1\'s, since it passed the earlier " \
							"check. This line should be unreachable."
				
	
	def get_bit_dump_string(self, bit_length):
		"""
		Retrieve the given amount of data from the BitStream, as a string of 
		0's and 1's.
		
		NOTE: This method is intended for testing and debugging and is likely 
		to be very inefficient compared to using get_byte or get_num, for 
		example.
		
		Arguments:
			bit_length::int	-- The number of bits we wish to pull from the 
							   stream.
		
		Returns:
			bit_dump_str::string  -- a string representing a sequence of bits.
								(must only contain the characters '0' and '1')
								This should be the next bit_length bits stored 
								in the BitStream from the current position.
		"""
		if(bit_length > (self.get_length() - self.get_current_pos())):
			raise NotEnoughBitsInStreamError("Not enough bits in the bitstream.")
		
		# Read bit by bit and construct the string.
		bit_dump_str = ""
		for i in range(0, bit_length):
			bit = self.get_num(1)
			if(bit == 0):
				bit_dump_str += "0"
			elif(bit == 1):
				bit_dump_str += "1"
			else:
				assert False, "A 1-bit long number must be 0 or 1. " \
							"This line should be unreachable."
		
		return bit_dump_str
