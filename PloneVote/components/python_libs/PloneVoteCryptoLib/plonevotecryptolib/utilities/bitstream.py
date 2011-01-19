_CELL_SIZE = 32

class BitStream:
	"""
	"""
	
	def current_poss(self):
		"""
		"""
		return self._current_cell*self._cell_size + self._current_cell_bit
	
	def __init__(self):
		"""
		"""
		self._cell_size = _CELL_SIZE
		self._cell_max = 2**self._cell_size
		self._cells = []
		self._current_cell = 0
		self._current_cell_bit = 0
	
	def seek(self, bit):
		"""
		"""
		pass
	
	def put_num(self, num, bit_length):
		"""
		"""
		pass
	
	def get_num(self, bit_length):
		"""
		"""
		pass
	
	def put_byte(self, byte):
		"""
		"""
		pass
	
	def get_byte(self):
		"""
		"""
		pass
	
	def put_string(self, string):
		"""
		"""
		pass
	
	def get_string(self, bit_length):
		"""
		"""
		pass
		
	
	
