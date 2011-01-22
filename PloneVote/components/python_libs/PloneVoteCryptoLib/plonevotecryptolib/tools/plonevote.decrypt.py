# -*- coding: utf-8 -*-
#
#  plonevote.decrypt.py : A tool to decrypt a file using PloneVoteCryptoLib.
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

import sys
import getopt

from plonevotecryptolib.PrivateKey import PrivateKey
from plonevotecryptolib.Ciphertext import Ciphertext
from plonevotecryptolib.utilities.BitStream import BitStream
from plonevotecryptolib.PVCExceptions import *

def print_usage():
	"""
	Prints the tool's usage message
	"""
	print """USAGE:
		  
		  plonevote.decrypt.py --key=private_key.pvprivkey --in=file.pvencrypted --out=file.ext
		  
		  plonevote.decrypt.py (--help|-h)
		  
		  Arguments can be given in any order. All arguments are mandatory.
		  	
		  	--key=private_key.pvprivkey  : The file containing the private key used for decryption.
		  	
		  	--in=file.pvencrypted	: The source (input) encrypted file to decrypt.
		  	
		  	--out=file.ext	: The destination (output) file that will contain the decrypted (original plaintext) data.
		  	
		  	--help|-h : Shows this message
		  """
	
def run_tool(key_file, in_file, out_file):
	"""
	Runs the plonevote.decrypt tool and decrypts in_file into out_file.
	"""
	# Load the private key
	print "Loading private key..."
	try:
		private_key = PrivateKey.from_file(key_file)
	except InvalidPloneVoteCryptoFileError, e:
		print "Invalid private key file (%s): %s" % (key_file, e.msg)
		sys.exit(2)
	
	# Open the input encrypted data
	print "Loading encrypted data..."
	try:
		ciphertext = Ciphertext.from_file(in_file)
	except InvalidPloneVoteCryptoFileError, e:
		print "Invalid PloneVote encrypted file (%s): %s" % (key_file, e.msg)
		sys.exit(2)
	
	# Decrypt to bitstream
	print "Decrypting..."	
	try:
		bitstream = private_key.decrypt_to_bitstream(ciphertext)
	except IncompatibleCiphertextError, e:
		print "Incompatible private key and ciphertext error: %s" % s.msg
	
	# Save the resulting plaintext to the output file
	print "Writing decrypted data..."
	try:
		out_f = open(out_file, 'wb')
	except Exception, e:
		print "Problem while opening output file %s: %s" % (out_file, e)
	
	# Remember that the bitstream is in the format 
	# [size (64 bits) | message (size bits) | padding]
	bitstream.seek(0)
	length = bitstream.get_num(64)
	
	try:
		for i in range(0, length / 8):
			byte = bitstream.get_byte()
			out_f.write(chr(byte))
	except Exception, e:
		print "Problem while writing to output file %s: %s" % (out_file, e)
	
	out_f.close()

def main():
	"""
	Parses command line options and runs the tool
	"""
    # parse command line options
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'n', ['key=', 'in=', 'out='])
	except getopt.error, msg:
		print msg
		print "for help use --help"
		sys.exit(2)
	
	# process options
	key_file = in_file = out_file = None
	for o, a in opts:
		if o in ("-h", "--help"):
			print_usage()
			sys.exit(0)
		elif o == "--key":
			key_file = a
		elif o == "--in":
			in_file = a
		elif o == "--out":
			out_file = a
		else:
			print "ERROR: Invalid argument: %d=%d\n" % (o, a)
			print_usage()
			sys.exit(2)
	
	# All arguments are mandatory
	for option in [key_file, in_file, out_file]:
		if(option == None):
			print_usage()
			sys.exit(2)			
    
    # Run decryption
	run_tool(key_file, in_file, out_file)

if __name__ == "__main__":
    main()
