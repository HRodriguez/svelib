# -*- coding: utf-8 -*-
#
#  plonevote.encrypt.py : A tool to encrypt a file using PloneVoteCryptoLib.
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
import os.path
import getopt

from plonevotecryptolib.PublicKey import PublicKey
from plonevotecryptolib.utilities.BitStream import BitStream
from plonevotecryptolib.utilities.TaskMonitor import TaskMonitor
from plonevotecryptolib.PVCExceptions import *

def print_usage():
	"""
	Prints the tool's usage message
	"""
	print """USAGE:
		  
		  plonevote.encrypt.py --key=public_key.pvpubkey --in=file.ext --out=file.pvencrypted
		  
		  plonevote.encrypt.py (--help|-h)
		  
		  Arguments can be given in any order. All arguments are mandatory.
		  	
		  	--key=public_key.pvpubkey  : The file containing the public key used for encryption.
		  	
		  	--in=file.ext	: The source (input) file to encrypt.
		  	
		  	--out=file.pvencrypted	: The destination (output) file that will contain the encrypted data.
		  	
		  	--help|-h : Shows this message
		  """
	
def run_tool(key_file, in_file, out_file):
	"""
	Runs the plonevote.encrypt tool and encrypts in_file into out_file.
	"""
	# Load the public key
	print "Loading public key..."
	try:
		public_key = PublicKey.from_file(key_file)
	except InvalidPloneVoteCryptoFileError, e:
		print "Invalid public key file (%s): %s" % (key_file, e.msg)
		sys.exit(2)
	
	# Open the input file
	print "Reading input file..."
	try:
		in_f = open(in_file, 'rb')
	except Exception, e:
		print "Problem while opening input file %s: %s" % (in_file, e)
	
	# Read the whole file into a bitstream
	bitstream = BitStream()
	try:
		read_quantum = 1024 # KB at a time
		bytes = in_f.read(read_quantum)
		while(bytes):
			for byte in bytes:
				bitstream.put_byte(ord(byte))
			bytes = in_f.read(read_quantum)
	except Exception, e:
		print "Problem while reading from input file %s: %s" % (in_file, e)
	
	in_f.close()
	
	# Define callbacks for the TaskMonitor for monitoring the encryption process
	if(len(in_file) <= 50):
		short_in_filename = in_file
	else:
		short_in_filename = os.path.split(in_file)
		if(len(short_in_filename) > 50):
			# Do ellipsis shortening
			short_in_filename = short_in_filename[0,20] + "..." + \
								short_in_filename[-20,-1]
	
	def cb_task_percent_progress(task):
		print "  %.2f%% of %s encrypted..." % \
				(task.get_percent_completed(), short_in_filename)
	
	# Create new TaskMonitor and register the callbacks
	taskmon = TaskMonitor()
	taskmon.add_on_progress_percent_callback(cb_task_percent_progress, \
											 percent_span = 5)
	
	# Encrypt bitstream
	print "Encrypting..."
	ciphertext = public_key.encrypt_bitstream(bitstream, task_monitor = taskmon)
	
	# Save the ciphertext to the output file
	try:
		ciphertext.to_file(out_file)
	except Exception, e:
		print "Problem while saving the output file %s: %s" % (in_file, e.msg)
	
		

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
    
    # Run encryption
	run_tool(key_file, in_file, out_file)

if __name__ == "__main__":
    main()
