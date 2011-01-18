# -*- coding: utf-8 -*-
#
#  plonevote.get_cryptosys.py : A tool to generate new cryptosystem instances.
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

from plonevotecryptolib.utilities.TaskMonitor import TaskMonitor
from plonevotecryptolib.EGCryptoSystem import EGCryptoSystem

def print_usage():
	"""
	Prints the tool's usage message
	"""
	print """USAGE:
		  
		  plonevote.get_cryptosys.py filename --nbits=N --name="..." --description="..."
		  
		  plonevote.get_cryptosys.py (--help|-h)
		  
		  Long options (--X) may be given in any order.
		  
		  	filename : the name of the file to which to save the newly generated cryptosystem.
		  	
		  	--nbits=N : (optional) the size in bits for the keys in the cryptosystem.
		  	
		  	--name="..."  : (optional) a short human readable name to identify the new cryptosystem definition.
		  	
		  	--description="..."  : (optional) a human readable description of the new cryptosystem definition.
		  	
		  	--help|-h : Shows this message
		  """
	
def run_tool(nbits, filename, name, description):
	"""
	Runs the plonevote.get_cryptosys tool.
	"""
	# Define callbacks for the TaskMonitor for progress monitoring
	def cb_task_start(task):
		print task.task_name + ":"

	def cb_task_progress(task):
		sys.stdout.write(".")
		sys.stdout.flush()

	def cb_task_end(task):
		print ""
	
	# Create new TaskMonitor and register the callbacks
	taskmon = TaskMonitor()
	taskmon.add_on_task_start_callback(cb_task_start)
	taskmon.add_on_tick_callback(cb_task_progress)
	taskmon.add_on_task_end_callback(cb_task_end)
	
	# Generate a new cryptosystem of the requested size
	if(nbits == None):
		cryptosys = EGCryptoSystem.new(task_monitor = taskmon)
	else:
		try:
			cryptosys = EGCryptoSystem.new(nbits, task_monitor = taskmon)
		except KeyLengthTooLowError:
			print "ERROR: The given bit size does not meet PloneVoteCryptoLib "\
				  "minimum security requirements (too short)."
		except KeyLengthNonBytableError:
			print "ERROR: The given bit size must be a multiple of 8."
	
	# Save the cryptosystem to file
	print "\nSaving cryptosystem to %d..." % filename,
	
	cryptosys.to_file(name, description, filename)
	
	print "SAVED."

def main():
	"""
	Parses command line options and runs the tool
	"""
    # parse command line options
	try:
		opts, args = getopt.getopt(sys.argv[1:], "n", ["nbits", "name", "description"])
	except getopt.error, msg:
		print msg
		print "for help use --help"
		sys.exit(2)
        
    # process options
	nbits_str = name = description = filename = None
	for o, a in opts:
		if o in ("-h", "--help"):
			print_usage()
			sys.exit(0)
		elif o == "nbits":
			nbits_str = a
		elif o == "name":
			name = a
		elif o == "description":
			description = a
		else:
			print "ERROR: Invalid argument: %d=%d\n" % (o, a)
			print_usage()
       		
    # process arguments
	if(len(args) != 1):
		print "ERROR: Invalid arguments.\n" 
		print_usage()
    
	filename = args[0]
    
    # Check all arguments
	print nbits, name, description, filename

if __name__ == "__main__":
    main()
