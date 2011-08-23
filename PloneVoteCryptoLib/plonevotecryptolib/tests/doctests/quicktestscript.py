import doctest
import os
import glob

######
# HACK: Patch doctest in memory so that it works correctly with coverage.
#
# This is required only for python 2.4, see:
#   https://bitbucket.org/ned/coveragepy/issue/19/not-picking-up-doctest-tests#comment-82784
#   http://svn.zope.org/Zope3/trunk/src/zope/testing/doctest.py?rev=28679&r1=28703&r2=28705
######
import sys
if(sys.version_info < (2, 5)): # pragma: no cover
    import pdb
    class _Patched_OutputRedirectingPdb(pdb.Pdb):
        """
        A specialized version of the python debugger that redirects stdout
        to a given stream when interacting with the user.  Stdout is *not*
        redirected when traced code is executed.
        """
        def __init__(self, out):
            self.__out = out
            self.__debugger_used = False
            pdb.Pdb.__init__(self)

        def set_trace(self):
            self.__debugger_used = True
            pdb.Pdb.set_trace(self)
      	 
        def set_continue(self):
            # Calling set_continue unconditionally would break unit test coverage
            # reporting, as Bdb.set_continue calls sys.settrace(None).
            if self.__debugger_used:
                pdb.Pdb.set_continue(self)

        def trace_dispatch(self, *args):
            # Redirect stdout to the given stream.
            save_stdout = sys.stdout
            sys.stdout = self.__out
            # Call Pdb's trace dispatch method.
            try:
                return pdb.Pdb.trace_dispatch(self, *args)
            finally:
                sys.stdout = save_stdout

    doctest._OutputRedirectingPdb = _Patched_OutputRedirectingPdb
######
# End HACK
######

# Get the full path to the doctests
doctest_dir = os.path.dirname(__file__)
doctest_files = glob.glob(os.path.join(doctest_dir, "*.txt"))
for doctest_file in doctest_files:
    doctest_file = os.path.split(doctest_file)[1] # keep only the filename
    doctest.testfile(doctest_file)
