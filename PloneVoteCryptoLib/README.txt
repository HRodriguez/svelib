Basic cryptographic library for the PloneVote verifiable online voting system.

ToDo: Improve this README file.

Note on python versions:
    This package should be tested to work with python 2.4 and 2.6 before 
    deployment. During development, it is safer to work with python 2.4.

Setting up your development environment:

    * Get the code from the repository
    * Use setuptools to install this package for development:
      (As root from PloneVoteCryptoLib/ )
      
        python2.4 setup.py develop
        
    (see http://packages.python.org/distribute/setuptools.html#development-mode)
    
    * Run all tests (see below)

Running tests and getting code coverage:
    (Requires the coverage.py and nose modules to be installed)

 Coverage from unit tests:
    From anywhere in the source tree:
        nosetests --with-coverage --cover-package=plonevotecryptolib --verbose
        
 Coverage from doctests:
    From plonevotecryptolib/ (otherwise, adjust path):
        coverage run --timid tests/doctests/quicktestscript.py
        coverage report -m
        
 Combined coverage from unit tests and doctests:
    ?
        
