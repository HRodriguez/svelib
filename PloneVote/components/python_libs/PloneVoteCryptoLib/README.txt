Basic cryptographic library for the PloneVote verifiable online voting system.

ToDo: Improve this README file.

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
        
