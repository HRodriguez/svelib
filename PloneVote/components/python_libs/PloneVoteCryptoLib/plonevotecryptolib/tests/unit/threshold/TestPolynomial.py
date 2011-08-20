# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestPolynomial.py : Unit tests for 
#                       plonevotecryptolib/Threshold/Polynomial.py
#
#  For usage documentation of Polynomial.py, see, besides this file:
#    * the documentation strings for the classes and methods of 
#      Polynomial.py
#
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

# Standard library imports
import unittest
import random

# Main library PloneVoteCryptoLib imports
from plonevotecryptolib.Threshold.Polynomial import CoefficientsPolynomial

# ============================================================================
# The actual test cases:
# ============================================================================

class TestCoefficientsPolynomial(unittest.TestCase):
    """
    Test the class: 
     plonevotecryptolib.Threshold.Polynomial.CoefficientsPolynomial
    """
    
    def test_create_coeff_polynomial_small(self):
        """
        Create a new coefficients polynomial by giving the corresponding 
        coefficients (small modulus and coefficients example, for easy 
        reading).
        """
        # Generate our polynomial:
        # p(x) = x^2 + 4*x + 8 \in Z_{17} (ie. modulus 17 algebra)
        modulus = 17
        coefficients = [8, 4, 1] # coefficients[i] is c_{i} in SUM(c_{i}*x^i)
        p = CoefficientsPolynomial(modulus, coefficients)
        
        # Test that the resulting polynomial has the expected degree: 2
        self.assertEqual(p.get_degree(), 2)
        
        # Test that the modulus and coefficients were correctly recorded
        self.assertEqual(p.get_modulus(), modulus)
        self.assertEqual(p.get_coefficients(), coefficients)
        
        for i in range(0, len(coefficients)):
            self.assertEqual(p.get_coefficient(i), coefficients[i])
            
        # Test that the polynomial evaluates to the expected value for a few 
        # x's
        
        # 1) p(5) = 5^2 + 4*5 + 8 = 25 + 20 + 8 = 53 = 2 mod 17
        self.assertEqual(p(5), 2)
        # 2) p(1) = 1 + 4 + 8 = 13 = 13 mod 17
        self.assertEqual(p(1), 13)
        # 3) p(0) = 8 mod 17
        self.assertEqual(p(0), 8)
        # 4) p(16) = 16^2 + 4*16 + 8 = 256 + 64 + 8 = 328 = 5 mod 17
        self.assertEqual(p(16), 5)
        
        # The following examples are currently valid, although 
        # CoefficientsPolynomial could be altered to not allow calls with 
        # numbers outside of [0, modulus - 1]:
        
        # 5) p(90) = p(5) % 17 = 2 mod 17 (see 1, and (90 = 5) mod 17)
        self.assertEqual(p(90), 2)
        # 6) p(-12) = p(5) % 17 = 2 mod 17 (see 1, and (-12 = 5) mod 17)
        self.assertEqual(p(-12), 2)
    
    def test_create_coeff_polynomial_large_random(self):
        """
        Create a new coefficients polynomial by giving the modulus and 
        generating random coefficients (large modulus and coefficients example, 
        for stress testing).
        """
        # 4096-bit prime
        prime = int(\
                    "1030799842786894181631389441103185966569507239371816962" \
                    "4978338055490842089614129277498900319820357566344123748" \
                    "6733156317168957900155665107496366703386281755055392965" \
                    "0482922853287292659506843149296105637767886823281017653" \
                    "3910493192845060890137468614986408838534331249499143887" \
                    "8240392751996416013109700510089131594462789759613994845" \
                    "8435523590438946151771098557650151249388764789950580302" \
                    "5724273343076818749635035686807909690718552859584015925" \
                    "7687323419195652187155387082468433670807387493556016980" \
                    "5863461555878279456798001719303987238011908109139830602" \
                    "0669938885067728431660759420938086503333708168951681838" \
                    "3021541449655465434898294213951276050509787120108201138" \
                    "0714497759152490923615704418043118467768563572708275773" \
                    "2461440591991675120453490718568934924138096603098071715" \
                    "5809020294969435729482955533673603467176342000620072339" \
                    "9031249881813572203253808727332410548412729356180978096" \
                    "4888225806099431563543317084150424777724002753141453195" \
                    "1549167254419629309482949167419204154625159927438070053" \
                    "2255709285198635275092329304750758901073929816789775100" \
                    "3853339241804019013946059652824339135601164264716579746" \
                    "0752798419181115878818875144812516179341148144694010500" \
                    "1197785456808159638017068703237966891009241058822845094" \
                    "404308191065131495323419")

        # Generate our polynomial:
        degree = 50
        p = CoefficientsPolynomial.new_random_polynomial(prime, degree)
        
        # Test that the resulting polynomial has the expected degree and 
        # modulus
        self.assertEqual(p.get_degree(), degree)
        self.assertEqual(p.get_modulus(), prime)
        
        # Get the polynomial coefficients
        coefficients = p.get_coefficients()
        self.assertEqual(len(coefficients) - 1, degree)
        
        # define our own calculation of the polynomial value for a given x
        # using a recursive version of Horner's scheme
        def expected_value(x, coeffs):
            if(len(coeffs) == 0):
                return 0
            else:
                # If p(x) = SUM{c_i*x^i} for i \in [0,n]
                # and q(x) = SUM{c_{i+1}*x^i} for i \in [0,n-1], then:
                # p(x) = q(x)*x + c_{0}
                q = expected_value(x, coeffs[1:])
                return (q*x + coeffs[0]) % prime
                
        # test some random values
        for i in range(0, 50):
            x = random.randint(0, prime)
            self.assertEqual(p(x), expected_value(x, coefficients))
    
    def test_get_coeff_out_of_range(self):
        """
        Test that trying to get a coefficient by index where the given index is 
        not between 0 and the degree of the polynomial - 1, inclusive, results 
        in an exception being raised.
        """
        # Generate our polynomial:
        # p(x) = x^2 + 4*x + 8 \in Z_{17} (ie. modulus 17 algebra)
        modulus = 17
        coefficients = [8, 4, 1]
        p = CoefficientsPolynomial(modulus, coefficients)
        
        self.assertRaises(ValueError, p.get_coefficient, -1)
        self.assertRaises(ValueError, p.get_coefficient, len(coefficients))
    
    def test_create_coeff_polynomial_no_coeffs(self):
        """
        Test that attempting to create a coefficients polynomial with no 
        coefficients (ie. degree < 0) results in an exception being raised.
        """
        # Giving the coefficients explicitly
        self.assertRaises(ValueError, CoefficientsPolynomial, 17, [])
        
        # Creating a random polynomial of invalid degree
        self.assertRaises(ValueError, 
                          CoefficientsPolynomial.new_random_polynomial, 17, -1)
        self.assertRaises(ValueError, 
                          CoefficientsPolynomial.new_random_polynomial, 17, -20)


if __name__ == '__main__':
    unittest.main()
