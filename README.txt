svelib: Cryptographic library in python for implementing open-audit / 
voter-verifiable elections

==============================================================================
BASIC INFORMATION:
==============================================================================

Current owner: Hugo Rodriguez (sn4ke@ciencias.unam.mx)

Originally developed by: Lázaro Clapp (lazaro.clapp@gmail.com)

License: MIT (see PloneVoteCryptoLib/COPYRIGHT.txt)

For instructions on how to set up a developing environment and run the test 
suite for the library, see:

        PloneVoteCryptoLib/Readme.txt

==============================================================================
FAQ:
==============================================================================

What is this project?
    
    A python library implementing some specialized cryptographic primitives for 
    voter-verifiable online elections (ie. Sako-Kilian/Benaloh mixnets and 
    threshold El-Gamal encryption with proofs of decryption).
    
    It is intended to form part of the PloneVote system, an election hosting 
    product for the Plone CMS. PloneVote is currently under development at the  
    IMUNAM (Institute of Mathematics, Universidad Nacional Autónoma de México, 
    Mexico).
    
    This library, however, is not dependent upon PloneVote or Plone and can be 
    used to construct other secure election systems.
    
How the $exclamation does this thing work?

    TODO: Proper documentation will be forthcoming.
    
    For now, we can tell you that...
    
    * The desired election protocol for PloneVote follows very closely the one 
      described for Helios v1. See:
    
        Adida, B., 2008. Helios: Web-based Open-Audit Voting. In: 17th USENIX
        Security Symposium (Security '08).
        (http://www.usenix.org/event/sec08/tech/full_papers/adida/adida.pdf)
        
    * We implement verifiable mixnets following the scheme described in:
    
        Benaloh, J., August 2006. Simple Verifiable Elections. In: EVT'06, 
        Proceedings of the First Usenix/ACCURATE Electronic Voting Technology 
        Workshop.
        (www.usenix.org/event/evt06/tech/full_papers/benaloh/benaloh.pdf)
        
        Hence the name, SVElib.
        
    * We gave a presentation on the PloneVote system at Plone Symposium East 
      2011. The slides can be found in:
      
      Documentation/misc/PloneSymposiumEast2011_presentation_final.pdf
      
    * The full expected usage of svelib by PloneVote or a similar election 
      system is described, tersely, by the doctest file:
      
      PloneVoteCryptoLib/plonevotecryptolib/tests/doctests/
                                                    full_election_doctest.txt


Why is the project called svelib while the directories, namespaces, class-names 
and code documentation refeer to this library as PloneVoteCryptoLib?

    PloneVoteCryptoLib is the old name of the library. We will change all names 
    to svelib as soon as we have a full test suite that makes it easy for us to 
    do so without the risk of breaking anything.
