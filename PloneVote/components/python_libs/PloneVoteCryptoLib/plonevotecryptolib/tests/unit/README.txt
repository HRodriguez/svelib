Unit tests organization:


main/   -- Unit tests for the modules in plonevotecryptolib.*

    TestPVCExceptions.py    -- tests for plonevotecryptolib.PVCExceptions
    
    TestEGCryptoSystem.py   -- tests for plonevotecryptolib.EGCryptoSystem
    
    TestEGCryptoSystem.resources    -- data files for TestEGCryptoSystem.py
    
    TestBasicEncryption.py  -- tests for:
                                plonevotecryptolib.PublicKey
                                plonevotecryptolib.PrivateKey
                                plonevotecryptolib.KeyPair
                                plonevotecryptolib.Ciphertext
                                
    TestBasicEncryption.resources   -- data files for TestBasicEncryption.py
    

utilities/  -- Unit tests for the modules in plonevotecryptolib.utilities.*

    TestEnumerate.py    -- tests for plonevotecryptolib.utilities.Enumerate
    
    TestBitStream.py    -- tests for plonevotecryptolib.utilities.BitStream
    
    TestTaskMonitor.py  -- tests for plonevotecryptolib.utilities.TaskMonitor
    
    TestSerialize.py    -- tests for plonevotecryptolib.utilities.serialize
    
    TestSerialize.resources     -- data files for TestSerialize.py


threshold/  -- Unit tests for the modules in plonevotecryptolib.Threshold.*

    TestPolynomial.py   -- test for plonevotecryptolib.Threshold.Polynomial


mixnet/     -- Unit tests for the modules in plonevotecryptolib.Mixnet.*


No tests for plonevotecryptolib.tools, no code in plonevotecryptolib/data and 
definitelly no recursive tests for plonevotecryptolib.tests ;)
