# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  ThresholdEncryptionSetUp.py : 
#  An auxiliary class used for setting up a threshold encryption scheme.
#
#  This class should be used both to generate a commitment for a threshold 
#  encryption scheme and to combine the commitments of multiple trustees in 
#  order to generate a threshold encryption private/public key pair.
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

import math

import Crypto.Hash.SHA256

from plonevotecryptolib.Threshold.Polynomial import CoefficientsPolynomial
from plonevotecryptolib.Threshold.ThresholdEncryptionCommitment import ThresholdEncryptionCommitment
from plonevotecryptolib.Threshold.ThresholdPublicKey import ThresholdPublicKey
from plonevotecryptolib.Threshold.ThresholdPrivateKey import ThresholdPrivateKey
from plonevotecryptolib.Threshold.ThresholdKeyPair import ThresholdKeyPair

from plonevotecryptolib.PVCExceptions import InvalidPloneVoteCryptoFileError
from plonevotecryptolib.PVCExceptions import ElectionSecurityError
from plonevotecryptolib.PVCExceptions import IncompatibleCiphertextError

from plonevotecryptolib.utilities.BitStream import BitStream

class ThresholdEncryptionSetUpStateError(Exception):
	"""
	Raised when a ThresholdEncryptionSetUp operation is called when the 
	instance is in an inappropriate state.
	
	Common examples:
		- generate_commitment called without having registered all the 
		  trustees' public keys.
		- get_fingerprint called without having registered all the trustees' 
		  commitments.
		- generate_threshold_keypair called without having registered all the 
		  trustees' commitments.				
	"""
    
	def __str__(self):
		return self.msg

	def __init__(self, msg):
		"""
		Create a new ThresholdEncryptionSetUpStateError exception.
		"""
		self.msg = msg

class IncompatibleCommitmentError(Exception):
	"""
	Raised when ThresholdEncryptionSetUp.add_trustee_commitment is given a 
	ThresholdEncryptionCommitment that is not compatible with the current 
	ThresholdEncryptionSetUp instance. 
	(ie. has a different number of trustees)
	"""
    
	def __str__(self):
		return self.msg

	def __init__(self, msg):
		"""
		Create a new IncompatibleCommitmentError exception.
		"""
		self.msg = msg

class InvalidCommitmentError(ElectionSecurityError):
	"""
	Raised when a ThresholdEncryptionCommitment is detected to be invalid.
	
	For example, when it is found that a partial private key given in the 
	commitment is not consistent with its public coefficients.
	
	This is an election security error. If raised, the election process may 
	only safely continue if the detected invalid commitment is replaced with a 
	correct one and threshold public and private keys are generated again from 
	scratch.
	
	Attributes:
		trustee::int	-- The number of the trustee to which the invalid 
						   commitment is associated.
		commitment::ThresholdEncryptionCommitment	-- The invalid commitment.
	"""

	def __init__(self, trustee, commitment, msg):
		"""
		Create a new ThresholdEncryptionSetUpStateError exception.
		"""
		ElectionSecurityError.__init__(self, msg)
		self.trustee = trustee
		self.commitment = commitment


class ThresholdEncryptionSetUp:
	"""
	Used for setting up a threshold encryption scheme.
	
	This class can be used both to generate a commitment for a threshold 
	encryption scheme and to combine the commitments of multiple trustees in 
	order to generate a threshold encryption private/public key pair.
	
	ToDo: Link a comprehensive doctest file showing how this class should be 
	used.
	
	Attributes (public):
		cryptosystem::EGCryptoSystem	-- The shared cryptosystem used by the 
										   threshold scheme.
	"""
	
	def get_fingerprint(self):
		"""
		Get the fingerprint of the threshold scheme.
		
		This requires all trustees' commitments to be loaded into the current 
		instance.
		
		The same fingerprint for two different ThresholdEncryptionSetUp objects 
		indicates that all commitments have been loaded and are the same for 
		both objects. This means that both objects are starting with the same 
		information when bootstrapping the threshold encryption scheme.
		
		In order for the keys generated by 
		ThresholdEncryptionSetUp.generate_threshold_keypair to be trustworthy, 
		all trustees must generate this fingerprint and ensure that it matches 
		the fingerprint obtained by all other trustees. This guarantees that 
		all trustees are working from the same set of commitments and, thus,  
		that the threshold encryption is set up correctly.
		
		It is important that the current trustee's commitment is loaded from a 
		trusted location, rather than taken from the server, in order for this 
		verification to work.
		
		This fingerprint is calculated as a hash of all public coefficients and 
		encrypted partial private keys from all of the trustees' commitments.
		
		Returns:
			fingerprint::string	-- fingerprint as a sha256 hexdigest
		
		Throws:
			ThresholdEncryptionSetUpStateError -- If commitments are not loaded.
		"""
		fingerprint = Crypto.Hash.SHA256.new()
		
		for commitment in self._trustees_commitments:
			if(commitment == None):
				raise ThresholdEncryptionSetUpStateError( \
					"get_fingerprint() must only be called after all the " \
					"trustees' commitments have been registered with this " \
					"ThresholdEncryptionSetUp instance. Missing at least one " \
					"commitment.")
					
			for pub_coeff in commitment.public_coefficients:
				fingerprint.update(hex(pub_coeff))
			for ciphertext in commitment.encrypted_partial_private_keys:
				for gamma, delta in ciphertext:
					fingerprint.update(hex(gamma))
					fingerprint.update(hex(delta))
					
		return fingerprint.hexdigest()
		
	
	def __init__(self, cryptosystem, num_trustees, threshold):
		"""
		Constructs a ThresholdEncryptionSetUp class.
		
		Arguments:
			cryptosystem::EGCryptoSystem	-- The cryptosystem to use for the 
											   threshold scheme.
			num_trustees::int	-- Total number of trustees in the threshold 
								   scheme. (the n in "k of n"-decryption)
			threshold::int	-- Minimum number of trustees required to decrypt 
							   threshold encrypted messages. 
							   (the k in "k of n"-decryption)
		"""
		self.cryptosystem = cryptosystem
		self._num_trustees = num_trustees
		self._threshold = threshold
		# We initialize the array of trustee public keys to None each
		self._trustees_simple_public_keys = [None for i in range(1,num_trustees + 1)]
		# Same for commitments
		self._trustees_commitments = [None for i in range(1,num_trustees + 1)]
	
	def add_trustee_public_key(self, trustee, public_key):
		"""
		Registers the (simple, 1-to-1) public key of a trustee with this object.
		
		This public keys are used to secretly transmit information only to a 
		given trustee as part of the threshold encryption set-up protocol. 
		Namely the encrypted partial private keys (P_{i}(j)), which are part of 
		the published commitment generated by each trustee, but encrypted so 
		that only the rightful recipient may read them.
		
		IMPORTANT: 
		The public keys from other trustees may be taken from the PloneVote 
		server or from some other shared storage, but it is recommended that 
		the public key for the current trustee executing the protocol be from a 
		trusted source (eg. local storage and matched to its corresponding 
		private key)
		
		Arguments:
			trustee::int	-- The index within the threshold scheme of the 
							   trustee to which the key to be registered 
							   belongs.
							   (trustees are indexed from 1 to num_trustees)
			public_key::PublicKey	-- The trustee's public key.
		"""
		if(not (1 <= trustee <= self._num_trustees)):
			raise ValueError("Invalid trustee. The threshold scheme trustees " \
							"must be indexed from 1 to %d" % self._num_trustees)
		
		# The trustee indexes go from 1 to n, the pk list indexes go from 0 to 
		# (n-1)					
		self._trustees_simple_public_keys[trustee - 1] = public_key
	
	def add_trustee_commitment(self, trustee, commitment):
		"""
		Registers the commitment of a trustee with this object.
		
		Commitments are combined in order to generate the keys for the 
		threshold encryption scheme.
		
		IMPORTANT: 
		The commitments from other trustees may be taken from the PloneVote 
		server or from some other shared storage, but it is highly recommended  
		that the commitment for the current trustee executing the protocol be  
		from a trusted source (eg. local storage). This, together with ensuring 
		that the fingerprints for the ThresholdEncryptionSetUp used by each 
		trustee to generate their keys match, can protect trustees from the 
		server or some other third party supplanting their commitments while 
		in transit.
		
		Arguments:
			trustee::int	-- The index within the threshold scheme of the 
							   trustee to which the key to be registered 
							   belongs.
							   (trustees are indexed from 1 to num_trustees)
			commitment::ThresholdEncryptionCommitment	--
							The trustee's published commitment. 
		"""
		if(not (1 <= trustee <= self._num_trustees)):
			raise ValueError("Invalid trustee. The threshold scheme trustees " \
							"must be indexed from 1 to %d" % self._num_trustees)
		
		# Check that global parameters of the commitment match those of the 
		# current ThresholdEncryptionSetUp instance.
		if(self.cryptosystem != commitment.cryptosystem):
			raise IncompatibleCommitmentError("The given commitment is not " \
							"compatible with the current " \
							"ThresholdEncryptionSetUp instance: " \
							"Different cryptosystems used.")
							
		if(self._num_trustees != commitment.num_trustees):
			raise IncompatibleCommitmentError("The given commitment is not " \
							"compatible with the current " \
							"ThresholdEncryptionSetUp instance: " \
							"Different number of trustees.")
							
		if(self._threshold != commitment.threshold):
			raise IncompatibleCommitmentError("The given commitment is not " \
							"compatible with the current " \
							"ThresholdEncryptionSetUp instance: " \
							"Different threshold value.")
		
		# The trustee indexes go from 1 to n, the commitment list indexes go 
		# from 0 to (n-1)					
		self._trustees_commitments[trustee - 1] = commitment
		
	
	def generate_commitment(self):
		"""
		Generate a ThresholdEncryptionCommitment towards the threshold scheme.
		
		Returns:
			commitment::ThresholdEncryptionCommitment
		
		Throws:
			ThresholdEncryptionSetUpStateError -- If public keys are not loaded.
		"""
		# 0. Verify that all public keys are available for 1-to-1 encryption.
		for trustee in range(1, self._num_trustees + 1):
			# The trustee indexes go from 1 to n, the pk list indexes go from 0 
			# to (n-1)
			pk = self._trustees_simple_public_keys[trustee - 1]
			if(pk == None):
				raise ThresholdEncryptionSetUpStateError(
					"generate_commitment() must only be called after all the " \
					"trustees' public keys have been registered with this " \
					"ThresholdEncryptionSetUp instance. Missing public key " \
					"for trustee %d." % trustee)
		
		# 1. Construct a new random polynomial of degree (threshold - 1)
		# Note: A polynomial of degree (t - 1) is determined by any t 
		# (distinct) points.
		degree = self._threshold - 1
		nbits = self.cryptosystem.get_nbits()
		prime = self.cryptosystem.get_prime()
		generator = self.cryptosystem.get_generator()
		
		#  All calculations inside the polynomial are performed modulus q
		#  where q is such that p = 2*q + 1 (q is prime because of how we 
		#  construct p when generating an EGCryptoSystem).
		#  We do this, because the values of the polynomial coefficients or its 
		#  value at a certain point are always used as the exponent of elements 
		#  in Z_{p}^{*}, and we know:
		#  a = b mod (p - 1) => g^a = g^b mod p
		#  (because g^{a-b} = g^{x(p-1)} = (g^x)^{p-1} = 1 mod p)
		#  We use q and not p - 1, because Z_{q} is a field (because q is 
		#  prime), while the same would not be true for p-1, and we need the 
		#  polynomials to be on a field in order to perform Lagrange 
		#  Interpolation (see ThresholdDecryptionCombinator.decrypt_to_X()). 
		#  This also means that 2*P(0) will be the threshold private key 
		#  (never actually seen directly by the parties), and g^(2*P(0)) 
		#  the threshold public key.
		#  For the full explanation, see: (TODO: Add reference)
		
		q = (prime - 1) / 2
		polynomial = \
			CoefficientsPolynomial.new_random_polynomial(q, degree)
		
		# 2. Generate the public "coefficients" (actually g^coefficient for 
		# each coefficient of the polynomial).
		public_coeficients = []
		for coeff in polynomial.get_coefficients():
			public_coeficients.append(pow(generator, coeff, prime)) 
		
		# 3. Generate the partial private keys and partial public keys
		# for each trustee.
		#
		# The partial private key for trustee j is P_{i}(j), with i the   
		# trustee generating the commitment, its full private key is the sum 
		# of the P_{i}(j) values generated by all trustees (including its own).
		#
		# The partial public key fragment or commitment partial public key is 
		# g^P_{i}(j), with g^P(j) (the product of all g^P_{i}(j)'s) being the 
		# "true" partial public key.
		#
		# IMPORTANT: We encrypt each partial private key so that only its 
		# intended recipient may read it.
		partial_pub_keys = []
		enc_partial_priv_keys = []
		for trustee in range(1, self._num_trustees + 1):
			ppriv_key = polynomial(trustee)	# P_{i}(j)
			
			ppub_key = pow(generator, ppriv_key, prime) # g^P_{i}(j) 
			partial_pub_keys.append(ppub_key)
			
			trustee_pk = self._trustees_simple_public_keys[trustee - 1]
			
			# Note that trustee public keys need not use the same cryptosystem 
			# as the threshold encryption. In fact, they might not even have 
			# the same bit length.
			bitstream = BitStream()
			bitstream.put_num(ppriv_key, nbits)
			ciphertext = trustee_pk.encrypt_bitstream(bitstream)
			enc_partial_priv_keys.append(ciphertext)
		
		# 4. Construct a ThresholdEncryptionCommitment object storing this 
		# commitment and return it.
		return ThresholdEncryptionCommitment(self.cryptosystem, 
			self._num_trustees, self._threshold, public_coeficients, 
			partial_pub_keys, enc_partial_priv_keys)
	
	def generate_public_key(self):
		"""
		Construct the threshold public key for the scheme.
		
		This  method requires all trustees' commitments to be loaded into the 
		current instance. Anyone with access to all the trustees' commitments 
		can generate the public key for the threshold scheme.
		
		Returns:
			public_key::ThresholdPublicKey	-- The public key for the threshold 
											   scheme.
		
		Throws:
			ThresholdEncryptionSetUpStateError -- If commitments are not loaded.
		"""
		# The public key for a threshold encryption scheme is the value 
		# generator^{2*P(0)} for P the shared sum of all of the polynomials
		# generated by each trustee. Where the polynomials are taken on the
		# field Z_{q} (that is, mod q, with q = (p - 1) / 2) as explained in
		# the comments for generate_commitment().
		# By linearity of the sum of polynomials, we can obtain that same value 
		# by multiping the published g^{c_0 | for i} = g^(P_{i}(0)) 
		# public "coefficients":
		# ie. $g^{2P(0)}=g^{\sum2P_{i}(0)}=\prod\left(g^{P_{i}(0)}\right)^{2}$
		
		key = 1
		prime = self.cryptosystem.get_prime()
		
		for commitment in self._trustees_commitments:
			if(commitment == None):
				raise ThresholdEncryptionSetUpStateError(
					"generate_public_key() must only be called after all the " \
					"trustees' commitments have been registered with this " \
					"ThresholdEncryptionSetUp instance. Missing at least one " \
					"commitment.")
			
			# factor is (g^{P_{i}(0)})^{2}
			factor = pow(commitment.public_coefficients[0], 2, prime)
			# key holds the multiplication
			key = (key * factor) % prime
		
		# We must also save the partial public keys for each trustee for 
		# verification purposes. That is, the value g^P(i) for each trustee.
		# Since we require no compatibility with PublicKey.encrypt_to_X(),
		# we don't need to multiple P(i) by 2.
		
		partial_public_keys = []
		
		for trustee in range(1, self._num_trustees + 1):
			# (Could roll this loop into the previous one, but this is more 
			# readable)
			partial_pub_key = 1
			for commitment in self._trustees_commitments:
				# We already know the commitment exists
				
				# ppub_key_fragment is g^P_{i}(j) where i is the trustee 
				# emitting the commitment and j the trustee for whom we wish to 
				# generate the partial public key.
				ppub_key_fragment = commitment.partial_public_keys[trustee - 1]
				
				# We wish to obtain partial_pub_key = g^P(j).
				# For that, we multiple all "ppub_key_fragment"s
				# ie. $g^{P(j)}=g^{\sum_{i}P_{i}(j)}=\prod_{i}g^{P_{i}(j)}$
				partial_pub_key = (partial_pub_key * ppub_key_fragment) % prime
			
			partial_public_keys.append(partial_pub_key)
			
		
		return ThresholdPublicKey(self.cryptosystem, self._num_trustees, 
								  self._threshold, key, partial_public_keys)
								  
	def generate_key_pair(self, current_trustee, simple_private_key):
		"""
		Constructs the threshold private and public key for the scheme.
		
		This  method requires all trustees' commitments to be loaded into the 
		current instance. The partial private key given in each commitment for 
		the current trustee is verified to be consistent with the public 
		coefficients given in the commitment.
		
		This trustee's threshold private key is generated as P(j)= SUM(P_{i}(j)) 
		for all the P_{i} polynomials of all trustees.
		
		Arguments:
			current_trustee::int	-- The number of the trustee who wishes to 
									   generate their threshold private key.
			simple_private_key::PrivateKey	--The simple (1-to-1, non threshold)
										private key of the trustee generating 
										their threshold private key.
										
		Returns:
			key_pair::ThresholdKeyPair --
				A threshold key pair containing the threshold public key and 
				current_trustee's threshold private key.
		
		Throws:
			ThresholdEncryptionSetUpStateError -- If commitments are not loaded.
			InvalidCommitmentError 	-- If a commitment gives an inconsistent 
									   partial private key.
		"""
		
		partial_private_keys = []
		prime = self.cryptosystem.get_prime()
		generator = self.cryptosystem.get_generator()
		
		# For each commitment:
		for trustee in range(1, self._num_trustees + 1):
			commitment = self._trustees_commitments[trustee - 1]
			
			# We check that the commitment is loaded.
			if(commitment == None):
				raise ThresholdEncryptionSetUpStateError(
					"generate_private_key() must only be called after all " \
					"the trustees' commitments have been registered with " \
					"this ThresholdEncryptionSetUp instance. Missing at " \
					"least one commitment.")
		
			# We decrypt the partial private key intended for the current 
			# trustee.
			
			# 	encrypted_partial_private_keys is indexed from 0 to n-1, 
			# 	trustees are indexed from 1 to n.
			ciphertext = \
				commitment.encrypted_partial_private_keys[current_trustee - 1]
			
			try:
				bitstream = simple_private_key.decrypt_to_bitstream(ciphertext)
			except IncompatibleCiphertextError:
				raise InvalidCommitmentError(trustee, commitment,
						"SECURITY ERROR: " \
						"Invalid commitment. The encrypted partial private " \
						"key addressed to the current trustee is encrypted" \
						"with a key that is incompatible with the private " \
						"key given. This could mean either a corrupt " \
						"commitment or an incorrect 1-to-1 (non threshold) " \
						"private key passed as an argument to "\
						"generate_private_key().")
				
			bitstream.seek(0)
			size = bitstream.get_num(64)
			pp_key = bitstream.get_num(size)
		
			# We verify the key against the public coefficients of the 
			# commitment:
			#
			#  g^(2*P_{j}(i)) must be the same as \prod{(g^{c_{jk}})^{2(i^{k})}.
			#  where i is the current trustee, j the trustee that generates the 
			#  commitment, g^{c_{jk}} the public coefficients and P_{j}(i) the 
			#  partial private key.
			#  proof: (LaTeX)
			#  $g^{2P_{j}(i)}=g^{2\sum_{k}c_{jk}(i^{k})}=
			#   \prod_{k}\left(g^{2c_{jk}(i^{k})}\right)=
			#   \prod_{k}\left[\left(g^{c_{jk}}\right)^{2(i^{k})}\right]$
			#
			#  Note that we must multiply the exponents by 2, in order for them 
			#  to be congruent mod p - 1 (since the polynomials are taken in 
			#  Z_{q}). See comments for generate_commitment and 
			#  (TODO: Add reference).
			
			# g^(2*P_{j}(i))
			left_hand_side = pow(generator, 2*pp_key, prime)
			# Calculate \prod{(g^{c_{jk}})^{2(i^{k})} as the rhs
			right_hand_side = 1
			
			# We need the index k from 0 to len(coeffs)
			for k in range(0, len(commitment.public_coefficients)):
				p_coeff = commitment.public_coefficients[k]
				# g^{c_{jk}})^{2(i^{k}) [  p_coeff is g^{c_{jk}}   ]
				right_hand_side *= pow(p_coeff, 2*current_trustee**k, prime)
				right_hand_side = right_hand_side % prime
			
			if(left_hand_side != right_hand_side):
				raise InvalidCommitmentError(trustee, commitment,
						"SECURITY ERROR: " \
						"Invalid commitment. The partial private key " \
						"addressed to the current trustee is inconsistent " \
						"with the commitment's public coefficients. " \
						"This indicates either corruption or deliberate " \
						"tampering of the commitment, either by the trustee " \
						"generating it or in transit.")
			
			# We record the partial private key
			partial_private_keys.append(pp_key)
		
		# We add all partial private keys to obtain this trustee's private key.
		# Since polynomials are in Z_{q}, the sum must be done mod q.
		# (So that P the sum polynomial is also in Z_{q} with the partial 
		# private key of trustee i being P(i))
		q = (prime - 1) / 2
		
		key = 0
		for pp_key in partial_private_keys:
			key = (key + pp_key) % q
		
		# We construct the threshold public key
		threshold_public_key = self.generate_public_key()
		
		# We construct the threshold private key
		threshold_private_key = ThresholdPrivateKey(self.cryptosystem, 
													self._num_trustees, 
													self._threshold,
													threshold_public_key,
													key)
		
		return ThresholdKeyPair(threshold_private_key, threshold_public_key)
		
	
	def generate_private_key(self, current_trustee, simple_private_key):
		"""
		Construct the threshold private key for the scheme.
		
		This  method requires all trustees' commitments to be loaded into the 
		current instance. The partial private key given in each commitment for 
		the current trustee is verified to be consistent with the public 
		coefficients given in the commitment.
		
		This trustee's threshold private key is generated as P(j)= SUM(P_{i}(j) 
		for all the P_{i} polynomials of all trustees.
		
		Arguments:
			current_trustee::int	-- The number of the trustee who wishes to 
									   generate their threshold private key.
			simple_private_key::PrivateKey	--The simple (1-to-1, non threshold)
										private key of the trustee generating 
										their threshold private key.
										
		Returns:
			threshold_private_key::ThresholdPrivateKey --
				current_trustee's threshold private key.
		
		Throws:
			ThresholdEncryptionSetUpStateError -- If commitments are not loaded.
			InvalidCommitmentError 	-- If a commitment gives an inconsistent 
									   partial private key.
		"""
		kp = self.generate_key_pair(current_trustee, simple_private_key)
		return kp.private_key
