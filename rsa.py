#Evaluating the RSA-decryption function homomorphically on encrypted data, it is not possible to use the buildin pycryptodome one. One has to rather build ones own function with the tools possible w.r.t. the API HNP

#The keygeneration algorithm is not connected to homomorphic evaluation directly. Therefore one may use typical python libraries here:

import logging
import Crypto.Util.number as CU
import Crypto.Random as CR
import numpy as np
from loguru import logger

# This class is similarily written as https://docs.zama.ai/hnp/user/practical-examples/linear-regression.html
#Secret keys cannot be stored in the class by the way HNP works (and that one wants to use homomorphically an encrypted version of the secret key)

bitlength = 4

#TODO For every but the HNP decryption function: use the private key as a member variable!! Would be nicer.

class RSA_Tool:
	def __init__(self, public_key = None):
		self.public_key = public_key

	def keygen(self):
		logging.info('RSA: starting key generation')
		secure_dist = 2**(bitlength//2) #describes how big and different from Phi the parameter e must be
		p = CU.getPrime(N = bitlength, randfunc = CR.get_random_bytes)
		q = CU.getPrime(N = bitlength, randfunc = CR.get_random_bytes) 
		while p == q:
			q = CU.getPrime(N = bitlength, randfunc = CR.get_random_bytes) 
		
		N = p*q	
		Phi = (p-1)*(q-1)
	
		e = CU.getRandomRange(a = secure_dist, b = Phi - secure_dist, randfunc = CR.get_random_bytes)	
		d = CU.inverse(e, Phi)
		while (e*d) % Phi != 1:
			e = CU.getRandomRange(a = secure_dist, b = Phi - secure_dist, randfunc = CR.get_random_bytes)	
			d = CU.inverse(e, Phi)
	
		self.public_key = N, e
		logger.info('RSA: storing public key \n' + str(self.public_key))
		
		private_key = d
		logger.info('RSA: returning private key \n' + str(private_key)) 
		
		return private_key
		
# all features (which are the things we want to encode and encrypt) are normed vectors (hence have elements in [0,1])	 - for RSA they must be mapped to the set of nonegative integers <=N
	def __encode(self, M):#
		logger.info('RSA: encoding the message \n' + str(M))
		N, e = self.public_key
		encoded_M = np.floor(M*(N-1))  #test out how good this works without floor!!!!!!!!
		logger.info('RSA: encoded message \n' + str(encoded_M))
		return encoded_M
 			
	def __decode(self, M):
		logger.info('RSA: decoding the message \n' + str(M))
		N, e = self.public_key
		decoded_M = M/(N-1)
		logger.info('RSA: decoded message \n' + str(decoded_M))
		return decoded_M
		
# Sadly, for numpy arrays, no pow with 3 arguments (and taking modulo after each multiplication/addition) exists, so one needs to build ones own version
	def __power_substitute(self, array, exponent, modulus):
		binary = bin(exponent)[2:]
		prod = 1
		for i in binary:
			prod = (prod * prod) % modulus
			if i == '1':
				prod = (prod * array) % modulus
		return prod

	def __encrypt(self, M):	
		logger.info('RSA: encrypting the plaintext \n' + str(M))	
		N, e = self.public_key
		Encrypted_M = self.__power_substitute(M, e, N) 
		logger.info('RSA: encrypted plaintext \n' + str(Encrypted_M))	
		return Encrypted_M
	
	def __decrypt(self, C, private_key):
		logger.info('RSA: decrypting the ciphertext \n' + str(C))
		N, e = self.public_key
		decrypted_C = self.__power_substitute(C, private_key, N) 
		logger.info('RSA: decrypted ciphertext \n' + str(decrypted_C))
		return decrypted_C
				
	def encode_and_encrypt(self, M):
		return self.__encrypt(self.__encode(M))
		
	def decrypt_and_decode(self, C, private_key):
		return self.__decode(self.__decrypt(C, private_key))
		
# Sadly one cannot just use the original RSA decryption function with HNP as the operation pow with 3 arguments cannot be handled by the HNP compilation function nor can the operations // or % be so.
# Therefore one implements a substitute function of pow with 3 arguments that can be handled by HNP
# Furthermore, one saves the private key as a numpy array, as a conversion to byte array will not be possible as above homomorphically and equality tests like ... % 2 == 1 take time (even after implementation of %) homomorphically	
# Additionally one must provide N as argument to the HNP compiled decryption function - as there is a cap on floats and it is not known how specify parameters of being integers, one is also saving N as an narray (but in this case, one would like to get rid of the narray in the HNP compiled version and write it as an int at some point in the future)
		
	def big_int_to_narray(self, private_key):
		logger.info('RSA: converting the private key to narray \n' + str(private_key))
		string = bin(private_key)[2:]
		new_string=""
		for i in string:
			new_string = new_string + i + " "
		narray = np.fromstring(new_string, dtype=int, sep=' ')
		logger.info('RSA: converted private key to narray \n' + str(narray))
		return narray
	
	#This function only exists for intermediate debugging reasons
	def __moduloTEST(self, array):
		#logger.info('RSA: Computing mod N of the array \n' + str(array))
		N, e = self. public_key
		array_mod_N = array - N * (np.floor(array / N))	
		#logger.info('RSA: Computed mod N \n' + str(array_mod_N) + "\n which should also be \n" +  str(array % N))
		return array_mod_N
	
	#This function only exists for intermediate debugging reasons
	def __narray_decryptTEST(self, C, private_key_array):
		logger.info('RSA: decrypting the ciphertext with private key being the array \n' + str(private_key_array))
		logger.info('RSA: the ciphertext is \n' + str(C))
		prod = 1
		for i in private_key_array:
			prod = self.__moduloTEST(prod * prod)
			dummy = C ** i
			prod = self.__moduloTEST(prod * dummy)
		logger.info('RSA: decrypted ciphertext \n' + str(prod))
		return prod
		
	#This function only exists for intermediate debugging reasons	
	def narray_decrypt_and_decodeTEST(self, C, private_key_array):
		return self.__decode(self.__narray_decryptTEST(C, private_key_array))
		
	def __modulo(self, array, N):
		#logger.info('RSA: Computing mod N (as array) of the array \n' + str(array))
		#logger.info('RSA: N is \n' + str(N))		
		array_mod_N = array - N * (np.floor(array / N))	
		#logger.info('RSA: Computed mod N \n' + str(array_mod_N) + "\n which should also be \n" +  str(array % N))
		return array_mod_N
		
	def __narray_decrypt(self, C, private_key_array, N):
		logger.info('RSA: decrypting the ciphertext with private key being the array \n' + str(private_key_array))
		logger.info('RSA: the ciphertext is \n' + str(C))
		prod = 1
		for i in private_key_array:
			prod = self.__modulo(prod * prod, N)
			dummy = i*C + (1-i)*1           #dummy = C ** i seems to be not compiled
			prod = self.__modulo(prod * dummy, N)
		logger.info('RSA: decrypted ciphertext \n' + str(prod))
		return prod
		
	def __narray_decode(self, M, N):
		logger.info('RSA: decoding the message \n' + str(M))
		decoded_M = M/(N-1)
		logger.info('RSA: decoded message \n' + str(decoded_M))
		return decoded_M
		
	def narray_decrypt_and_decode(self, C, private_key_array, N_array):
		N = 0
		for i in N_array:
			N = N * 2
			N = N + i
		return self.__narray_decode(self.__narray_decrypt(C, private_key_array, N), N)
		
	def store_public(self, path):
		with open(path, 'w') as f:
			f.write(str(self.public_key))
		
	def store_public_private(self, path, private_key):	
		self.store_public(path)
		with open(path, 'a') as f:
			f.write("\n"+str(private_key))
			
	def __string_to_pair(self, string):
		a_string, b_string = string[1:-2].split(", ")
		a = int(a_string)
		b = int(b_string)
		return a, b
				
	def load_public(self, path):
		with open(path, 'r') as f:
			public_key_string = f.readline()
			self.public_key = self.__string_to_pair(public_key_string)
			
	def load_public_private(self, path):
		with open(path, 'r') as f:
			public_key_string = f.readline()
			self.public_key = self.__string_to_pair(public_key_string)
			private_key_string = f.readline()
			private_key = int(private_key_string)
			return private_key

# The following provides a way to test out differences between pow and power_substitute
if __name__ == "__main__":
	RSA_tool = RSA_Tool()
	private_key = RSA_tool.keygen()
	
	array = np.random.rand(3)
	
	array_enc = RSA_tool.encode_and_encrypt(array)
	
	array_dec = RSA_tool.decrypt_and_decode(array_enc, private_key)
	private_key_array = RSA_tool.big_int_to_narray(private_key)
	array_dec2 = RSA_tool.narray_decrypt_and_decodeTEST(array_enc, private_key_array)
	N, e = RSA_tool.public_key
	N_array = RSA_tool.big_int_to_narray(N)
	array_dec3 = RSA_tool.narray_decrypt_and_decode(array_enc, private_key_array, N_array)
	

	path = "test.txt"
	RSA_tool.store_public_private(path, private_key)
	RSA_tool.load_public_private(path)
	
#Problem still so far - cannot use ** have to use square and multiply and modulo N after each multiplication


# Sadly, also this is not enough for large security parameters.... -> save secret key not as a number but as a narray of bytes.
