import functions
import logging
from loguru import logger

class Main_key_server:
	
	# Upon setup, each key server receives the public server key (with which the features are encrypted) and a part of the private key, such that all key servers together can combine their parts, to receive the complete secret key (also homomorphically after encryption by other keys) - at least that is what one wants to simulate here. Because in HNP secret keys cannot be altered (which will be changed at some time for HNPs successor concrete-numpy), the main key server has the complete secret key, the other key servers (here one other) nothing, but one simulates the behavior as if the private key would have been shared in parts as far as possible.
	# The face feature server itself only interacts with the main key server.
	def __init__(self, partial_keys):
		logger.info('Main key server: initiating')
		self.partial_keys = partial_keys	# actually the whole private key in the simulation
		logger.info('Main key server: initiated')
	
	# As described in the face feature server, the face feature server does not only need to get the public server key from the main key server but	also the private one in this simulation, as features must be encrypted on the server in this simulation because HNP does only allow for encryption of all parameters of a function to be evaluated at once.
	def export_public_server_key(self):
		logger.info('Main key server: sending public server keys to the face feature server')
		logger.info('Main key server: sent public server keys to the face feature server')
		return self.partial_keys
	
	# Right now a dummy function, as one cannot alter private keys in HNP. Therefore one cannot get real key switching keys and only simulate the homomorphic key switching later on by decrypting and encrypting again in the functions thereafter.
	def __encrypt_by_local_keys(self, local_public_key):
		logger.info('Main key server: encryption of partial private server key by local public key - started')
		partial_key_switching_keys = self.partial_keys
		logger.info('Main key server: encryption of partial private server key by local public key - done')
		return partial_key_switching_keys
		
	def __combine_partial_key_switching_keys(self, main_partial_key_switching_keys, sub_partial_key_switching_keys):
		logger.info('Main key server: combination of partial key switching keys - started')
		key_switching_keys = main_partial_key_switching_keys
		logger.info('Main key server: combination of partial key switching keys - done')
		return key_switching_keys
	
	# Actually this function does not only receive the local public key here, but also the local private one, because (as explained above) homomorphic key switching is not possible in HNP, so one simulates it here.
	def key_switch_1(self, enc_answer, local_public_key):
		logger.info('Main key server: Key switch from server keys to local keys - started')
		logger.info('Main key server: Asking sub key server for its respective partial key switching keys - started')
		return local_public_key
		
	def key_switch_2(self, enc_answer, local_public_key, sub_partial_key_switching_keys):	
		logger.info('Main key server: Asking sub key server for its respective partial key switching keys - done')
		key_switching_keys = self.__combine_partial_key_switching_keys(self.__encrypt_by_local_keys(local_public_key), sub_partial_key_switching_keys)
		logger.info('Main key server: Simulation of homomorphic key switching - started')
		dummy = key_switching_keys.decrypt(enc_answer)
		reenc_answer = local_public_key.encrypt(dummy)
		logger.info('Main key server: Simulation of homomorphic key switching - done')
		logger.info('Main key server: Key switch from server keys to local keys - done')
		return reenc_answer
