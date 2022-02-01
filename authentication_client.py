import numpy as np
import functions
import logging
from loguru import logger

class Authentication_client:

	def __init__(self):
		logger.info('Authentication_client: initiation - started')
		context = functions.hom_identity.create_context()
		self.local_keys = context.keygen()
		self.server_keys = None
		logger.info('Authentication_client: initiation - done')
		
	def import_public_server_key(self, public_key):	
		logger.info('Authentication_client: import of public key for feature encryption from face feature server - started')
		self.server_keys = public_key		
		logger.info('Authentication_client: import of public key for feature encryption from face feature server - done')
		
	def __compute_mean(self, features):
		logger.info('Authentication_client: normed mean computation over several features - started')
		features_matrix = np.array(list(features))
		mean = np.mean(features_matrix, axis=0)
		new_feature = mean/np.linalg.norm(mean)
		logger.info('Authentication_client: normed mean computation over several features - done')
		return new_feature	
		
	# Because HNP does only allow for encryption of all parameters of the function to homomorphically evaluate at once, this function does in fact not use the stored public key to encrypt, but rather returns the feature in plain. This problem will be fixed in concrete-numpy (successor of HNP) in the near future.
	def __encrypt_feature(self, feature):
		logger.info('Authentication_client: simulation of encryption of a feature - started')
		logger.info('Authentication_client: simulation of encryption of a feature - done')
		return feature	
		
	def __decrypt_answer(self, enc_answer):		
		logger.info('Authentication_client: decryption of answer with local keys - started')
		answer = self.local_keys.decrypt(enc_answer)
		logger.info('Authentication_client: decryption of answer with local keys - done')
		return answer
		
	# Actually this function should not return also the local keys, but only the public local keys. Sadly, HNP does not support public key encryption (but concrete-numpy will do so) and therefore for the reencryption on the keyserver, one needs to return the local keys (including the porivate local key) in this simulation.
	# Furthermore, having implemented an authenticated channel, one can send the public local key to the server in the beginning, which can store it and then use it throughout the whole scenario. Due to not implementing such a channel in this simulation, one does it as follows:
	def authenticate_1(self, username, features):
		logger.info('Authentication_client: authentication - started on this side')
		message = (username, self.__encrypt_feature(self.__compute_mean(features)), self.local_keys)
		return message
		
	def authenticate_2(self, encrypted_answer):
		answer = self.__decrypt_answer(encrypted_answer)
		# Right now, answer is a numpy array of shape (1,) with its only element being a float value near to 0 (which is interpreted as false) or near to 1 (which is interpreted as true). Therefore:
		answer = answer > 0.5
		logger.info('Authentication_client: ' + functions.colors.WARNING + 'actual answer' + functions.colors.ENDC + ' after decryption on the client side ' + functions.colors.WARNING + str(answer) + functions.colors.ENDC)	
		logger.info('Authentication_client: authentication - done on this side')
		return answer
