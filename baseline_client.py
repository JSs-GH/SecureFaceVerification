import baseline_functions
import logging
from loguru import logger

#right now, only one stored feature and one test feature at a time are supported

class Baseline_client:

	# Right now, this function takes as parameter the keypair for TFHE that is shared among all clients to secure confidentiality of the stored features because the private key cannot be saved in HNP. This problem will be fixed in concrete-numpy in the near future allowing serialization of private keys. Then, one can read the keys from a file and there is no need to give them as parameter here.
	def __init__(self, keys):
		logger.info('Baseline_client: initiation - started')
		self.keys = keys
		logger.info('Baseline_client: initiation - done')
	
	# Also, HNP does not allow yet to encrypt parameters of the function to be homomorphically evaluated step by step. Therefore in this SIMULATION, one encrypts test feature and stored feature together on the server before computing the dissimilarity measure.	
	def __encrypt_feature(self, feature):
		logger.info('Baseline_client: simulation of encryption of a feature - started')
		logger.info('Baseline_client: simulation of encryption of a feature - done')
		return feature
		
	def __decrypt_dissimilarity_measure(self, enc_dis):		
		logger.info('Baseline_client: decryption of dissimilarity measure - started')
		decryption = self.keys.decrypt(enc_dis)
		logger.info('Baseline_client: decryption of dissimilarity measure - done')
		return decryption
		
	def enroll(self, username, feature):
		logger.info('Baseline_client: enrollment - started on this side')
		message = (baseline_functions.enroll, username, self.__encrypt_feature(feature))		
		logger.info('Baseline_client: enrollment - done on this side')
		return message
		
	def authenticate_1(self, username, feature):
		logger.info('Baseline_client: authentication - started on this side')
		message = (baseline_functions.authenticate, username, self.__encrypt_feature(feature))
		return message
		
	def authenticate_2(self, encrypted_dissimilarity_measure):
		dissimilarity_measure = self.__decrypt_dissimilarity_measure(encrypted_dissimilarity_measure)		
		logger.info('Baseline_client: ' + baseline_functions.colors.WARNING + 'actual dissimilarity measure' + baseline_functions.colors.ENDC + ' after decryption on the client side ' + baseline_functions.colors.WARNING + str(dissimilarity_measure) + baseline_functions.colors.ENDC)
		answer = baseline_functions.treshold(dissimilarity_measure)		
		logger.info('Baseline_client: authentication - done on this side')
		return answer
