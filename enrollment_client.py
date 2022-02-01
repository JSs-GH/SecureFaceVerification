import hnumpy as hnp
import numpy as np
import functions
import logging
from loguru import logger

# One assumes a authenticated, encrypted channel between all parties

class Enrollment_client:
	
	def __init__(self):
		logger.info('Enrollment_client: initiation - started')
		self.server_keys = None
		logger.info('Enrollment_client: initiation - done')
	
	# This function takes as input the public key, the features on the server should be encrypted with. Right now, this function takes as parameter the keypair for TFHE that is prote to secure confidentiality of the stored features because the private key cannot be saved in HNP.  allowing serialization of private keys. Then, one can read the keys from a file and there is no need to give them as parameter here.
	def import_public_server_key(self, public_key):	
		logger.info('Enrollment_client: import of public key for feature encryption from face feature server - started')
		self.server_keys = public_key		
		logger.info('Enrollment_client: import of public key for feature encryption from face feature server - done')
		
	def __compute_mean(self, features):
		logger.info('Enrollment_client: normed mean computation over several features - started')
		features_matrix = np.array(list(features))
		mean = np.mean(features_matrix, axis=0)
		new_feature = mean/np.linalg.norm(mean)
		logger.info('Enrollment_client: normed mean computation over several features - done')
		return new_feature	
		
	# Because HNP does only allow for encryption of all parameters of the function to homomorphically evaluate at once, this function does in fact not use the stored public key to encrypt, but rather returns the feature in plain. This problem will be fixed in concrete-numpy (successor of HNP) in the near future.
	def __encrypt_feature(self, feature):
		logger.info('Enrollment_client: simulation of encryption of a feature - started')
		logger.info('Enrollment_client: simulation of encryption of a feature - done')
		return feature	
					
	# Here, the server does not a specified message type (enroll or authenticate) because authentication messages are not just pairs but triples
	def enroll(self, username, features):
		logger.info('Enrollment_client: enrollment - started on this side')
		message = (username, self.__encrypt_feature(self.__compute_mean(features)))		
		logger.info('Enrollment_client: enrollment - done on this side')
		return message
