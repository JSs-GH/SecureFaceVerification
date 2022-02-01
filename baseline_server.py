import baseline_functions
import logging
from loguru import logger

class Baseline_server:
	
	# Right now, this function takes as parameter the keypair for TFHE that is shared among all clients to secure confidentiality of the stored features because TFHE implements only private key encryption so far and the encryption must be done on the server as encryption of parameters one by one is not possible yet. This problem will be fixed in concrete-numpy in the near future. Then, one can read the public key from a file and there is no need to give both keys as parameter here although one just calls it public_key to indicate what one wants later on.
	def __init__(self, public_key):
		logger.info('Baseline_server: initiation - started')
		self.keys = public_key
		self.stored_features = dict()
		logger.info('Baseline_server: initiation - done')
		
	def process_message(self, message):
		logger.info('Baseline_server: processing message - started')
		message_type, username, feature = message
		if message_type == baseline_functions.enroll:
			answer = self.__enroll(username, feature)
		else:
			answer = self.__authenticate(username, feature)
		logger.info('Baseline_server: processing message - done')
		return answer
	
	# The baseline here can only save one feature per username.				
	def __enroll(self, username, feature):
		logger.info('Baseline_server: enrollment - started on this side')
		self.stored_features[username] = feature
		logger.info('Baseline_server: enrollment - done on this side')
		return
		
	def __authenticate(self, username, test_feature):
		logger.info('Baseline_server: authentication - started on this side')
		stored_feature = self.stored_features.get(username)
		enc_stored_feature, enc_test_feature = self.keys.encrypt(stored_feature, test_feature)		
		logger.info('Baseline_server: authentication - started actual homomorphic evaluation on this side')
		enc_result = baseline_functions.hom_dissimilarity_measure.run(self.keys.public_keys, enc_stored_feature, enc_test_feature)
		logger.info('Baseline_server: authentication - done with actual homomorphic evaluation on this side')
		logger.info('Baseline_server: authentication - done on this side')
		return enc_result
