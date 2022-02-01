import numpy as np
import functions
import logging
from loguru import logger

class Face_feature_server:
		
	def __init__(self):
		logger.info('Face_feature_server: initiation - started')
		self.public_key = None
		self.enc_stored_features = dict()
		logger.info('Face_feature_server: initiation - done')	
	
	# Right now, this function takes as parameter the keypair for TFHE used to secure confidentiality of the stored features because TFHE implements only private key encryption so far and the encryption must be done on the server as encryption of parameters one by one is not possible yet. This problem will be fixed in concrete-numpy in the near future. Then, one can jus get the public key from the main key server over an authenticated channel and there is no need to give both keys as parameter here. Therefore, one just calls it public_key to indicate what one wants later on.	
	def import_public_server_key(self, public_key):	
		logger.info('Face_feature_server: import of public key for feature encryption from face feature server - started')
		self.public_key = public_key		
		logger.info('Face_feature_server: import of public key for feature encryption from face feature server - done')
		
	def export_public_server_key(self):
		logger.info('Face_feature_server: sending public server keys to client - started')
		logger.info('Face_feature_server: sent public server keys to client - done')
		return self.public_key
	
	# The baseline here can only save one feature per username.				
	def __enroll(self, username, enc_feature):
		logger.info('Face_feature_server: enrollment - started on this side')
		if self.enc_stored_features.get(username) == None:
			self.enc_stored_features[username] = []
		self.enc_stored_features[username].insert(0, enc_feature)
		logger.info('Face_feature_server: enrollment - done on this side')
		return
		
	def __authenticate(self, username, enc_test_feature):
		logger.info('Face_feature_server: authentication - started on this side')
		enc_stored_feature = self.enc_stored_features[username][0]
		#print("Expected answer after encryption")
		#print(functions.decision(enc_stored_feature, enc_test_feature))
		print("Simulated answer after encryption")
		print(functions.hom_decision.simulate(enc_stored_feature, enc_test_feature))
		#print("Encrypt and run answer after encryption\n")
		#print(functions.hom_decision.encrypt_and_run(self.public_key, enc_stored_feature, enc_test_feature))
		really_enc_stored_feature, really_enc_test_feature = self.public_key.encrypt(enc_test_feature, enc_stored_feature)
		logger.info('Face_feature_server: authentication - started actual homomorphic evaluation of decision on this side')
		enc_answer = functions.hom_decision.run(self.public_key.public_keys, really_enc_stored_feature, really_enc_test_feature)
		print("Real answer after encryption")
		print(self.public_key.decrypt(enc_answer))	
		logger.info('Face_feature_server: authentication - done with actual homomorphic evaluation of decision on this side')
		logger.info('Face_feature_server: authentication - done on this side')
		return enc_answer
		
	def process_message_1(self, message):
		logger.info('Face_feature_server: processing message - started')
		if len(message) == 2:
			username, enc_feature = message
			self.__enroll(username, enc_feature)
			return
		username, enc_feature, public_local_keys = message
		enc_answer = self.__authenticate(username, enc_feature)
		logger.info('Face_feature_server: asking main key server for key switch - started')
		return (enc_answer, public_local_keys)
		
	def process_message_2(self, rekeyed_answer):	
		logger.info('Face_feature_server: asking main key server for key switch - done')
		logger.info('Face_feature_server: processing message - done')		
		return rekeyed_answer
		
		
		
		
	
