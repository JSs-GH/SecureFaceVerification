import rsa
import logging
from loguru import logger
#right now, only one stored feature and one test feature at a time are supported

class Client:
	keys_path = 'c_keys_pem.pem' #The admin is reponsible to import the content of the file 'ks_new_c_keys_pem.pem' to this file after new local keys have been generated in the reenserver
	
	def __init__(self):
		logger.info('Client: initiating')
		self.RSA_tool = rsa.RSA_Tool()
		self.private_key = None
		logger.info('Client: initiated')
		
	def load_keys(self):
		logger.info('Client: loading keys')
		self.private_key = RSA_tool.load_public_private(keys_path)
		logger.info('Client: loaded keys \n' + str(self.RSA_tool.public_keys) + "\n" + str(self.private_key))
		
	def __export_public_key(self):
		logger.info('Client: exporting public key')
		return self.RSA_tool.public_key
		logger.info('Client: exported public key \n' + str(self.RSA_tool_public_key))
		
	def __encrypt(self, feature):
		logger.info('Client: encrypting feature \n' + str(feature))
		cipher_text = RSA_tool.encode_and_encrypt(feature)
		logger.info('Client: encrypted feature \n' + str(cipher_text))
		return cipher_text
		
	def process(self, username, feature):
		return (username, __export_public_key(), __encrypt(feature))
		
