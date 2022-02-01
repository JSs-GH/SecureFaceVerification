import logging
from loguru import logger

# For a description of this dummy class see Main_key_server

class Sub_key_server:
	
	def __init__(self, partial_keys):
		logger.info('Sub key server: initiating')
		self.partial_keys = partial_keys	# actually nothing in the simulation
		logger.info('Sub key server: initiated')
		
	def __encrypt_by_local_keys(self, local_keys):
		logger.info('Sub key server: encryption of partial private server key by local keys - started')
		partial_key_switching_keys = None
		logger.info('Sub key server: encryption of partial private server key by local keys - done')
		return partial_key_switching_keys
		
	def get_partial_key_switching_keys(self, local_keys):	
		logger.info('Sub key server: getting partial key switching keys - started')		
		logger.info('Sub key server: getting partial key switching keys - done')
		return self.__encrypt_by_local_keys(local_keys)
