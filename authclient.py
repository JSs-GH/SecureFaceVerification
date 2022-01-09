import rsa
import logging
from loguru import logger

#right now, only one stored feature and one test feature at a time are supported

class AuthClient(Client):		
	def decrypt(self, cipher_text):
		logger.info('Authentication Client: Decrypting ciphertext \n' + str(cipher_text))
		decrypted_message = self.RSA_tool.decrypt_and_decode(cipher_text, self.private_key)
		logger.info('Authentication Client: Decrypted ciphertext \n' + str(decrypted_message))
		return decrypted_message
