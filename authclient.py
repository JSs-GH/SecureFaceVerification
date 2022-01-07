from Crypto.PublicKey import RSA #maybe this needs to be converted to our own RSA-algorithm in the end which only uses operations (power, modulo) that evaulate can handle

#right now, only one stored feature and one test feature at a time are supported

class AuthClient(Client):		
	def answer(self, cipher_text):
		decrypt = PKCS1_OAEP.new(key=self.keys)
		decrypted_message = decrypt.decrypt(cipher_text)
		return decrypted_message
