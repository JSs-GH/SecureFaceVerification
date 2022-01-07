from Crypto.PublicKey import RSA #maybe this needs to be converted to our own RSA-algorithm in the end which only uses operations (power, modulo) that evaulate can handle

#right now, only one stored feature and one test feature at a time are supported

class Client:
	key_path = 'c_private_pem.pem' #The admin is reponsible to import the content of the file 'new_c_private_pem.pem' to this file after new local keys have been generated in the reenserver
	
	def __init__(self):
		self.keys = None
		print("Client initiated")
		
	def load_keys(self):
		self.keys = RSA.import_key(open(key_path, 'r').read())
		
	def __export_public_key(self):
		return self.keys.publickey()
		
	def __encrypt(self, feature):
		cipher = PKCS1_OAEP.new(key=self.keys)
		cipher_text = cipher.encrypt(feature.tobytes('C'))
		return cipher_text()
		
	def process(self, username, feature):
		return (username, __export_public_key(), __encrypt(feature))
		
