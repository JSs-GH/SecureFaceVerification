import rsa
import pickle
import time
import os
import functions

class Reenserver:
	deletion_time = 30 # After the admin had time to save the generated local keys, this server should not be allowed to own these

	encr_rsa_path = 'ks_encr_rsa_path.p'
	new_c_rsa_path = 'ks_new_c_keys_pem.pem'  
	
	def __init__(self):
		logger.info('Reencryption Server: initiating')
		self.secret_server_key = None
		logger.info('Reencryption Server: initiated')
		
	def generate_server_keys(self):
		logger.info('Reencryption Server: generating server keys')
		context = hom_all.create_context()
		self.secret_server_key = context.keygen()
		logger.info('Reencryption Server: generated server keys')
		
	def send_public_server_key(self):
		logger.info('Reencryption Server: sending public server keys')
		return self.secret_server_key.public_key()
		logger.info('Reencryption Server: sent public server keys')
		
	def __distribute_local_keys(self, RSA_tool, rsa_private_key):
		logger.info('Reencryption Server: distributing local RSA data, for the Client all RSA data unencrypted, for the Face Feature Server unencrypted RSA public key and encrypted RSA secret key and N')
		RSA_tool.store_public_private(new_c_rsa_path, rsa_private_key)
		rsa_public_key = RSA_tool.public_key
		N, e = rsa_public_key
		triple = (rsa_public_key, self.secret_server_key.encrypt(RSA_tool.big_int_to_narray(rsa_private_key)), self.secret_server_key.encrypt(RSA_tool.big_int_to_narray(N)))
		pickle.dump(triple, open(encr_loc_privkey_path, "wb"))
		time.sleep(deletion_time)
		os.remove(encr_loc_privkey_path)
		os.remove(new_c_private_key_path)
		logger.info('Reencryption Server: distributed local RSA data, for the Client all RSA data unencrypted, for the Face Feature Server unencrypted RSA public key and encrypted RSA secret key and N')
		
	def generate_and_distribute_local_keys(self):
		logger.info('Reencryption Server: Generating and distributing new local RSA data')
		RSA_tool = rsa.RSA_Tool()
		rsa_private_key = RSA_tool.keygen()
		__distribute_local_keys(RSA_tool, rsa_private_key)
		logger.info('Reencryption Server: Generated and distributed new local RSA data')
		
	def load_and_distribute_local_keys(self): #loads old client keys (one key pair at a moment) provided by the some admin for a short periode of time (for example for case that all servers and clients where down and one does not want to reinitiate the whole Face feature server database) - only the secret_server_key (and respective encryptions) change(s) in this case when building a new instance of this class
		logger.info('Reencryption Server: Loading and distributing old local RSA data')
		RSA_tool = rsa.RSA_Tool()
		rsa_private_key = RSA_tool.load_public_private(open(new_c_private_key_path, 'r').read())
		__distribute_local_keys(RSA.tool, rsa_private_key)
		logger.info('Reencryption Server: Loaded and distributed old local RSA data')
		
	def encrypt(self, text): #function only necessary as long as HNP is only a SYMMETRIC homomorphic scheme (meaning as long as encryption needs the secret key and the double encryption can therefore not be done by the Face Feature Server)
		logger.info('Reencryption Server: Encrypting for others with the secret server key')
		return self.secret_server_keys.encrypt(text)
		logger.info('Reencryption Server: Encrypted for others with the secret server key')
	
	def reencrypt(self, ciphertext, public_key):
		logger.info('Reencryption Server: Reencrypting with the secret server key and public RSA data from clients')
		plaintext = self.secret_server_keys.decrypt(ciphertext)
		RSA_tool = rsa.RSA_Tool(public_key)
		reencryption = RSA_tool.encode_and_encrypt(plaintext)
		logger.info('Reencryption Server: Reencrypted with the secret server key and public RSA data from clients')
		return reencryption
