from Crypto.PublicKey import RSA
import pickle
import time
import os
import functions

class Reenserver:
	delete_time = 30 #After the admin had time to save the generated local keys, this server should not be allowed to own these
	key_strength = 1024

	encr_loc_privkey_path = 'ks_encr_loc_privkey_path.p'
	new_c_private_key_path = 'new_c_private_pem.pem'  
	
	def __init__(self):
		self.secret_server_key = None
		print("KeyServer ready")
		
	def generate_server_keys(self):
		context = hom_all.create_context()
		self.secret_server_key = context.keygen()
		
	def __distribute_local_keys(self, private_key):
		private_pem = private_key.export_key().decode()
		with open(new_c_private_key_path, 'w') as pr:
    		pr.write(private_pem)
    	pair = (private_key.publickey(), self.secret_server_key.encrypt(private_key))
    	pickle.dump(pair, open(encr_loc_privkey_path, "wb"))
    	time.sleep(delete_time)
    	os.remove(encr_loc_privkey_path)
    	os.remove(new_c_private_key_path)
		
	def generate_and_distribute_local_keys(self):
		private_key = RSA.generate(key_strength)
		__distribute_local_keys(private_key)
		
	def load_and_distribute_local_keys(self): #loads old client keys provided by the some admin for a short periode of time (for example for case that all servers and clients where down and one does not want to reinitiate the whole Face feature server database) - only the secret_server_key (and respective encryptions) change(s) in this case when building a new instance of this class
		private_key = pr_key = RSA.import_key(open(new_c_private_key_path, 'r').read())
		__distribute_local_keys(private_key)
    	
    def encrypt(self, text): #function only necessary as long as HNP is only a SYMMETRIC homomorphic scheme (meaning as long as encryption needs the secret key and the double encryption can therefore not be done by the Face Feature Server)
    	return self.secret_server_keys.encrypt(text)
	
	def reencrypt(self, cipher_text, loc_publ_key):
		answer = self.secret_server_keys.decrypt(cipher_text)
		cipher = PKCS1_OAEP.new(key=loc_publ_key)
		reenc_answer = cipher.encrypt(answer)
		return reenc_answer
