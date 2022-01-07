import functions

class Ffserver:
	
	pubkey_path = 'ffs_public_pem.p'
	encr_loc_privkey_path = 'ffs_encr_loc_privates_pem.p'
	new_encr_loc_privkey_path = 'ffs_new_encr_loc_privates_pem.p' #The admin is reponsible to import the content of the file 'ks_encr_loc_privkey_path.p' to this file after new local keys have been generated in the reenserver
	encr_features_path = 'ffs_encr_features.p'
	
	def __init__(self):
		self.public_key = None
		self.encr_local_private_keys = {}
		self.encrypted_features = {}
		print("Face feature server initiated")
		
	def load(self):
		self.public_key = pickle.load(open(pubkey_path, "rb"))
		self.encr_local_private_keys = pickle.load(open(encr_loc_privkey_path, "rb"))
		self.encrypted_features = pickle.load(open(encr_features_path, "rb"))
		
	def load_and_combine(self):
		public_key, enc = pickle.load(open(new_encr_loc_privkey_path, "rb"))
		self.encr_local_private_keys[public_key]=enc
		pickle.dump(self.encr_local_private_keys, open(encr_loc_privkey_path, "wb"))
				
	def enroll(self, username, local_public_key, encrypted_feature):
		self.encrypted_features[username]=(local_public_key, encrypted_feature)
		pickle.dump(self.encrypted_features, open(encr_features_path, "wb"))
		
	def find_encr_stored_feature(self, username):
		return self.encrypted_features[username] #public key of the computer used for enrollment + with this key encrypted feature
	
	def authenticate(self, test_local_public_key, encrypted_test_feature, stored_local_public_key, encrypted_stored_feature):		
		stored_encr_local_priv_key = self.encr_local_private_keys[stored_local_public_key]
		test_encr_local_priv_key = self.encr_local_private_keys[test_local_public_key]
		encr_answer = hom_all(self.public_key, test_encr_priv_key, encrypted_test_feature, test_encr_priv_key, encrypted_stored_feature)
		return encr_answer
