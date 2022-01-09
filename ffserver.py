import logging
from loguru import logger
import functions

class Ffserver:
	encr_rsa_path = 'ffs_encr_rsa_pem.p'
	new_encr_rsa_path = 'ffs_new_encr_rsa_pem.p' #The admin is reponsible to import the content of the file 'ks_encr_rsa_path.p' to this file after new local rsa keys have been generated in the reenserver
	encr_features_path = 'ffs_encr_features.p'
	
	def __init__(self, public_key = None):
		logger.info('Face Feature Server: initiating')
		self.public_key = public_key			# The public server key - can be eitherbe given when initiating the instance or later on
		self.encr_rsa = {}				# A map from RSA public keys to pairs of encrpytions of RSA private keys and encryption of N
		self.encrypted_features = {}	# A map from usernames to the RSA public key and the so encrypted feature stored w.r.t. this user
		logger.info('Face feature server: initiated')
		
	def receive_public_server_key(public_key):
		logger.info('Face Feature Server: receiving public server key for homomorphic evaluation from the reencryption server')
		self.public_key = public_key
		logger.info('Face Feature Server: received public server key for homomorphic evaluation from the reencryption server')
		
	def load(self):
		logger.info('Face Feature Server: loading public server key, map of RSA public keys to encryptions of RSA private keys, map of usernames to encrypted features')
		self.public_key = pickle.load(open(pubkey_path, "rb"))
		self.encr_rsa = pickle.load(open(encr_rsa_path, "rb"))
		self.encrypted_features = pickle.load(open(encr_features_path, "rb"))
		logger.info('Face Feature Server: loaded public server key, map of RSA public keys to encryptions of RSA private keys, encrypted features')
		
	def load_and_combine(self):
		logger.info('Face Feature Server: loading a new pair of RSA public key and encryption of RSA private key and combining it with the saved map')
		public_key, enc_rsa_priv_key, enc_rsa_N = pickle.load(open(new_encr_rsa_path, "rb"))
		self.encr_rsa_keys[public_key]=enc_rsa_priv_key, enc_rsa_N 
		pickle.dump(self.encr_rsa_keys, open(encr_rsa_path, "wb"))
		logger.info('Face Feature Server: loaded a new pair of RSA public key and encryption of RSA private key and combined it with the saved map')
				
	def enroll(self, username, rsa_public_key, encrypted_feature):
		logger.info('Face Feature Server: deleting old stored feature for given username and saving new one')
		self.encrypted_features[username]=(rsa_public_key, encrypted_feature)
		pickle.dump(self.encrypted_features, open(encr_features_path, "wb"))
		logger.info('Face Feature Server: deleted old stored feature for given username and saved new one')
		
	def find_encr_stored_feature(self, username):
		logger.info('Face Feature Server: finding saved feature w.r.t. to given username')
		return self.encrypted_features[username]
		logger.info('Face Feature Server: found saved feature w.r.t. to given username')
	
	def authenticate(self, test_rsa_public_key, test_double_enc_feature, stored_rsa_public_key, stored_double_encrypted_feature):	
		logger.info('Face Feature Server: authenticating by \n 1.) looking up the encrypted RSA data w.r.t. the RSA public key from the client trying to authenticate and the encrypted RSA data w.r.t. the RSA public key w.r.t. the typed in username (which was found together with the respective feature using the function find_encr_stored_feature before) \n 2.) Homomorphically computing the dissimilarity measure of the two features and deciding if login is possible')	
		stored_encr_rsa_priv_key, stored_encr_rsa_N = self.encr_rsa[stored_rsa_public_key]
		test_encr_rsa_priv_key, test_encr_rsa_N = self.encr_rsa[test_rsa_public_key]
		encr_answer = hom_all(self.public_key, test_double_enc_feature, test_encr_rsa_priv_key, test_encr_rsa_N, stored_double_encrypted_feature, stored_encr_rsa_priv_key, stored_encr_rsa_N)
		logger.info('Face Feature Server: aecision if login must be done computed')	
		return encr_answer
