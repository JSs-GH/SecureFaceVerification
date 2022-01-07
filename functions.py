#right now, only one stored feature and one test feature at a time are supported

import hnumpy as hnp
import numpy as np

treshold = 0.5
feature_size = 128

def decryption(keys, cipher_text):
	decrypt = PKCS1_OAEP.new(key=keys)
	decrypted_message = decrypt.decrypt(cipher_text)
	return decrypted_message
    
def dissimilarity_measure(x,y):
	return 1 - np.sum(np.multiply(x,y))
	
def decision(d):
	if d > treshold:
		return True
	else:
		return False

def all(keys, cipher_text, keys2, ciphertext_2):
	test_feature = decryption(keys, cipher_text)
	stored_feature = decryption(keys2, ciphertext_2)
	d = dissimilarity measure(test_feature, stored_feature)
	return decision(d)

hom_all = hnp.compile_fhe(
    all,
    {"keys": hnp.encrypted(), #possible problem here
    "cipher_text": hnp.encrypted_ndarray(bounds=(0,1), shape=(feature_size,)), 
    "stored_feature": hnp.encrypted_ndarray(bounds=(0,1), shape=(feature_size,))}
)
