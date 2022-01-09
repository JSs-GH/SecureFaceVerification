#right now, only one stored feature and one test feature at a time are supported

import hnumpy as hnp
import numpy as np
import rsa

treshold = 0.5
feature_size = 128
rsa_array_length = rsa.bitlength*2
default_RSA_tool = rsa.RSA_Tool()
    
def dissimilarity_measure(x,y):
	return 1 - np.sum(np.multiply(x,y))
	
def decision(d):
	return d > treshold

def all(enc_rsa_ciphertext1, enc_rsa_priv_1, enc_rsa_N_1, enc_rsa_ciphertext2, enc_rsa_priv_2, enc_rsa_N_2):
	encr_test_feature = default_RSA_tool.narray_decrypt_and_decode(enc_rsa_ciphertext1, enc_rsa_priv_1, enc_rsa_N_1)
	encr_stored_feature = default_RSA_tool.narray_decrypt_and_decode(enc_rsa_ciphertext2, enc_rsa_priv_2, enc_rsa_N_2)
	d = dissimilarity_measure(encr_test_feature, encr_stored_feature)
	return decision(d)

hom_all = hnp.compile_fhe(
    all,
    {"enc_rsa_ciphertext1": hnp.encrypted_ndarray(bounds=(-1,2), shape=(feature_size,)),
    "enc_rsa_priv_1": hnp.encrypted_ndarray(bounds=(-1,2), shape=(rsa_array_length,)),
    "enc_rsa_N_1": hnp.encrypted_ndarray(bounds=(-1,2), shape=(rsa_array_length,)),
    "enc_rsa_ciphertext2": hnp.encrypted_ndarray(bounds=(-1,2), shape=(feature_size,)),
    "enc_rsa_priv_2": hnp.encrypted_ndarray(bounds=(-1,2), shape=(rsa_array_length,)),
    "enc_rsa_N_2": hnp.encrypted_ndarray(bounds=(-1,2), shape=(rsa_array_length,))}
)
