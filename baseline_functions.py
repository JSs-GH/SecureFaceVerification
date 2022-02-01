import hnumpy as hnp
import numpy as np

# The following constants are used to prevent misbehavior because of misspellings in the code:
authenticate 	= "authenticate"
enroll 			= "enroll"

feature_size = 128

# Having a tool that outputs values between 0 and 1 for classification purposes, one typically interprets values below 0.3 as 0, values above 0.7 as 1 and values between as unclear.
# The dissimilarity measure outputting values between 2 (totally not equal features) and 0 (equal features) and the interest being a minimization of false positives, one could take the treshold 0.3*2=0.6
# Here one is taking an even sharper treshold because one wants to minimize false positives in our context: 0.1
treshold_value = 0.1

# Computes the dissimilarity measure product using the hadamard product as in the baseline.
def dissimilarity_measure(test_feature, stored_feature):
	return 1 - np.sum(np.multiply(test_feature, stored_feature)) #alternatively: np.dot(test_feature, stored_feature)
	
def treshold(dissimilarity):
	return dissimilarity < treshold_value

# Defines the circuit w.r.t. the decision function, that is used in the homomorphic evaluation on the server.
hom_dissimilarity_measure = hnp.compile_fhe(
    dissimilarity_measure,
    {"test_feature": hnp.encrypted_ndarray(bounds=(-1.05,1.05), shape=(feature_size,)),
     "stored_feature": hnp.encrypted_ndarray(bounds=(-1.05,1.05), shape=(feature_size,))},
     config=hnp.config.CompilationConfig(parameter_optimizer="handselected", bits_of_security=128),
)

class colors:
    WARNING = '\033[93m'
    ENDC = '\033[0m'

