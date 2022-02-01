import hnumpy as hnp
import numpy as np

feature_size = 128

# Instead of computing the dissimilarity measure 1- x^t y, one computes just x^t y and compares this against a treshold.
treshold_value = 0.75

# Identity function needed for the key switch later on
def identity(x):
	return x
	
# Defines the circuit w.r.t. the identity function, that is used in the homomorphic evaluation on the server.
hom_identity = hnp.compile_fhe(
    identity,
    {"x": hnp.encrypted_ndarray(bounds=(-1.5,1.5), shape=(1,))}, 
     config=hnp.config.CompilationConfig(parameter_optimizer="handselected", bits_of_security=128),
)

# Computes the euclidean product using the hadamard product as in the baseline.
def euclidean(test_feature, stored_feature):
	return np.sum(np.multiply(test_feature, stored_feature)) #alternatively: np.dot(test_feature, stored_feature)
	
# Outputs true, if a given value a is greater than the treshold and otherwise false.
def treshold(a):
	return a > treshold_value

# Outputs true, if test_feature and stored_feature are sufficiently equal and otherwise false.
def decision(test_feature, stored_feature):
	return treshold(euclidean(test_feature, stored_feature))

# Defines the circuit w.r.t. the decision function, that is used in the homomorphic evaluation on the server.
hom_decision = hnp.compile_fhe(
    decision,
    {"test_feature": hnp.encrypted_ndarray(bounds=(-1.5,1.5), shape=(feature_size,)),
     "stored_feature": hnp.encrypted_ndarray(bounds=(-1.5,1.5), shape=(feature_size,))},
     config=hnp.config.CompilationConfig(parameter_optimizer="handselected", bits_of_security=128),
)

class colors:
    WARNING = '\033[93m'
    ENDC = '\033[0m'
