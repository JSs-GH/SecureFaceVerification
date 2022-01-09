# HNP does not allow to serialize keys yet. Therefore, one is simulating here, every time parties switch, there is a communication between these parties exchanging parameters
import reenserver
import ffserver
import client
import authclient


#Initialisation
reencryption_server = Reenserver()
reencryption_server.generate_server_keys()
public_server_keys = reencryption_server.send_public_server_key() #This action may be asked by the part of the Face Feature Server before the cryptography part face_feature_server here is started

face_feature_server = Ffserver(public_server_keys)
client = Client()

reencryption_server.generate_and_distribute_local_keys()
face_feature_server.load_and_combine()
client.load_keys()

#Enrollment
#Enrollment Client side
store_feature = numpy.load("store_feature.npy")
store_feature = numpy.squeeze(store_feature)
username = "Heinz51"
username, encrpytion, public_local = client.process(username, store_feature)

#Face Feature Server side
face_feature_server.enroll(username, encrpytion, public_local)


#Initialisation
authclient = AuthClient()
reencryption_server.generate_and_distribute_local_keys()
face_feature_server.load_and_combine()
authclient.load_keys()

#Authentication
#Authentication Client side
test_feature = numpy.load("test_feature.npy")
test_feature = numpy.squeeze(test_feature)
username = "Heinz51" #also test with "Heinz52"
username, encr_test_feature, public_test_local_key = authclient.process(username, test_feature)

#Face Feature Server side
public_stored_local_key, encr_stored_feature = face_feature_server.find_encr_stored_feature(username)

#Reencryption Server side
#Now ask Reencryption server to encrypt this a second time - would not be necessary if HNP would provide an ASsymmetric homomorphic scheme
enc2_stored_feature = reencryption_server.encrypt(encr_stored_feature)
#Same for the test feature
enc2_test_feature = reencryption_server.encrypt(encr_test_feature)

#Face Feature Server side
encr_answer = face_feature_server.authenticate(public_test_local_key, enc2_test_feature, public_stored_local_key, enc2_stored_feature)

#Reencryption Server side
encr_loc_answer = reencryption_server.reencrypt(self, encr_answer, public_test_local_key)

#Authentication Client side
print(authclient.answer(enc_loc_answer))
