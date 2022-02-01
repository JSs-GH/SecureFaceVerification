# HNP does not allow to serialize keys yet. Therefore, one is simulating here, every time parties switch, there is a communication between these parties exchanging parameters, this communication is expected to be authenticated and encrypted.
import hnumpy as hnp
import numpy as np
import functions
import main_key_server
import sub_key_server
import face_feature_server
import enrollment_client
import authentication_client
import logging
from loguru import logger

# Initialisation
logger.info('Simulation: key generation - started')
context = functions.hom_decision.create_context()
keys = context.keygen()
logger.info('Simulation: key generation - done')

# Key distribution
# Right now, the main key server receives the whole secret server key and the sub key server None as HNP does not allow altering private keys.
main_partial_keys = keys
sub_partial_keys = None
logger.info('Simulation: partial key distribution to key servers - started')
main_key_server = main_key_server.Main_key_server(main_partial_keys)
sub_key_server = sub_key_server.Sub_key_server(sub_partial_keys)
logger.info('Simulation: partial key distribution to key servers - done')

logger.info('Simulation: key distribution to face feature server - started')
public_key = main_key_server.export_public_server_key()
face_feature_server = face_feature_server.Face_feature_server()
face_feature_server.import_public_server_key(public_key)
logger.info('Simulation: key distribution to face feature server - done')

logger.info('Simulation: key distribution to clients - started')
public_key = face_feature_server.export_public_server_key()
enrollment_client = enrollment_client.Enrollment_client()
enrollment_client.import_public_server_key(public_key)

public_key = face_feature_server.export_public_server_key()
authentication_client = authentication_client.Authentication_client()
authentication_client.import_public_server_key(public_key)
logger.info('Simulation: key distribution to clients - done')

#input()

# Name and Feature collection for later enrollment and authentication simulations
username_1 = 'Karl-Heinz'
username_2 = 'Agatha'
#feature_1 = np.random.uniform(-1, 1, (functions.feature_size, ))
feature_1 = np.zeros(functions.feature_size)
feature_1[0]=1
#feature_1 = feature_1/np.linalg.norm(feature_1)
feature_1 = [feature_1]
#feature_2 = np.random.uniform(-1, 1, (functions.feature_size, ))
feature_2 = np.zeros(functions.feature_size)
feature_2[3]=1
#feature_2 = feature_2/np.linalg.norm(feature_2)
feature_2 = [feature_2]

# Enrollment
logger.info('Simulation: enrollment simulation on enrollment client for ' + username_1 + ' with feature of ' + username_1 + ' - started')
message = enrollment_client.enroll(username_1, feature_1)
face_feature_server.process_message_1(message)
logger.info('Simulation: enrollment simulation on enrollment client for ' + username_1 + ' with feature of ' + username_1 + ' - done')

logger.info('Simulation: enrollment simulation on enrollment client for ' + username_2 + ' with feature of ' + username_2 + ' - started')
message = enrollment_client.enroll(username_2, feature_2)
face_feature_server.process_message_1(message)
logger.info('Simulation: enrollment simulation on enrollment client for ' + username_2 + ' with feature of ' + username_2 + ' - done')

# Authentication
logger.info('Simulation: authentication simulation on authentication client for ' + username_1 + ' with feature of ' + username_1 + ' - started')
message = authentication_client.authenticate_1(username_1, feature_1)
enc_answer, public_local_key = face_feature_server.process_message_1(message)
public_local_key_for_sub = main_key_server.key_switch_1(enc_answer, public_local_key)
sub_partial_key_switching_keys = sub_key_server.get_partial_key_switching_keys(public_local_key_for_sub)
reenc_answer = main_key_server.key_switch_2(enc_answer, public_local_key, sub_partial_key_switching_keys)
rekeyed_answer = face_feature_server.process_message_2(reenc_answer)
plaintext_answer = functions.treshold(np.dot(feature_1[0], feature_1[0]))
logger.info('Simulation: ' + functions.colors.WARNING + 'expected answer' + functions.colors.ENDC + ' after decryption on the client side ' + functions.colors.WARNING + str(plaintext_answer) + functions.colors.ENDC)
answer = authentication_client.authenticate_2(rekeyed_answer)
logger.info('Simulation: authentication simulation on authentication client for ' + username_1 + ' with feature of ' + username_1 + ' - done with ' + functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + functions.colors.ENDC)

logger.info('Simulation: authentication simulation on authentication client for ' + username_1 + ' with feature of ' + username_2 + ' - started')
message = authentication_client.authenticate_1(username_1, feature_2)
enc_answer, public_local_key = face_feature_server.process_message_1(message)
public_local_key_for_sub = main_key_server.key_switch_1(enc_answer, public_local_key)
sub_partial_key_switching_keys = sub_key_server.get_partial_key_switching_keys(public_local_key_for_sub)
reenc_answer = main_key_server.key_switch_2(enc_answer, public_local_key, sub_partial_key_switching_keys)
rekeyed_answer = face_feature_server.process_message_2(reenc_answer)
plaintext_answer = functions.treshold(np.dot(feature_2[0], feature_1[0]))
logger.info('Simulation: ' + functions.colors.WARNING + 'expected answer' + functions.colors.ENDC + ' after decryption on the client side ' + functions.colors.WARNING + str(plaintext_answer) + functions.colors.ENDC)
answer = authentication_client.authenticate_2(rekeyed_answer)
logger.info('Simulation: authentication simulation on authentication client for ' + username_1 + ' with feature of ' + username_2 + ' - done with ' + functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + functions.colors.ENDC)

logger.info('Simulation: authentication simulation on authentication client for ' + username_2 + ' with feature of ' + username_1 + ' - started')
message = authentication_client.authenticate_1(username_2, feature_1)
enc_answer, public_local_key = face_feature_server.process_message_1(message)
public_local_key_for_sub = main_key_server.key_switch_1(enc_answer, public_local_key)
sub_partial_key_switching_keys = sub_key_server.get_partial_key_switching_keys(public_local_key_for_sub)
reenc_answer = main_key_server.key_switch_2(enc_answer, public_local_key, sub_partial_key_switching_keys)
rekeyed_answer = face_feature_server.process_message_2(reenc_answer)
plaintext_answer = functions.treshold(np.dot(feature_1[0], feature_2[0]))
logger.info('Simulation: ' + functions.colors.WARNING + 'expected answer' + functions.colors.ENDC + ' after decryption on the client side ' + functions.colors.WARNING + str(plaintext_answer) + functions.colors.ENDC)
answer = authentication_client.authenticate_2(rekeyed_answer)
logger.info('Simulation: authentication simulation on authentication client for ' + username_2 + ' with feature of ' + username_1 + ' - done with ' + functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + functions.colors.ENDC)

logger.info('Simulation: authentication simulation on authentication client for ' + username_2 + ' with feature of ' + username_2 + ' - started')
message = authentication_client.authenticate_1(username_2, feature_2)
enc_answer, public_local_key = face_feature_server.process_message_1(message)
public_local_key_for_sub = main_key_server.key_switch_1(enc_answer, public_local_key)
sub_partial_key_switching_keys = sub_key_server.get_partial_key_switching_keys(public_local_key_for_sub)
reenc_answer = main_key_server.key_switch_2(enc_answer, public_local_key, sub_partial_key_switching_keys)
rekeyed_answer = face_feature_server.process_message_2(reenc_answer)
plaintext_answer = functions.treshold(np.dot(feature_2[0], feature_2[0]))
logger.info('Simulation: ' + functions.colors.WARNING + 'expected answer' + functions.colors.ENDC + ' after decryption on the client side ' + functions.colors.WARNING + str(plaintext_answer) + functions.colors.ENDC)
answer = authentication_client.authenticate_2(rekeyed_answer)
logger.info('Simulation: authentication simulation on authentication client for ' + username_2 + ' with feature of ' + username_2 + ' - done with ' + functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + functions.colors.ENDC)
