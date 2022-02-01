# HNP does not allow to serialize keys yet. Therefore, one is simulating here, every time parties switch, there is a communication between these parties exchanging parameters
import hnumpy as hnp
import numpy as np
import baseline_functions
import baseline_client
import baseline_server
import logging
from loguru import logger

# Initialisation
logger.info('Baseline_simulation: key generation - started')
context = baseline_functions.hom_dissimilarity_measure.create_context()
keys = context.keygen()
logger.info('Baseline_simulation: key generation - done')

# Key distribution
logger.info('Baseline_simulation: key distribution to clients and server - started')
client_1 = baseline_client.Baseline_client(keys)
client_2 = baseline_client.Baseline_client(keys)
server = baseline_server.Baseline_server(keys)
logger.info('Baseline_simulation: key distribution to clients and server - done')

# Name and Feature collection for later enrollment and authentication simulations
username_1 = 'Karl-Heinz'
username_2 = 'Agatha'
feature_1 = np.random.uniform(-1, 1, (baseline_functions.feature_size, ))
feature_1 = feature_1/np.linalg.norm(feature_1)
feature_2 = np.random.uniform(-1, 1, (baseline_functions.feature_size, ))
feature_2 = feature_2/np.linalg.norm(feature_2)

# Enrollment
logger.info('Baseline_simulation: enrollment simulation on client 1 for ' + username_1 + ' with feature of ' + username_1 + ' - started')
message = client_1.enroll(username_1, feature_1)
server.process_message(message)
logger.info('Baseline_simulation: enrollment simulation on client 1 for ' + username_1 + ' with feature of ' + username_1 + ' - done')

logger.info('Baseline_simulation: enrollment simulation on client 2 for ' + username_2 + ' with feature of ' + username_2 + ' - started')
message = client_2.enroll(username_2, feature_2)
server.process_message(message)
logger.info('Baseline_simulation: enrollment simulation on client 2 for ' + username_2 + ' with feature of ' + username_2 + ' - done')

# Authentication
logger.info('Baseline_simulation: authentication simulation on client 1 for ' + username_1 + ' with feature of ' + username_1 + ' - started')
message = client_1.authenticate_1(username_1, feature_1)
enc_dissimilarity_measure = server.process_message(message)
plaintext_dis = 1 - np.dot(feature_1, feature_1)
logger.info('Baseline_simulation: ' + baseline_functions.colors.WARNING + 'expected dissimilarity measure' + baseline_functions.colors.ENDC + ' after decryption on the client side ' + baseline_functions.colors.WARNING + str(plaintext_dis) + baseline_functions.colors.ENDC)
answer = client_1.authenticate_2(enc_dissimilarity_measure)
logger.info('Baseline_simulation: authentication simulation on client 1 for ' + username_1 + ' with feature of ' + username_1 + ' - done with ' + baseline_functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + baseline_functions.colors.ENDC)

logger.info('Baseline_simulation: authentication simulation on client 1 for ' + username_1 + ' with feature of ' + username_2 + ' - started')
message = client_1.authenticate_1(username_1, feature_2)
enc_dissimilarity_measure = server.process_message(message)
plaintext_dis = 1 - np.dot(feature_2, feature_1)
logger.info('Baseline_simulation: ' + baseline_functions.colors.WARNING + 'expected dissimilarity measure' + baseline_functions.colors.ENDC + ' after decryption on the client side ' + baseline_functions.colors.WARNING + str(plaintext_dis) + baseline_functions.colors.ENDC)
answer = client_1.authenticate_2(enc_dissimilarity_measure)
logger.info('Baseline_simulation: authentication simulation on client 1 for ' + username_1 + ' with feature of ' + username_2 + ' - done with ' + baseline_functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + baseline_functions.colors.ENDC)

logger.info('Baseline_simulation: authentication simulation on client 1 for ' + username_2 + ' with feature of ' + username_1 + ' - started')
message = client_1.authenticate_1(username_2, feature_1)
enc_dissimilarity_measure = server.process_message(message)
plaintext_dis = 1 - np.dot(feature_1, feature_2)
logger.info('Baseline_simulation: ' + baseline_functions.colors.WARNING + 'expected dissimilarity measure' + baseline_functions.colors.ENDC + ' after decryption on the client side ' + baseline_functions.colors.WARNING + str(plaintext_dis) + baseline_functions.colors.ENDC)
answer = client_1.authenticate_2(enc_dissimilarity_measure)
logger.info('Baseline_simulation: authentication simulation on client 1 for ' + username_2 + ' with feature of ' + username_1 + ' - done with ' + baseline_functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + baseline_functions.colors.ENDC)

logger.info('Baseline_simulation: authentication simulation on client 1 for ' + username_2 + ' with feature of ' + username_2 + ' - started')
message = client_1.authenticate_1(username_2, feature_2)
enc_dissimilarity_measure = server.process_message(message)
plaintext_dis = 1 - np.dot(feature_2, feature_2)
logger.info('Baseline_simulation: ' + baseline_functions.colors.WARNING + 'expected dissimilarity measure' + baseline_functions.colors.ENDC + ' after decryption on the client side ' + baseline_functions.colors.WARNING + str(plaintext_dis) + baseline_functions.colors.ENDC)
answer = client_1.authenticate_2(enc_dissimilarity_measure)
logger.info('Baseline_simulation: authentication simulation on client 1 for ' + username_2 + ' with feature of ' + username_2 + ' - done with ' + baseline_functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + baseline_functions.colors.ENDC)

logger.info('Baseline_simulation: authentication simulation on client 2 for ' + username_1 + ' with feature of ' + username_1 + ' - started')
message = client_2.authenticate_1(username_1, feature_1)
enc_dissimilarity_measure = server.process_message(message)
plaintext_dis = 1 - np.dot(feature_1, feature_1)
logger.info('Baseline_simulation: ' + baseline_functions.colors.WARNING + 'expected dissimilarity measure' + baseline_functions.colors.ENDC + ' after decryption on the client side ' + baseline_functions.colors.WARNING + str(plaintext_dis) + baseline_functions.colors.ENDC)
answer = client_2.authenticate_2(enc_dissimilarity_measure)
logger.info('Baseline_simulation: authentication simulation on client 2 for ' + username_1 + ' with feature of ' + username_1 + ' - done with ' + baseline_functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + baseline_functions.colors.ENDC)

logger.info('Baseline_simulation: authentication simulation on client 2 for ' + username_1 + ' with feature of ' + username_2 + ' - started')
message = client_2.authenticate_1(username_1, feature_2)
enc_dissimilarity_measure = server.process_message(message)
plaintext_dis = 1 - np.dot(feature_2, feature_1)
logger.info('Baseline_simulation: ' + baseline_functions.colors.WARNING + 'expected dissimilarity measure' + baseline_functions.colors.ENDC + ' after decryption on the client side ' + baseline_functions.colors.WARNING + str(plaintext_dis) + baseline_functions.colors.ENDC)
answer = client_2.authenticate_2(enc_dissimilarity_measure)
logger.info('Baseline_simulation: authentication simulation on client 2 for ' + username_1 + ' with feature of ' + username_2 + ' - done with ' + baseline_functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + baseline_functions.colors.ENDC)

logger.info('Baseline_simulation: authentication simulation on client 2 for ' + username_2 + ' with feature of ' + username_1 + ' - started')
message = client_2.authenticate_1(username_2, feature_1)
enc_dissimilarity_measure = server.process_message(message)
plaintext_dis = 1 - np.dot(feature_1, feature_2)
logger.info('Baseline_simulation: ' + baseline_functions.colors.WARNING + 'expected dissimilarity measure' + baseline_functions.colors.ENDC + ' after decryption on the client side ' + baseline_functions.colors.WARNING + str(plaintext_dis) + baseline_functions.colors.ENDC)
answer = client_2.authenticate_2(enc_dissimilarity_measure)
logger.info('Baseline_simulation: authentication simulation on client 2 for ' + username_2 + ' with feature of ' + username_1 + ' - done with ' + baseline_functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + baseline_functions.colors.ENDC)

logger.info('Baseline_simulation: authentication simulation on client 2 for ' + username_2 + ' with feature of ' + username_2 + ' - started')
message = client_2.authenticate_1(username_2, feature_2)
enc_dissimilarity_measure = server.process_message(message)
plaintext_dis = 1 - np.dot(feature_2, feature_2)
logger.info('Baseline_simulation: ' + baseline_functions.colors.WARNING + 'expected dissimilarity measure' + baseline_functions.colors.ENDC + ' after decryption on the client side ' + baseline_functions.colors.WARNING + str(plaintext_dis) + baseline_functions.colors.ENDC)
answer = client_2.authenticate_2(enc_dissimilarity_measure)
logger.info('Baseline_simulation: authentication simulation on client 2 for ' + username_2 + ' with feature of ' + username_2 + ' - done with ' + baseline_functions.colors.WARNING + 'LOGIN_ALLOWED=' + str(answer) + baseline_functions.colors.ENDC)
