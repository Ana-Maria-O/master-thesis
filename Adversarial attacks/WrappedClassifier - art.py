from os import path
import sys
import numpy as np
import pandas as pd
from pyod.models.thresholds import CLUST
import pickle

sys.path.append("") # Fill in with the path of the folder that contains the Kitsune.pyx and Kitsune.c files
from Kitsune import Kitsune

from art.estimators.classification import BlackBoxClassifierNeuralNetwork
from art.attacks.evasion import ZooAttack, HopSkipJump
from art.attacks.poisoning import GradientMatchingAttack

# Train the model before we do anything else
scores = []

# Instances needed to train the feature mapping
FMinstances = 80155 # Number of FM instances as defined in the parameters for running Kitsune on the original dataset
fm_sub = int(FMinstances * 0.04)

# Instances needed to train the anomaly detector
ADinstances = 721399 # IDS
ad_sub = int(ADinstances * 0.04)

# Total number of training packets
train_num = FMinstances + ADinstances

# Get the training data
labeled_full_file = "" # Fill in with the path of the csv file that contains the labels of the dataset in which the attacks will be inserted.
features_file = "" # Fill in with the path of the file that contains the feature vectors of the packets that correspond to the labels of labeled_full_file
mawi_full = pd.read_csv(labeled_full_file)["Label"]
mawi_features =pd.read_csv(features_file, header=None, sep=' ')
train_data = mawi_features.head(train_num)
print(train_data.dtypes)

# (Optional) Replace the NaN values in mawi_full with the empty string
columns = ["eth.src", "eth.dst", "ip.src", "ip.dst", "arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.hw_mac", "arp.dst.proto_ipv4",
            "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]
to_str = ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]

dict = {col: "" for col in columns}
mawi_full.fillna(dict, inplace=True)
for col in to_str:
    mawi_full[col] = mawi_full[col].astype(str)

train_data = pd.concat([train_data.head(FMinstances).sample(fm_sub), train_data.tail(ADinstances).sample(ad_sub)], ignore_index=True)
train_data = np.array(list(train_data.itertuples(index=False, name=None)), dtype=float)

index = 0

# Make the input list into an array
print(len(train_data[0]))
i = 0

# Create an instance of the model
K = Kitsune(None, np.Inf, 10, fm_sub, ad_sub, num_features=len(train_data[0]))

# for i in range(10000):
for i in range(fm_sub + ad_sub):
    if i % 1000 == 0:
        print("Processed packets for training: " + str(i))
    # score = K.proc_next_packet()
    score = K.proc_feature(train_data[i])
    # Stop the loop if there are no more packets
    if score == -1:
        break
    

def predict_packet(x):
    # Extract feature from packet if needed
    feature = K.FE.extract_packet(x)

    # Run feature through anomaly detector and get the anomaly score
    score = K.proc_feature(feature)

    scores.append(score)

    # Threshold the scores
    th = CLUST(method='somsc')
    thresh_scores = th.eval(scores)

    return (x, thresh_scores)

def predict_packet_f(feature):
    scores = []
    if feature.shape[0] != 1:
        print("wtf is this")
    for feat in feature:
        # Run feature through anomaly detector and get the anomaly score
        score = K.proc_feature(feat)

        scores.append(score)

    # Threshold the scores
    th = 0.13
    thresh_scores = np.array([0 if sc < th else 1 for sc in scores])
    mat = np.zeros((feature.shape[0], 2), dtype=float)
    mat[np.arange(feature.shape[0]), thresh_scores] = 1
    return mat

def attackZOO(model:BlackBoxClassifierNeuralNetwork, training_packets:np.ndarray):
    # Create two instances of the zoo attack class
    zoo_untargeted = ZooAttack(model, targeted=False, nb_parallel=100)
    zoo_targeted = ZooAttack(model, targeted=True, nb_parallel=100)

    # Generate adversarial examples for both types of zoo attack
    untargeted_ae = zoo_untargeted.generate(training_packets, np.array([0 for i in range(len(training_packets))], dtype=int))
    targeted_ae = zoo_targeted.generate(training_packets, np.array([0 for i in range(len(training_packets))], dtype=int))

    return (untargeted_ae, targeted_ae)

# Array of inputs
# Randomly select a number of malicious inputs
mawi_features["Label"] = mawi_full
mawi_features = mawi_features[mawi_features["Label"] == 1].tail(mawi_features.shape[0] - train_num)
total_input_num = 100 # Number of features to be used as training data for generating attacks
mawi_features = mawi_features.sample(total_input_num)
mawi_features.drop(columns=["Label"], inplace=True)

# Make an array of inputs
arr = list(mawi_features.itertuples(index=False, name=None))
input = np.array(arr, dtype=float)

# Make an instance of the classifier object
wrapped_kitsune = BlackBoxClassifierNeuralNetwork(predict_packet_f, input[0].shape, 2)

# Generate ZOO adversarial examples and export them to a pickle file
print("Starting ZOO")
pickle.dump(attackZOO(wrapped_kitsune, input), open("ZOO_attacks.p", "wb"))

# Generate HSJ adversarial examples and export them to a pickle file
print("Start HopSkipJump")
hsj_t = HopSkipJump(wrapped_kitsune, targeted=True)
hsj_u = HopSkipJump(wrapped_kitsune, targeted=False)
pickle.dump(hsj_t.generate(input, np.array([0 for i in range(len(input))], dtype=int)), open("HSJ_attack_targeted.p", "wb"))
pickle.dump(hsj_u.generate(input, np.array([0 for i in range(len(input))], dtype=int)), open("HSJ_attack_untargeted.p", "wb"))

print("Done")

