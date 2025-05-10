import pickle
import pandas as pd
import random
import numpy as np

# Number of how many adversarial examples to be inserted into the original packets feature file
insertion_steps = [100, 1000, 5000, 10000]

hsj = pickle.load(open("", "rb")).tolist() # Fill in with the path to the pickle file with the generated untargeted HSJ adversarial examples
# Make a list with all the HSJ untargeted features
hsj = [hsj[index][:100] for index in range(len(hsj))]
hsj_t = pickle.load(open("", 'rb')) # Fill in with the path to the pickle file with the generated targeted HSJ adversarial examples
# Make a list with all the HSJ targeted features
hsj_t = [hsj_t[index][:100] for index in range(len(hsj_t))]

zoo_t, zoo_u = pickle.load(open("", "rb")) # Fill in with the path to the pickle file with the generated ZOO adversarial examples
zoo_t = zoo_t.tolist()
zoo_t = [zoo_t[index][:100] for index in range(len(zoo_t))]
zoo_u = zoo_u.tolist()
zoo_u = [zoo_u[index][:100] for index in range(len(zoo_u))]

features = pd.read_csv("", header=None, sep=' ') # Fill in with the path to the file with the features of the packets where the adversarial examples should be inserted

# Create a files of adversarial examples to be inserted into the original packet feature file.
def sample_features():
    for step in insertion_steps:
        # to_insert = random.sample(zoo_t, step)
        # pd.DataFrame(to_insert).to_csv("zoo_targeted_" + str(step) + ".csv", index=False)

        # to_insert = random.sample(zoo_u, step)
        # pd.DataFrame(to_insert).to_csv("zoo_untargeted_" + str(step) + ".csv", index=False)

        # to_insert = random.sample(hsj, step)
        # pd.DataFrame(to_insert).to_csv("hsj_untargeted" + str(step) + ".csv", index=False)

        to_insert = random.sample(hsj_t, step)
        pd.DataFrame(to_insert).to_csv("hsj_targeted_" + str(step) + ".csv", index=False)

# Convert the pickle files with adversarial examples into csv files
def p_to_csv():
    zoo_p_file = pickle.load(open("", 'rb')) # Fill in the path to the pickle file with all the generated ZOO attack examples
    hsjt_p_file = pickle.load(open("", 'rb')) # Fill in the path to the pickle file with all the generated targeted HSJ attack examples
    hsju_p_file = pickle.load(open("", 'rb')) # Fill in the path to the pickle file with all the generated untargeted HSJ attack examples

    zoou_df = pd.DataFrame(zoo_p_file[0], columns=range(len(zoo_p_file[0][0])))
    zoot_df = pd.DataFrame(zoo_p_file[1], columns=range(len(zoo_p_file[1][0])))
    hsjt_df = pd.DataFrame(hsjt_p_file, columns=range(len(hsjt_p_file[0])))
    hsju_df = pd.DataFrame(hsju_p_file, columns=range(len(hsju_p_file[0])))

    zoot_df.to_csv("ids_zoot_attack.csv", index=False)
    zoou_df.to_csv("ids_zoou_attack.csv", index=False)
    hsjt_df.to_csv("ids_hsjt_attack.csv", index=False)
    hsju_df.to_csv("ids_hsju_attack.csv", index=False)

p_to_csv()
sample_features()

file_roots = ["zoo_targeted_", "zoo_untargeted_", "hsj_targeted_", "hsj_untargeted"]

for fr in file_roots:
    for step in insertion_steps:
        to_insert = pd.read_csv(fr + str(step) + ".csv")
        # print(to_insert.columns)
        # print(features.columns)
        to_insert.columns = features.columns

        pd.concat([to_insert, features], ignore_index=True).to_csv("attack_training_features_" + fr + str(step) + ".csv", index=False)

    # Concat all malicious features in the testing set
    to_insert = pd.read_csv(fr + "10000.csv")
    to_insert.columns = features.columns
    pd.concat([features, to_insert], ignore_index=True).to_csv("attack_test_features_" + fr + ".csv", index=False)