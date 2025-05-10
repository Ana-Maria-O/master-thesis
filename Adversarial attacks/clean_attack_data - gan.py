import pandas as pd
import numpy as np

def clean_attacks_packets():
    attacks = pd.read_csv("") # Fill in with the path to the csv file with the GAN on features adversarial examples

    attacks = attacks[(((attacks["tcp.srcport"] > 0) & (attacks["tcp.dstport"] > 0) & (attacks["udp.srcport"] == 0) & (attacks["udp.dstport"] == 0))
            |((attacks["tcp.srcport"] == 0) & (attacks["tcp.dstport"] == 0) & (attacks["udp.srcport"] > 0) & (attacks["udp.dstport"] > 0)))] 
    attacks = attacks[(attacks["icmp.type"] == 0)] 
    # attacks = attacks[attacks["frame.time_epoch"] < 1499448068.916272]

    attacks.replace(0, np.nan, inplace=True)
    attacks.sort_values(by=["frame.time_epoch"])
    attacks.to_csv("gan_adversarial_examples_clean.csv", index=False)

def insert_attacks():
    # attacks = pd.read_csv("gan_adversarial_examples_clean.csv")
    attacks = pd.read_csv("_ganf_adversarial_examples_features.csv")

    kitsune_set = pd.read_csv("", header=None, sep=' ') # Fill in the path to the file with the original packets or packet features where the adversarial attacks should be inserted

    kitsune_set.columns = attacks.columns
    number_attacks = [1, 100, 480, 961]
    # number_attacks = [1, 10, 24]

    # Rename the columns in the generated feature file to match the normal features
    corr_cols = {}
    for i in range(100):
        corr_cols["Feature " + str(i)] = "Feature " + str(i + 1)
    attacks.rename(columns=corr_cols, inplace=True)
    attacks.drop(columns=["Unnamed: 0"], inplace=True)

    attacks.to_csv("mawi_adversarial_examples_features.csv", index=False)

    for num in number_attacks:
        attack = attacks.sample(num)

        # Insert the attack in the tsv meant for Kitsune
        attack.to_csv("inserted_attack_features_" + str(num) + ".csv")
        # attack.to_csv("inserted_attack_packets_" + str(num) + ".csv")

        kitsune_set_new = pd.concat([attack, kitsune_set]).reset_index(drop=True)
        # kitsune_set_new = kitsune_set_new.sort_values(by="frame.time_epoch").reset_index(drop=True)

        kitsune_set_new.to_csv("_ganf_attack_features_" + str(num) + ".tsv", index=False, sep='\t')
        # kitsune_set_new.to_csv("gan_attack_packets_" + str(num) + ".tsv", index=False, sep='\t')

clean_attacks_packets()
insert_attacks()