import pyshark
import pandas as pd
import numpy as np

# Path for the labelled unfiltered csv file
CSV_PATH = "abeled_mawi_unifiltered.csv"

# Path for labeleled and filtered csv file
NUMBER_PATH = "abeled_mawi_filtered.csv"

# Path for the unlabelled pcap file
PCAP_PATH = "mawi_data_unfiltered.pcap"

# Path for the unlabelled tsv file
TSV_PATH = "unlabeled_mawi_unfiltered.pcap.tsv"

# File with suspicious packets
sus_file = "mawi_suspicious.pcap.tsv"

# File with anomalous packets
ano_file = "mawi_anomalous.pcap.tsv"

feature_file = "mawi_gan_features_1"

ben_file = "mawi_all_benign.pcap.tsv"

# Column names for the csv
# COLUMNS = ""


# Write the columns in the csv file
# labeled.write(COLUMNS)
def label_mawi():
    # Get the pcap packets
    packets = pd.read_csv(TSV_PATH, sep='\t')

    ben_packets = pd.read_csv(ben_file, sep='\t')
    # Make a copy of the pcap file for labelling
    # labeled = packets.copy()

    # # run tshark filtering commands to get the suspicious packets
    # sus_packets = pd.read_csv(sus_file, sep='\t')
    # # run thsark filtering commands to get the anomalous packets
    # ano_packets = pd.read_csv(ano_file, sep='\t')

    # Pre-process some of the columns so the merge function doesn't throw a tantrum
    # sus_packets['arp.src.hw_mac'] = sus_packets['arp.src.hw_mac'].astype(object)
    # ano_packets['arp.src.hw_mac'] = ano_packets['arp.src.hw_mac'].astype(object)
    # sus_packets['arp.src.proto_ipv4'] = sus_packets['arp.src.proto_ipv4'].astype(object)
    # ano_packets['arp.src.proto_ipv4'] = ano_packets['arp.src.proto_ipv4'].astype(object)
    # sus_packets['arp.dst.hw_mac'] = sus_packets['arp.dst.hw_mac'].astype(object)
    # ano_packets['arp.dst.hw_mac'] = ano_packets['arp.dst.hw_mac'].astype(object)
    # sus_packets['arp.dst.proto_ipv4'] = sus_packets['arp.dst.proto_ipv4'].astype(object)
    # ano_packets['arp.dst.proto_ipv4'] = ano_packets['arp.dst.proto_ipv4'].astype(object)
    # sus_packets['ipv6.src'] = sus_packets['ipv6.src'].astype(object)
    # ano_packets['ipv6.src'] = ano_packets['ipv6.src'].astype(object)
    # sus_packets['ipv6.dst'] = sus_packets['ipv6.dst'].astype(object)
    # ano_packets['ipv6.dst'] = ano_packets['ipv6.dst'].astype(object)

    # mal_packets = pd.concat([sus_packets, ano_packets],ignore_index=True)
    ben_packets.drop_duplicates(inplace=True)

    cols = packets.columns.values.tolist()
    check = pd.merge(packets, ben_packets, on=cols, how='left', indicator='Label')
    check['Label'] = np.where(check.Label == 'both', 0, 1)
    print(check[check['Label'] == 0].shape[0])
    

    # Get the first anomalous and suspicious packets
    # sus = sus_packets.next()
    # ano = ano_packets.next()
    # sus_finished = False
    # ano_finished = False

    # # Check the column names
    # # print(float(sus.frame_info.time_epoch))
    # packets[""]
    # # Label all the suspicious packets as malicious
    # while not sus_finished:
    #     # print(sus.eth.src)
    #     thing = packets[(packets["frame.time_epoch"] == float(sus.frame_info.time_epoch)) 
    #                     & (packets["frame.len"] == int(sus.length)) & (packets["eth.src"] == sus.eth.src)
    #                     ]
    #     if len(thing) != 1:
    #         print("AAAAAAAAA")
    #     packets.loc[(packets["frame.time_epoch"] == float(sus.frame_info.time_epoch)) 
    #                 & (packets["frame.len"] == int(sus.length))
    #                 & (packets["eth.src"] == sus.eth.src), "Label"] = 1
        
    #     # vals = packets["Label"].unique()

    #     try:
    #         sus = sus_packets.next()
    #     except:
    #         sus_finished = True

    # # Label all the anomalous packets as malicious
    # while not ano_finished:
    #     thing = packets[(packets["frame.time_epoch"] == float(ano.frame_info.time_epoch)) & (packets["frame.len"] == int(ano.length)) & (packets["eth.src"] == ano.eth.src)]
    #     if len(thing) != 1:
    #         print("AAAAAAAAA")
    #     packets.loc[(packets["frame.time_epoch"] == float(ano.frame_info.time_epoch))
    #                 & (packets["frame.len"] == int(ano.length))
    #                 & (packets["eth.src"] == ano.eth.src), "Label"] = 1

    #     try:
    #         ano = ano_packets.next()
    #     except:
    #         ano_finished = True

    # sus_pack = packets[packets["frame.time_epoch"] == sus]
    # ano_pack = packets[packets["frame.time_epoch"] == ano]

    # # Label each packet
    # for index, row in packets.iterrows():
    #     if index % 1000 == 0:
    #         print("Packets processed: " + str(index))
    #     # Check that the time of the current packet is smaller or equal to the times of the next anomalous
    #     while row['frame.time_epoch'] > sus and not sus_finished:
    #         try:
    #             sus = float(sus_packets.next().frame_info.time_epoch)
    #         except:
    #             sus_finished = True
        
    #     while row['frame.time_epoch'] > ano and not ano_finished:
    #         try:
    #             ano = float(ano_packets.next().frame_info.time_epoch)
    #         except:
    #             ano_finished = True

    #     # If the time of the current packet is less then the time of the next suspicious and anomalous packet, then it is benign
    #     if row['frame.time_epoch'] < sus and row['frame.time_epoch'] < ano:
    #         packets.at[index, 'Label'] = "Benign"

    #     # If not, then it must be equal to one of the times of the anomalous or suspicious packet. Label is accordingly
    #     elif row['frame.time_epoch'] == sus:
    #         packets.at[index, 'Label'] = "Suspicious"

    #     elif row['frame.time_epoch'] == ano:
    #         packets.at[index, 'Label'] = "Anomalous"

    #     else:
    #         print("Some weird shit is happening with this packet: " + str(row['frame.time_epoch']))
    #         print(ano)
    #         print(sus)
    #         print("--------------------")
    #         packets.at[index, 'Label'] = "Benign"

        # print(packets['Label'])

    # result = packets.copy()
    check.to_csv(CSV_PATH, index=False)

    # print(labeled.head)

# Function that replaces string labels with 0 if benign and 1 if malicious
def replace_with_numbers():
    labeled = pd.read_csv(CSV_PATH)

    labels = labeled["Label"].unique()

    for label in labels:
        if label != "Benign":
            labeled["Label"].replace(label, 1, inplace= True)
        else:
            labeled["Label"].replace(label, 0, inplace= True)

    labeled.to_csv(NUMBER_PATH, index=False)

def split_feature_file(filename):
    file = open(filename, 'r')

    packets_number = 2552402

    file_lines = file.readlines()

    lines_number = len(file_lines)

    count = 0

    output = open(filename + "_1", 'w')

    for line in file_lines:
        # Once we reach the features for the 2nd file, we close the first file and open the second
        if count == lines_number - packets_number:
            output.close()
            output = open(filename + "_2", 'w')

        output.write(line)

        count += 1
    
    output.close()

def label_gan(attack_num):
    # CSV file with the attack rows
    ATTACK_CSV = "inserted_attack39.csv"
    # Get labelled regular file
    labelled_file = pd.read_csv(NUMBER_PATH)

    # Get attack rows
    attack_rows = pd.read_csv(ATTACK_CSV)

    # labelled_file.drop(columns=["Unnamed: 0.1", "Unnamed: 0"], inplace= True)
    # labelled_file.to_csv(CSV_PATH, index= False)

    for i in range(attack_num):
        attk = attack_rows.iloc[i]["frame.time_epoch"]
        fl = attack_rows.iloc[i]["frame.len"]
        maybe = labelled_file[labelled_file["frame.time_epoch"] == attk]
        # if (maybe.shape[0] > 1): 
        #     print("b")
        
        # if maybe.iloc[0]["Label"] != 1:
        #     print("aaaaaa")
        #     labelled_file.loc[maybe.index.values.astype(int)[0], "Label"] = 1
        #     maybe = labelled_file[labelled_file["frame.time_epoch"] == attk]
        #     print(labelled_file.iloc[maybe.index.values.astype(int)[0]]["Label"])

    # labelled_file.to_csv(NUMBER_PATH, index=False)

    
    # Get full tsv file
    # full_tsv = pd.read_csv(TSV_PATH)

    # print("aaaa")
    # Figure out where to insert attack and label attack    

def filter_mawi():
    # Get the full labelled file
    all_labelled = pd.read_csv(CSV_PATH)

    # Remove all malicious packets from the first half of the labelled file
    labelled_train = all_labelled.head(2000000)
    all_labelled = all_labelled.tail(2000000)

    labelled_train = labelled_train[labelled_train["Label"] == 0]
    # all_labelled is the labeled filtered for Kitsune csv file
    all_labelled = pd.concat([labelled_train, all_labelled], ignore_index = True)
    all_labelled.to_csv(NUMBER_PATH, index=False)

    print("Done")

# split_feature_file(feature_file)
# label_mawi()
filter_mawi()
# replace_with_numbers()
# label_gan(39)
