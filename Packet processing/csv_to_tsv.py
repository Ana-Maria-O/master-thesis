import pandas as pd
import os
import subprocess

# Remove the malicious packets from the training set of a set of labeled packets
def main_function():
    PATH = "" # Path to the folder which contains the csv files that form the entire set of packets
    files = os.listdir(PATH)
    TRAINING_PERCENT = 0.5
    total = 0
    all_data = pd.DataFrame()

    # Merge all the csv files into one dataframe
    for path in files: 
        df = pd.read_csv(PATH + "\\" + path)
        all_data = pd.concat([all_data, df])

    # Get the number of lines in the csv file
    lines = all_data.shape[0]
    # print(lines)
    training_number = int(lines * TRAINING_PERCENT)

    # Get the lines that need to be filtered
    training = all_data.head(training_number)
    testing = all_data.tail(lines - training_number)

    # print(training.shape)

    # Remove the lines that are anomalies
    training = training[training["Label"] == 'Benign']

    # print(training_number)
    # print(lines - training_number)
    # print(training.shape)
    # print(testing.shape)
    # # print(training)

    # Combine the training and testing sets into one dataframe
    benign_data = pd.concat([training, testing], ignore_index=True)

    benign_data.to_csv("ids_benign_raw.csv")

    print(benign_data.shape)

    # Process the benign data to remove the labels and id
    benign_data.drop(columns="Label").to_csv("ids_benign_final.tsv", sep="\t", index=False)

def pcap_to_tsv():
    pcap_file = "mawi_all_benign.pcap"
    fields = "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst"
    cmd =  '"C:/Program Files/Wireshark/tshark.exe" -r ' + pcap_file + ' -T fields '+ fields +' -E header=y -E occurrence=f > '+pcap_file+".tsv"
    subprocess.call(cmd,shell=True)

pcap_to_tsv()