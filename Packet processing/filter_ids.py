import pandas as pd
import numpy as np
import time

# Difference between UTC time and the time in the CSV files
time_difference_num = 15 * 3600

PATH = "TrafficLabelling_"

# files = []

# Path of the unlabelled tsv file
TSV_PATH = "IDS_1.csv"

# def filter_flows(packet, src_ip, dst_ip, src_port=0, dst_port=0):
# def filter_flows(packet):
#     global all_csv
#     global flows

    # flows = all_csv[(all_csv[" Source IP"] == src_ip) & (all_csv[" Destination IP"] == dst_ip)]
    # flows_rev = all_csv[(all_csv[" Source IP"] == dst_ip) & (all_csv[" Destination IP"] == src_ip)]

    # # Get the flows with the same protocol and source + dest ip and port and the right protocol
    # if 'TCP' in packet:
    #     flows = flows[(flows[" Source Port"] == src_port) & (flows[" Destination Port"] == dst_port) & (flows[" Protocol"] == 6)]
    #     flows_rev = flows_rev[(flows_rev[" Source Port"] == dst_port) & (flows_rev[" Destination Port"] == src_port) & (flows_rev[" Protocol"] == 6)]

    # elif 'UDP' in packet:
    #     flows = flows[(flows[" Source Port"] == src_port) & (flows[" Destination Port"] == dst_port) & (flows[" Protocol"] == 17)]
    #     flows_rev = flows_rev[(flows_rev[" Source Port"] == dst_port) & (flows_rev[" Destination Port"] == src_port) & (flows_rev[" Protocol"] == 17)]

    # else:
    #     # If the packet has IP but is not TCP or UDP, then the value of the protocol is 0
    #     flows = flows[flows[" Protocol"] == 0]
    #     flows_rev = flows_rev[flows_rev[" Protocol"] == 0]

    # # After filtering for IP addresses, ports and protocols we filter for time
    # # We know that a flow lasts for a maximum of 120 seconds, so we only get the flows that the packet could belong to time-wise
    # flows = flows[(float(packet.frame_info.time_epoch) >= flows[" Timestamp"]) & (float(packet.frame_info.time_epoch) - flows[" Timestamp"] <= 120) ]
    # flows_rev = flows[(float(packet.frame_info.time_epoch) >= flows[" Timestamp"]) & (float(packet.frame_info.time_epoch) - flows[" Timestamp"] <= 120) ]

def label_ids():
    all_csv = pd.DataFrame()
    start_time = time.time()
    freq = 1000
    to_delete = []

    # Data frame for all the labelled data
    final_labelled = pd.read_csv(TSV_PATH)

    # Add a label column
    final_labelled["Label"] = np.nan
    # packets = pyshark.FileCapture(PCAP_PATH, keep_packets= False)

    # max_index = final_labelled.shape[0]

    files = ['Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv', 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv']

    # Combine all the csv files into one dataframe
    for file in files:
        ids = pd.read_csv(PATH + "\\" + file)

        all_csv = pd.concat([all_csv, ids])
    
    # Convert the strings from the Timeframe column to UNIX epoch numbers
    all_csv[" Timestamp"] = pd.to_datetime(all_csv[" Timestamp"])
    # The previous row considers the time to be UTC, but we know from the capture packets that the timestamp is 3 hours behind UTC time
    all_csv[" Timestamp"] = all_csv[" Timestamp"].apply(lambda x: x.timestamp() + time_difference_num)

    to_delete = []

    for index, packet in final_labelled.iterrows():
    # Go through each packet and label it
    # while index < max_index:
        if index % freq == 0:
            print("Packet " + str(index) + ". Time elapsed: " + str(time.time() - start_time))
    #     packet = packets.next()

        # If the current packet doesn't have an IP field, then it is considered benign
        if pd.isnull(packet["ip.src"]) and pd.isnull(packet["arp.src.proto_ipv4"]):
            packet["Label"] = 0
        else:
            # If it has an IP field, then find its corresponding flow based on its IP, ports, time and protocol
            if pd.isnull(packet["tcp.srcport"]):
                if pd.isnull(packet["udp.srcport"]):
                    flow = all_csv[(((all_csv[" Source IP"] == packet["arp.src.proto_ipv4"]) & (all_csv[" Destination IP"] == packet["arp.dst.proto_ipv4"])) 
                            | ((all_csv[" Source IP"] == packet["arp.dst.proto_ipv4"]) & (all_csv[" Destination IP"] == packet["arp.src.proto_ipv4"])))
                            & ((packet["frame.time_epoch"] >= all_csv[" Timestamp"]) & (packet["frame.time_epoch"] <= all_csv[" Timestamp"] + 120))
                            & (all_csv[" Protocol"] == 0)]
                    
                else:
                    flow = all_csv[(((all_csv[" Source IP"] == packet["ip.src"]) & (all_csv[" Destination IP"] == packet["ip.dst"]) & (all_csv[" Source Port"] == packet["udp.srcport"]) & (all_csv[" Destination Port"] == packet["udp.dstport"])) 
                            | ((all_csv[" Source IP"] == packet["ip.dst"]) & (all_csv[" Destination IP"] == packet["ip.src"]) & (all_csv[" Source Port"] == packet["udp.dstport"]) & (all_csv[" Destination Port"] == packet["udp.srcport"])))
                            & ((packet["frame.time_epoch"] >= all_csv[" Timestamp"]) & (packet["frame.time_epoch"] - all_csv[" Timestamp"] <= 120))
                            & (all_csv[" Protocol"] == 17)]
            else:
                flow = all_csv[(((all_csv[" Source IP"] == packet["ip.src"]) & (all_csv[" Destination IP"] == packet["ip.dst"]) & (all_csv[" Source Port"] == packet["tcp.srcport"]) & (all_csv[" Destination Port"] == packet["tcp.dstport"])) 
                        | ((all_csv[" Source IP"] == packet["ip.dst"]) & (all_csv[" Destination IP"] == packet["ip.src"]) & (all_csv[" Source Port"] == packet["tcp.dstport"]) & (all_csv[" Destination Port"] == packet["tcp.srcport"])))
                        & ((packet["frame.time_epoch"] >= all_csv[" Timestamp"]) & (packet["frame.time_epoch"] <= all_csv[" Timestamp"] + 120))
                        & (all_csv[" Protocol"] == 6)]
            
            # If the packet belongs to no flow, then mark it to be deleted later
            if flow.empty:
                to_delete += [index]
            else:
                # If the packets has a flow, check that it doesn't have conflicting labels
                if len(flow[" Label"].unique()) > 1:
                    print("WE ARE IN TROUBLE")
                    print(packet)
                    print("----------------------------")
                else:
                    label = flow[" Label"].unique()[0]
                    if label == "BENIGN":
                        packet["Label"] = 0
                    else:
                        packet["Label"] = 1
    #     if 'IP' in packet:
    #         # Only get the flows with the right source and destination IP
    #         if 'TCP' in packet:
    #             filter_flows(packet, packet.ip.src, packet.ip.dst, int(packet.tcp.srcport), int(packet.tcp.dstport))
    #         elif 'UDP' in packet:
    #             filter_flows(packet, packet.ip.src, packet.ip.dst, int(packet.udp.srcport), int(packet.udp.dstport))
    #         else:
    #             filter_flows(packet, packet.ip.src, packet.ip.dst)

    #         if len(flows) == 0 and len(flows_rev) == 0:
    #             to_delete += [packet.frame_info.time_epoch]

    #         # Now we take the label that belongs to the flows and label the packet with it
    #         number_labels = len(pd.concat([flows, flows_rev])[" Label"].unique())
    #         if number_labels > 1:
    #             print("------------------------")
    #             print(index)
    #             print(flows[["Flow ID", " Source IP", " Timestamp", " Label"]])
    #             print("We have a big problem")
    #         elif number_labels != 0:
    #             final_labelled.loc[index, "Label"] = flows[" Label"].unique()[0]
                
    #     else:
    #         final_labelled.loc[index, "Label"] = "BENIGN"

    #     index += 1
    # Delete the packets which don't belong to any flow
    final_labelled.drop(to_delete, axis=0)
    final_labelled.to_csv("ids_labeled_clean.csv")
    file = open("Deleted.txt")
    file.print(to_delete)
    file.close()
    # final = final_labelled.copy()

    # final.to_csv("unfiltered_labelled.csv") # Fill in the path for the csv where to write the labeled packets

    # file = open("to_delete.txt", "w") # Fill in the path for the txt file where to write the packets which were dropped from the original packet set because they could not be labeled
    # file.write(str(to_delete))

    # final.close()
    # file.close()

def filter_ids_benign():
    labelled_unfiltered = pd.read_csv("ids_labeled_clean.csv") # Path to the csv file with the labeled packets which need to be filtered based on their label
    training_percentage = 0.2164

    done = False

    # See if the first packets_needed packets are benign, if not then remove the first one, re-compute the number needed and check again until the numbers match
    while not done:
        # Get the number of samples in the unfiltered dataset and the number of packets needed for the training set
        number_data = labelled_unfiltered.shape[0]
        print(number_data)
        packets_needed = int (number_data * training_percentage)
        # Take the possible training set
        print(packets_needed)
        maybe_training = labelled_unfiltered.head(packets_needed)

        # If there are non-benign datapoints in the training set, drop the first non-benign datapoint from the unfiltered data
        if (maybe_training[maybe_training["Label"] == 0].shape[0] != packets_needed):
            print(maybe_training[maybe_training["Label"] == 0].shape[0])
            # Get index of the first row which isn't benign
            not_benign = maybe_training[maybe_training["Label"] != 0].index[0]
            labelled_unfiltered.drop(axis=0, index=not_benign, inplace=True)
        else:
            # If all the datapoints are benign, then save the filtered dataset into a file and end the loop
            labelled_unfiltered.to_csv("ids_labeled_filtered.csv", index=False)
            print("Size of training set: " + str(packets_needed))
            print("Size of final dataset: " + str(labelled_unfiltered.shape[0]))
            done = True

def clean_ids():
    # The file with IDS packet data to be cleaned
    ids_unclean_file = "ids_labeled_clean2.csv"
    ids_unclean = pd.read_csv(ids_unclean_file)

    ids_unclean.drop(columns=["Unnamed: 0.1"], inplace=True)
    ids_unclean.to_csv(ids_unclean_file, index=False)
    
    # Remove rows that have no label (they don't belong to any flow or to multiple flows with different labels)
    # ids_unclean = ids_unclean[ids_unclean["Label"].notna()]
    # ids_unclean.to_csv(ids_unclean_file, index=False)

def make_final_ids():
    ids_clean_file_1 = "ids_labeled_clean1.csv"
    ids_clean_file_2 = "ids_labeled_clean2.csv"
    ids_final_file = "ids_labeled_clean.csv"
    ids_tsv = "ids_filtered.tsv"

    ids_clean_1 = pd.read_csv(ids_clean_file_1)
    ids_clean_2 = pd.read_csv(ids_clean_file_2)

    print(ids_clean_1.shape)
    print(ids_clean_2.shape)

    final_ids = pd.concat([ids_clean_1, ids_clean_2], ignore_index=True)

    print(final_ids.shape)
    print(final_ids)
    final_ids.to_csv(ids_final_file, index=False)
    final_ids.drop(columns=["Label"], inplace=True)
    final_ids.to_csv(ids_tsv, index=False, sep='\t')

def make_actual_final_ids():
    clean_filtered_csv = pd.read_csv("ids_labeled_filtered.csv")
    clean_filtered_csv.drop(columns=["Label"], inplace=True)
    clean_filtered_csv.to_csv("final_ids.tsv", sep='\t', index=False)

def analyze_ids():
    ids_file = "ids_labeled_clean.csv"
    ids_data = pd.read_csv(ids_file)
    ids_data = ids_data[ids_data["Label"] == 1]
    print(ids_data.shape)

# analyze_ids()
# make_final_ids()
# clean_ids()
# label_ids()
# final_labelled = pd.read_csv(TSV_PATH, sep='\t')
# filter_ids_benign()
# fil = "ids_labeled_clean.csv"
# for_k = "ids_filtered.tsv"
# thing = pd.read_csv(fil)
# thing.drop(columns=["Label"], inplace=True)
# thing.to_csv(for_k, index=False, sep='\t')
# half = final_labelled.shape[0] // 2
# final_labelled.head(half).to_csv("IDS_1.csv")
# final_labelled.tail(final_labelled.shape[0] - half).to_csv("IDS_2.csv")
make_actual_final_ids()