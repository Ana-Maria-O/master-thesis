from Kitsune import Kitsune
import numpy as np
import time
import pickle
import psutil
from memory_profiler import profile
import pandas as pd

f_prof = open("memory_profile_ids_features.log", 'w+')

@profile
def generate_RMSES(stream = f_prof):
# def generate_RMSES():
    # Make a function with the following: process.cpu_percent, memory_info, consider memory_percent maybe?,  
    # The file where we store the memory usage logs
    fp = open("memorytest_ids_features.log", 'w+')\


    # File for storing features
    # f = open("ids_gan_features_1", 'w') 
    # f = None

    # Get the process of the current program
    process = psutil.Process()

    # Name of the sample capture zip file
    # capture = ""
    # Name of the pcap file
    capture_pcap = "ids_features.csv"
    # Number of packets to process
    packet_limit = np.Inf
    # How often to display the number of processed packets
    display_freq = 1000

    # KitNET params
    # Max autoencoder size in the ensemble layer
    maxAE_size = 10

    # Number of instances for learning the feature mapping
    # FMinstances = 55236 # MAWI
    # FMinstances = 2500 # For AE size & noise robustness runs
    # FMinstances = 6250 # For size robustness runs
    FMinstances = 80155 # IDS

    # Number of instances for training the anomaly detector
    # ADinstances = 497127 # MAWI
    # ADinstances = 22500 # For AE size & noise robustness runs
    # ADinstances = 56250 # For size robustness runs
    ADinstances = 721399 # IDS

    # total_packets = 2552363 # MAWI
    total_packets = 3704042 # IDS

    # Call cpu_percent to measure how much CPU is used to build Kitsune
    process.cpu_percent()
    # Measure RAM usage before starting Kitsune
    ram_before = process.memory_info().vms

    # Build Kitsune
    # K = Kitsune(capture_pcap, packet_limit, maxAE_size, FMinstances, ADinstances)
    K = Kitsune(capture_pcap, packet_limit, maxAE_size, FMinstances, ADinstances, num_features=100)

    # Measure RAM usage after building Kitsune
    ram_after = process.memory_info().vms

    # Measure the CPU percentage while building Kitsune
    fp.write("CPU percentage used while building Kitsune: " + str(process.cpu_percent()) + "\n")
    # Measure RAM after building Kitsune
    fp.write("RAM used while building Kitsune: " + str(ram_after-ram_before) + "\n")

    print("Running Kitsune:")
    RMSEs = []
    i = 0

    # Call cpu_percent to measure how much CPU is used to process packets
    process.cpu_percent() 
    # Measure RAM usage before processing packets
    ram_before = process.memory_info().vms

    start = time.time()
    # Processing the packets
    # while i < total_packets:
    # while True:
    # Read feature csv
    features = pd.read_csv(capture_pcap).to_numpy()
    for feature in features:
        i +=1
        if i % display_freq == 0:
            print(i)
            print("Current time: " + str(time.time() - start))

        # Process the next packet
        # rmse = K.proc_next_packet()
        rmse = K.proc_feature(feature)
        # rmse = K.return_feature() # For storing features

        # Stop the loop if there are no more packets
        if rmse == -1:
            break
        # Otherwise append the rmse
        RMSEs.append(rmse)

        # For storing features
        # f.write(str(rmse))
        # f.flush()

    stop = time.time()

    # f.close()
    # Measure RAM usage after processing packets
    ram_after = process.memory_info().vms

    # Measure the CPU percentage while processing packets
    fp.write("CPU percentage used while processing packets: " + str(process.cpu_percent()) + "\n")
    # Measure RAM after processing packets
    fp.write("RAM used while processing packets: " + str(ram_after-ram_before) + "\n")

    # Save the results in a pickle file
    pickle.dump(RMSEs, open("ids_features_normal_results.p", "wb"))
    print("Number of lines in p file is " + str(len(RMSEs)))\
    # pickle.dump(RMSEs, open("ids_ganf_961y_results.p", "wb"))
    # The end :)
    print("All packets have been processed. Time elapsed: " + str(stop - start))

if __name__ == "__main__":
    generate_RMSES()