K = Kitsune(capture_pcap, packet_limit, maxAE_size, FMinstances, ADinstances)

# List for packet features
features = []

i = 0

# For each packet
while i < total_packets:
    i +=1

    # Save the current packet's features
    feature = K.return_feature()

    # Append the feature vector to the list of feature vectors
    features.append(feature)
