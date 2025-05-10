import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import sklearn.metrics
import pickle
import time
from random import sample
from pyod.models.thresholds import CLUST
# from Kitsune import Kitsune

# The labeled dataset
LABELED_DATA = ""

# The dataset with results
RESULT_DATA = ""

# Open the file with labeled data
# ld = open(LABELED_DATA, 'r')

# # Open the file with result data
# rd = open(RESULT_DATA, 'r')

def number_of_true_positives(results:list, truth:list, threshold:float=None) -> float:
    # Return -1 if the lengths of the list of results and truth values don't match
    if len(results) != len(truth):
        raise(Exception("Results and truth lengths do not match"))
    else:
        # Number of results
        n = len(results)
        # Number of true positives
        true_pos = 0
        
        if threshold is not None:
            for index in range(n):
                # predicted_value is 0 if the result is less than threshold (benign) and 1 if higher (malicious)
                predicted_value = 0
                if results[index] >= threshold:
                    predicted_value = 1

                if truth[index] == 1 and predicted_value == 1:
                    true_pos += 1
        else:
            for index in range(n):
            # predicted_value is 0 if the result is less than threshold (benign) and 1 if higher (malicious)
                if truth[index] == 1 and results[index] == 1:
                    true_pos += 1
        
        return true_pos

def number_of_positives(data:list, threshold=None) -> float:
    pos = 0
    # If the threshold is 0, then the data list has values 0 and 1
    if threshold is None:
        pos = sum(data)
    else:
        pos = sum([1 if i >= threshold else 0 for i in data])

    return pos

def number_of_true_negatives(results:list, truth:list, threshold:float=None) -> float:
    # Return -1 if the lengths of the list of results and truth values don't match
    if len(results) != len(truth):
        raise(Exception("Results and truth lengths do not match"))
    else:
        # Number of results
        n = len(results)
        # Number of true positives
        true_neg = 0

        if threshold is not None:
            for index in range(n):
                # predicted_value is 0 if the result is less than threshold (benign) and 1 if higher (malicious)
                predicted_value = 0
                if results[index] >= threshold:
                    predicted_value = 1

                if truth[index] == 0 and predicted_value == 0:
                    true_neg += 1
        else:
            for index in range(n):
                if truth[index] == 0 and results[index] == 0:
                    true_neg += 1
        
        return true_neg

def number_of_negatives(data:list, threshold=None) -> float:
    pos = 0
    # If the threshold is 0, then the data list has values 0 and 1
    if threshold is None:
        pos = len(data) - sum(data)
    else:
        pos = sum([1 if i < threshold else 0 for i in data])

    return pos

def number_of_false_positives(results:list, truth:list, threshold:float=None) -> float:
    # Return -1 if the lengths of the list of results and truth values don't match
    if len(results) != len(truth):
        raise(Exception("Results and truth lengths do not match"))
    else:
        # Number of results
        n = len(results)
        # Number of true positives
        false_pos = 0

        if threshold is not None:
            for index in range(n):
                # predicted_value is 0 if the result is less than threshold (benign) and 1 if higher (malicious)
                predicted_value = 0
                if results[index] >= threshold:
                    predicted_value = 1

                if truth[index] == 0 and predicted_value == 1:
                    false_pos += 1
        else:
            for index in range(n):
                if truth[index] == 0 and results[index] == 1:
                    false_pos += 1
        
        return false_pos

def number_of_false_negatives(results:list, truth:list, threshold:float=None) -> float:
    # Return -1 if the lengths of the list of results and truth values don't match
    if len(results) != len(truth):
        raise(Exception("Results and truth lengths do not match"))
    else:
        # Number of results
        n = len(results)
        # Number of true positives
        false_neg = 0

        if threshold is not None:
            for index in range(n):
                # predicted_value is 0 if the result is less than threshold (benign) and 1 if higher (malicious)
                predicted_value = 0
                if results[index] >= threshold:
                    predicted_value = 1

                if truth[index] == 1 and predicted_value == 0:
                    false_neg += 1
        else:
            for index in range(n):
                if truth[index] == 1 and results[index] == 0:
                    false_neg += 1
        
        return false_neg

# Function for plotting and saving some data in a simple line graph
def plot_data(x_axis: list, y_axis: list, destination_file: str, x_name: str):
    # Make the plot
    x = [i for i in range(len(x_axis))]
    plt.plot(x, y_axis)

    # Make the plot look nice
    plt.xlabel(x_name)
    plt.ylabel("Average precision")

    
    ax = plt.gca()
    plt.xticks(x, x_axis)
    # ax.set_xlim([x_axis[0], x_axis[-1]])

    # Save the plot in a file
    plt.savefig(destination_file)
    plt.clf()


# Call Kitsune and output the file name of the results. Kept in a separate function for easy changes based on output format
def call_Kitsune(fminstances: int, adinstances: int, output_path: str, features ="", dim=10, packets=""):
    results = []

    # If the features variable is not empty, then call Kitsune without the feature extractor
    if features is not "":
        # Get the dataframe with features
        features = pd.read_csv(features).to_numpy()

        # Make a Kitsune instance
        K = Kitsune(None, np.Inf, dim, fminstances, adinstances, num_features=100)

        # Get the results
        for feature in features:
            results.append(K.proc_feature(feature))
    else:
        K = Kitsune(packets, np.inf, dim, fminstances, adinstances)

        while True:
            result = K.proc_next_packet()

            if result == -1:
                break

            results.append(result)
        
    # Output the result pickle file
    pickle.dump(results[(fminstances + adinstances):], open(output_path, 'wb'))
    
    return None


# True positive rate
def true_positive_rate(results:list, truth:list, threshold:float=None) -> float:
    # Get the number of true positives in the results
    true_pos = number_of_true_positives(results, truth, threshold)

    # Get the number of all positives in ground truth data
    all_pos = number_of_positives(truth)

    # Return the true positive rate
    return true_pos / all_pos

# True negative rate
def true_negative_rate(results:list, truth:list, threshold:float=None) -> float:
    # Get the number of true negatives
    true_neg = number_of_true_negatives(results, truth, threshold)    

    # Get the number of all negatives in ground truth data
    all_neg = number_of_negatives(truth)

    # Return the true negative rate
    return true_neg / all_neg

# False positive rate
def false_positive_rate(results:list, truth:list, threshold:float=None) -> float:
    # Get the number of false positives in the results
    false_pos = number_of_false_positives(results, truth, threshold)

    # Get the number of all negatives in ground truth data
    all_neg = number_of_negatives(truth)

    # Return the false positive rate
    return false_pos / all_neg

# False negative rate
def false_negative_rate(results:list, truth:list, threshold:float=None) -> float:
    # Get the number of false negatives in the results
    false_neg = number_of_false_negatives(results, truth, threshold)

    # Get the number of all positives in ground truth data
    all_pos = number_of_positives(truth)

    # Return the false positive rate
    return false_neg / all_pos

# Accuracy
def accuracy(results:list, truth:list, threshold:float=None) -> float:
    # Get number of true negatives in results
    true_neg = number_of_true_negatives(results, truth, threshold)

    # Get the number of true positives in results
    true_pos = number_of_true_positives(results, truth, threshold)

    # Size of the dataset
    # depends on the format of the results and ground truth data
    total_data_number = len(results)

    # Return the accuracy of the results
    return (true_neg + true_pos) / total_data_number

# Precision
def precision(results:list, truth:list, threshold:float=None) -> float:
    if threshold is not None:
        # Get the number of true positives in results
        true_pos = number_of_true_positives(results, truth, threshold)

        # Get the number of all positives in results
        all_pos = number_of_positives(results, threshold)
    else:
        # Get the number of true positives in results
        true_pos = number_of_true_positives(results, truth)

        # Get the number of all positives in results
        all_pos = number_of_positives(results)

    # Return the precision of the results
    if true_pos == all_pos:
        return 1
    if all_pos == 0:
        raise("No positive values in file.")
    return true_pos / all_pos

# F1-score
# Recall = True Positive Rate
def f1_score(precision:float, recall:float) -> float:
    if precision + recall == 0:
        return 0
    return 2 * (precision * recall) / (precision + recall)

# Robustness
# data is the labelled dataset
# PATH is the root of the path where to dump the generated datasets
def generate_data(data, PATH):
    # Number of datasets to generate per case
    count = 5
    # How much of the testing data to be malicious
    outlier_prp = 0.1
    # How much of the total size of the dataset to be training data
    training_prp = 0.25
    # The size of the datasets for dimensionality and noise cases
    basic_size = 100000
    # Sizes of the datasets for size training
    size_sizes = [100, 1000, 10000, 100000, 250000]
    # Proportions of outliers in training data for noise case
    noise_prps = [0.05, 0.25, 0.5, 0.75, 0.9]

    # Labeled dataset
    # data = "labeled_mawi_unifiltered.csv"
    # Number of datapoints from which the original training data was extracted
    training_pre_filter = 2000000

    # Get the labeled dataset into a dataframe
    all_data = pd.read_csv(data)
    # all_data.drop(columns="Unnamed: 0", inplace=True)

    # Path for the new datasets
    # PATH = "Metrics/Robustness/"
    ae_size = "AE_size/"
    size = "size/"
    noise = "noise/"

    # Get the training data and the malicious entries in the training data pool
    training = all_data.head(training_pre_filter)
    training_malicious = training[training["Label"] == 1]
    training = training[training["Label"] == 0]

    # Get the benign and malicious test data
    test_benign = all_data.tail(all_data.shape[0] - training_pre_filter)
    test_malicious = test_benign[test_benign["Label"] == 1]
    test_benign = test_benign[test_benign["Label"] == 0]

    # The number of training data points
    training_size = int(basic_size * training_prp)

    # Number of testing data points
    testing_size = basic_size - training_size
    testing_size_malicious = int(testing_size * outlier_prp)
    testing_size_benign = testing_size - testing_size_malicious

    # Generate datasets for the noise case
    for elem in noise_prps:
        # Get the number of the malicious data points for the training set
        training_malicious_size = int(elem * training_size)
        # Get the number of the benign data points for the training set
        training_benign_size = training_size - training_malicious_size

        for i in range(count):
            # Sample the training and test sets and put them into one dataframe
            noise_dataset = pd.concat([training.sample(training_benign_size), training_malicious.sample(training_malicious_size),
                                       test_benign.sample(testing_size_benign), test_malicious.sample(testing_size_malicious)])
            
            # Order the set based on packet time
            noise_dataset.sort_values(by=["frame.time_epoch"], inplace=True)

            # Convert dataset to csv and store the labels separately
            pickle.dump(noise_dataset["Label"].tolist(), open(PATH + noise + "labels_" + str(elem) + "_" + str(i) + ".p", "wb"))
            noise_dataset.drop(columns="Label").to_csv(PATH + noise + "noise_" + str(elem) + "_" + str(i) + ".tsv", sep='\t', index=False)

    # Generate datasets for the size case
    for elem in size_sizes:
        # Get the training set size
        training_size_size = int(elem * training_prp)

        # Get the malicious and benign test set sizes
        testing_size_size = elem - training_size_size
        testing_malicious_size_size = int(testing_size_size * outlier_prp)
        testing_benign_size_size = testing_size_size - testing_malicious_size_size

        for i in range(count):
            # Sample the training and test sets and put them into one dataframe
            size_dataset = pd.concat([training.sample(training_size_size), test_benign.sample(testing_benign_size_size),
                                       test_malicious.sample(testing_malicious_size_size)], ignore_index=True)
            
            # Order the set based on packet time
            size_dataset.sort_values(by=["frame.time_epoch"], inplace=True)

            # Convert dataset to csv and store the labels separately
            pickle.dump(size_dataset["Label"].tolist(), open(PATH + size + "labels_" + str(elem) + "_" + str(i) + ".p", "wb"))
            size_dataset.drop(columns="Label").to_csv(PATH + size + "size_" + str(elem) + "_" + str(i) + ".tsv", sep='\t', index=False)

    # Generate datasets for the AE size case
    for i in range(count):
        # Concatenate a randomly selected training set, benign testing set and malicious testing set
        ae_dataset = pd.concat([training.sample(training_size), test_benign.sample(testing_size_benign), test_malicious.sample(testing_size_malicious)], ignore_index=True)

        # Sort the data so the packets are in chronological order
        ae_dataset.sort_values(by=["frame.time_epoch"], inplace=True)

        # Convert dataset to csv and store the labels separately
        pickle.dump(ae_dataset["Label"].tolist(), open(PATH + ae_size + "labels_" + str(i) + ".p", "wb"))
        ae_dataset.drop(columns="Label").to_csv(PATH + ae_size + "ae_size_" + str(i) + ".tsv", sep='\t', index=False)


# I want to replace this with AE size
# truth is a dict with the lists of truth values
# dims is the list of AE dimensions used for the plot
# samples is the number of samples tested for each dimension
# root_folder is the root of the path to the results and the truth files for the samples
# training_data_num is the number of training datapoints in each sample
# files is the list of files that Kitsune needs to run on
# results_root is the common root of the file names for the Kitsune result files
# file_length is the number of packets/features to be used
# features is true if the training and test data is made up of features, not packets
# with 100 000 samples and 10% noise in testing set
def dim_robustness(truth:dict, dims:list, samples:int, root_folder:str, files:str, results_root:str, file_length:int, file_base:str, features:bool=False, th:float=None):
    # List of precisions for each dimension
    precisions = []

    training_num = int(file_length * 0.25)

    # List of folders with Kitsune results
    folders = []
    for i in range(samples):
        folders += [results_root + str(x) + "_" + str(i) + ".p" for x in dims]

    # Produce the Kitsune results
    # index = 0
    # for file in files:
    #     for dim in dims:
            
    #         fm_num = int(training_num * 0.1)
    #         ad_num = training_num - fm_num

    #         if features:
    #             call_Kitsune(fm_num, ad_num, root_folder + "/Results_" + str(dim) + "/" + folders[index], features=root_folder + "/" + file, dim=dim)
    #         else:
    #             call_Kitsune(fm_num, ad_num, root_folder + "/Results_" + str(dim) + "/" + folders[index], packets=root_folder + "/" + file, dim=dim)
            
    #         index += 1
     
    # For each dimension to be tested, we get the Kitsune result data and compute its precision, then we add it to a list of precision values
    index = 0
    for dim in dims:
        # Average precision for this dimension
        avg_precision = 0.0

        for sample_num in range(samples):

            # Load the pickle file & remove training results
            result = pickle.load(open(root_folder + "/Results_" + str(dim) + "/" + folders[index + sample_num * len(dims)], "rb"))
            if th == None:
                thresh = threshold(result)
                prec = precision(thresh, truth[sample_num])
            else:
                prec = precision(result, truth[sample_num], th)

            # Add the precision of this sample to the sum of precisions
            avg_precision += prec

        index += 1
        # Get the average precision for the dimension
        avg_precision /= samples
        # Add the average precision to the list of precisions
        precisions.append(avg_precision)    
    
    # We make the robustness plot
    if th == None:
        pf = open(root_folder + "/" + file_base + "ae_size_precisions", "w")
        plot_data(dims, precisions, root_folder + "/" + file_base + "dim_robustness.png", "Max autoencoder size")
    else:
        pf = open(root_folder + "/" + file_base + "ae_size_precisions" + str(th) + ".txt", "w")
        plot_data(dims, precisions, root_folder + "/" + file_base + "dim_robustness_"+ str(th) + ".png", "Max autoencoder size")

    pf.write(str(precisions))
    pf.close()

# truth is a dict with the lists of truth values
# sizes is the list of dataset sizes used for the plot
# samples is the number of samples tested for each dimension
# root_folder is the root of the path to the results and the truth files for the samples
# training is the proportion of training values in each sample
# features is true if the training and test data is made up of features, not packets
def size_robustness(truth:dict, sizes:list[int], samples:int, root_folder:str, training:float, file_base:str, features:bool=False, th:float=None):
    precisions = []

    # List of all the tsv files that need to be run by Kitsune and the names of the results output files
    tsv_files = []
    output_files = []
    for size in sizes:
        tsv_files += ["size_" + str(size) + "_" + str(i) + ".tsv" for i in range(samples)]
        output_files += ["ids_results_rob_size_" + str(size) + "_" + str(i) + ".p" for i in range(samples)]

    # Run Kitsune on the tsv files and save the results
    # index = 0
    # for size in sizes:
    #     train_num = int(size * training)
    #     fm_num = int(train_num * 0.1)
    #     ad_num = train_num - fm_num
        
    #     for sample in range(samples):
    #         if features:
    #             call_Kitsune(fm_num, ad_num, root_folder + "/Results_" + str(size) + "/" + output_files[index], features=root_folder + "/" + tsv_files[index])
    #         else:
    #             call_Kitsune(fm_num, ad_num, root_folder + "/Results_" + str(size) + "/" + output_files[index], packets=root_folder + "/" + tsv_files[index])

    #         index += 1

    # For each size to be tested, we compute the precision of each sample and average them to get the average precision
    index = 0
    for size in sizes:
        folder = "Results_" + str(size)
        
        # Get the precision of each sample
        avg_precision = 0.0

        for sample in range(samples):
            # Load the anomaly scores for the sample
            result = pickle.load(open(root_folder + "/" + folder + "/" + output_files[index], "rb"))
            index += 1
            # Label the results
            if th == None:
                thresh = threshold(result)
                avg_precision += precision(thresh, truth[size][sample])
            else:
                avg_precision += precision(result, truth[size][sample], th)
        
        # Get the average
        avg_precision /= samples
        precisions.append(avg_precision)

    # We make the robustness plot
    if th == None:
        pf = open(root_folder + "/" + file_base + "size_precisions", "w")
        plot_data(sizes, precisions, root_folder + "/" + file_base + "size_robustness.png", "Dataset size")
    else:
        pf = open(root_folder + "/" + file_base + "size_precisions" + str(th) + ".txt", "w")
        plot_data(sizes, precisions, root_folder + "/" + file_base + "size_robustness_" + str(th) + ".png", "Dataset size")
    pf.write(str(precisions))
    pf.close()

# truth is a dict with the lists of truth values
# noises is the list of noise proportions in the training data
# samples is the number of samples tested for each dimension
# root_folder is the root of the path to the results and the truth files for the samples
# training is the preportion of training values in each sample
# training_data_num is the number of training datapoints in each sample
# features is true if the training and test data is made up of features, not packets
def noise_robustness(truth:dict, noises:list[float], samples:int, root_folder:str, training_data_num:int, file_base:str, features:bool=False, th:float=None):
    precisions = []

    # List of all the tsv files that need to be run by Kitsune and the names of the results output files
    tsv_files = []
    output_files = []
    for noise in noises:
        tsv_files += ["noise_" + str(noise) + "_" + str(i) + ".tsv" for i in range(samples)]
        output_files += ["ids_results_rob_noise_" + str(noise) + "_" + str(i) + ".p" for i in range(samples)]
   
    index = 0
    for noise in noises:
        fm_num = int(training_data_num * 0.1)
        ad_num = training_data_num - fm_num
        
        # for sample in range(samples):
        #     if features:
        #         call_Kitsune(fm_num, ad_num, root_folder + "/Results_" + str(noise) + "/" + output_files[index], features=root_folder + "/" + tsv_files[index])
        #     else:
        #         call_Kitsune(fm_num, ad_num, root_folder + "/Results_" + str(noise) + "/" + output_files[index], packets=root_folder + "/" + tsv_files[index])
            
        #     index += 1

    # For each dataset with different noise proportions, get the Kitsune result data and compute its precision, then we add it to a list of precision values
    index = 0
    for noise in noises:
        avg_precision = 0.0
        folder = "Results_" + str(noise)
        for i in range(samples):
            # Get the anomaly scores
            result = pickle.load(open(root_folder + "/" + folder + "/" + output_files[index], "rb"))
            index += 1
            # Threshold the scores
            if th == None:
                thresh = threshold(result)
                avg_precision += precision(thresh, truth[noise][i])
            else:
                avg_precision += precision(result, truth[noise][i], th)
        
        avg_precision /= samples
        precisions.append(avg_precision)

    

    # We make the robustness plot
    if th == None:
        # Dump the list of average precisions
        pf = open(root_folder + "/" + file_base + "noise_precisions", "w")
        plot_data(noises, precisions, root_folder + "/" + file_base + "noise_robustness.png", "Noise proportion")
    else:
        pf = open(root_folder + "/" + file_base + "noise_precisions" + str(th) + ".txt", "w")
        plot_data(noises, precisions, root_folder + "/" + file_base + "noise_robustness_" + str(th) + ".png", "Noise proportion")
    
    pf.write(str(precisions))
    pf.close()

# P@n
def p_at_n(results:list, truth:list, n:int, threshold:float=None, solved_results:list=None) -> float:
    # Get the number of malicious packets from the data
    # malicious_number = number_of_negatives(truth)
    c_results = results
    truth_2 = 0
    correct = 0

    # Get the malicious_number packets with the highest n anomaly scores in the result data
    for i in range(n):
        # Get the maximum value from the results and its index. Add them to results_negatives and truth_2 respectively
        maximum = max(c_results)
        index = results.index(maximum)
        truth_2 = truth[index]
        if threshold != None:
            if truth_2 == (maximum >= threshold):
                correct += 1
        else:
            if truth_2 == solved_results[index]:
                correct += 1

        # Remove the maximum from the results
        c_results.remove(maximum)

    # Compute P@n
    return correct / n

# AUC ROC
def auc_roc(results:list, truth:list, t:float) -> float:
    
    # Convert the results to binary
    binary_results = [1 if i >= t else 0 for i in results]
    
    return sklearn.metrics.roc_auc_score(truth, binary_results)

# Find a threshold for the data
def threshold(results:list):
    th = CLUST(method='somsc')
    return th.eval(results)

# Get metrics for MAWI
def mawi_metrics(LABELED_DATA, RESULT_DATA, METRICS_FILE, benign_sample_unfiltered, total_data, thresholds=[None]):
    # LABELED_DATA = "Attack/GAN/labeled_mawi_gan_attack_39_numbers.csv"
    # LABELED_DATA = "labeled_mawi_filtered.csv"

    # RESULT_DATA = "Attack/GAN/Packet GAN/mawi_results_gan_1.p"
    # RESULT_DATA = "C:/Users/Ana/Documents/KTH/Courses/Tea sis/Code stuff/mawi_results.p"

    # METRICS_FILE = "mawi_metrics_gan_1.txt"
    # METRICS_FILE = "mawi_metrics_benign_pyod.txt"

    f = open(METRICS_FILE, 'w') 

    # How many packets were used as training set
    benign_sample = 552363 # MAWI
    # benign_sample = 801554 # IDS
    # How many packets were filtered total to make the training set
    # benign_sample_unfiltered = 2000000
    # Total number of packets in the unfiltered data
    # total_data = 4000000
    # Value of n for computing P@n
    n = 100000

    # Read the labelled data and the results
    labeled = pd.read_csv(LABELED_DATA).tail(total_data - benign_sample_unfiltered) # The labelled test set
    results = pickle.load(open(RESULT_DATA, "rb"))[benign_sample:] # The results of the test set

    if thresholds == [None]:
        thresh = threshold(results)
        labeled["Anomaly Score"] = thresh
    else:
        labeled["Anomaly Score"] = results
    # print(thresh)
    # print(type(thresh))

    # Add the scores as a column to the labeled data
    
    # labeled["Anomaly Score"] = thresh

    # List of thresholds to be applied

    for th in thresholds:
    #     recall = true_positive_rate(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th)
    # # print("Begin metrics")
    # # recall = true_positive_rate(thresh, labeled["Label"].tolist())
    #     prec = precision(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th)
    # # prec = precision(thresh, labeled["Label"].tolist())

        f.write("Metrics for threshold: %s\n" % th)
        f.write("\n")
    #     f.write("Number of true positives: %s\n" % 
    #             (number_of_true_positives(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th)))
    # # f.write("Number of true positives: %s\n" % 
    # #         (number_of_true_positives(thresh, labeled["Label"].tolist())))
    #             # (number_of_true_positives(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist())))
    #     f.write("Number of true negatives: %s\n" % (number_of_true_negatives(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th)))
    # # f.write("Number of true negatives: %s\n" % (number_of_true_negatives(thresh, labeled["Label"].tolist())))

    #     f.write("Number of false positives: %s\n" % (number_of_false_positives(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th)))
    # # f.write("Number of false positives: %s\n" % (number_of_false_positives(thresh, labeled["Label"].tolist())))
    
    #     f.write("Number of false negatives: %s\n" % (number_of_false_negatives(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th)))
    # # f.write("Number of false negatives: %s\n" % (number_of_false_negatives(thresh, labeled["Label"].tolist())))

    # # print("Part 1 done")

    #     f.write("\n")
    #     f.write("True positive rate: %s\n" % recall)
    #     f.write("True negative rate: %s\n" % (true_negative_rate(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th)))
    # # f.write("True negative rate: %s\n" % (true_negative_rate(thresh, labeled["Label"].tolist())))
    
    #     f.write("False positive rate/Recall: %s\n" % (false_positive_rate(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th)))
    # # f.write("False positive rate/Recall: %s\n" % (false_positive_rate(thresh, labeled["Label"].tolist())))
    
    #     f.write("False negative rate: %s\n" % (false_negative_rate(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th)))
    # # f.write("False negative rate: %s\n" % (false_negative_rate(thresh, labeled["Label"].tolist())))

    # # print("Part 2 done")

    #     f.write("\n")
    #     f.write("Accuracy: %s\n" % (accuracy(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th)))
    # # f.write("Accuracy: %s\n" % (accuracy(thresh, labeled["Label"].tolist())))
    
    #     f.write("Precision: %s\n" % prec)
    #     f.write("F1 score: %s\n" % f1_score(prec, recall))
    #     if th == None:
    #         f.write("P@n (n is %s): %s\n" %(n, p_at_n(results, labeled["Label"].tolist(), n, solved_results=labeled["Anomaly Score"].tolist())))
    #     else:
    #         f.write("P@n (n is %s): %s\n" %(n, p_at_n(results, labeled["Label"].tolist(), n, threshold=th)))
    # f.write("P@n (n is %s): %s\n" %(n, p_at_n(results, labeled["Label"].tolist(), n, solved_results=thresh)))
        f.write("AUC ROC: %s\n" % auc_roc(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist(), th))
        # f.write("AUC ROC with raw anomaly scores: %s\n" % auc_roc(labeled["Anomaly Score"].tolist(), labeled["Label"].tolist()))
    # f.write("AUC ROC with thresholded results: %s\n" % auc_roc(thresh, labeled["Label"].tolist()))
    
        f.write("====================================\n")

    print("All done")

    f.close()

    # benign_data = labeled[labeled["Label"] == "Benign"]
    # anomalous_data = labeled[labeled["Label"] == "Anomalous"]
    # sus_data = labeled[labeled["Label"] == "Suspicious"]

    # print("Average benign score: " + str(benign_data["Anomaly Score"].mean()))
    # print("Average anomalous score: " + str(anomalous_data["Anomaly Score"].mean()))
    # print("Average suspicious score: " + str(sus_data["Anomaly Score"].mean()))

def compare_results(res_1_file, res_2_file):
    res_1 = pickle.load(open(res_1_file, 'rb'))
    res_2 = pickle.load(open(res_2_file, 'rb'))

    if (len(res_1) != len(res_2)):
        print("Lenghts unequal")
    else:
        i = 0
        count = 0
        while i < len(res_1):
            if res_1[i] != res_2[i]:
                print("Row " + str(i + 1) + " has unequal values: " + str(res_1[i]) + ", " + str(res_2[i]))
                count += 1

            i += 1
        
        print("Total number of un-matching scores: " + str(count) + " / " + str(len(res_1)))

def robustness_plots():

    truth = {}
    truth_size = {}
    truth_noise = {}
    dims = [5, 10, 25, 50, 100]
    sizes = [100, 1000, 10000, 100000, 250000]
    # sizes = [250000]
    noises = [0.05, 0.25, 0.5, 0.75, 0.9]
    samples = 5
    pic_file_base = "ids_pyod_"
    # root_folder = "Metrics/Robustness/"
    # root_folder = "Robustness/"
    # root_folder = "/home/ana/datasets/samples_for_robustness/mawi/"
    root_folder = "Robustness/" # Path to the folder where the robustness plots will be saved
    rob_types = ["AE_size", "size", "noise"]
    dim_file_name_root = "ids_results_rob_ae_"
    dim_files = ["ae_size_" + str(i) + ".tsv" for i in range(samples)]
    training_data_num = 25000
    training_proportion = 0.25
    # thresholds = [2, 1.25, 0.3, 0.13, 0.015] # Normal MAWI run
    thresholds = [None]
    # thresholds = [30, 10, 1.2, 0.3, 0.11, 0.012, 0.006] # Normal IDS run

    for th in thresholds:
    # Make plots for AE size
    # Get the files with the correct labels
        for i in range(samples):
            # Ignore the training results
            labels = pickle.load(open(root_folder + rob_types[0] + "/labels_" + str(i) + ".p", "rb"))[training_data_num:]
            truth[i] = labels

        dim_robustness(truth, dims, samples, root_folder + rob_types[0], dim_files, dim_file_name_root, 100000, file_base=pic_file_base, th=th)

    # Make plots for size
    # Get the files with the correct labels
        for size in sizes:
            truth_size[size] = {}
            for i in range(samples):
                labels = pickle.load(open(root_folder + rob_types[1] +"/labels_" + str(size) + "_" + str(i) + ".p", 'rb'))[int(training_proportion * size):]
                truth_size[size][i] = labels
        
        size_robustness(truth_size, sizes, samples, root_folder + rob_types[1], training_proportion, file_base=pic_file_base, th=th)

        # # Make plots for noise
        # # Get the correct labels
        for noise in noises:
            truth_noise[noise] = {}

            for i in range(samples):
                labels = pickle.load(open(root_folder + rob_types[2] + "/labels_" + str(noise) + "_" + str(i) + ".p", 'rb'))[training_data_num:]
                truth_noise[noise][i] = labels
        
        noise_robustness(truth_noise, noises, samples, root_folder + rob_types[2], training_data_num, file_base=pic_file_base, th=th)
    
def test_thresh():
    data = sample(pickle.load(open("mawi_results_gan_1.p", "rb")), 100)

    agg_types = ["agg", "birch", "bang", "bgm", "bsas", "dbscan", "ema", "kmeans", "mbsas", "mshift", "optics", "somsc", "spec", "xmeans"]
    agg_times = dict.fromkeys(agg_types, 0.0)
    samples = 10

    for typ in agg_types:
        try:
            th = CLUST(method=typ)
            for i in range(samples):
                s_time = time.time()
                th.eval(data)
                agg_times[typ] += time.time() - s_time
            
            agg_times[typ] /= samples
        except Exception as e:
            continue
    
    print(agg_times)

def avg_precision_score(truth, scores):
    return sklearn.metrics.average_precision_score(truth, scores)

# gan_num = [0]
# gan_num = [1, 10, 24]
# gan_num = [1, 10, 300, 603]
# gan_num = [1, 60, 113]
# gan_num = [1, 100, 480, 961]
gan_num = [100, 1000, 5000, 10000, "test"]

labeled_data = "labeled_mawi_filtered.csv" # Path to the csv file with the filtered and labeled packets
labeled_unfiltered_data = "labeled_mawi_unifiltered.csv" # Path to the csv file with the unfiltered and labeled packets
robustness_path_root = "Robustness/" # Path to the folder where the robustness plots will be saved
result_data = ["mawi_results.p"] # Path to the pickle file with the Kitsune results of the dataset
metrics_file = ["metrics_mawi_normal.txt"] # Path to the file to write the metrics into

filtered_number = 2000000
# filtered_number = 802797
total_number = 4000000
# total_number = 3705285

# training_number = 552363
training_number = 801554

# thresholds = [[1.5, 1, 0.5, 0.3, 0.05, 0.0125], [1.5, 1, 0.3, 0.05, 0.0125], [1.5, 1, 0.5, 0.25, 0.05, 0.0125]] # GANf 1, 60 & 113
# thresholds = [[2, 1.25, 0.3, 0.125, 0.015], [2, 1.25, 0.07, 0.015]] # GAN 10 & 24
# thresholds = [2, 1.25, 0.3, 0.13, 0.015] # Normal MAWI run
# thresholds = [2, 1.25, 0.3, 0.08, 0.0125] # MAWI GAN 1
# thresholds = [2, 1.25, 0.3, 0.125, 0.015] # MAWI GAN 10
# thresholds = [[2, 1.25, 0.07, 0.015]] # MAWI GAN 24

# thresholds = [[30, 10, 1.2, 0.3, 0.11, 0.012, 0.006]] # Normal IDS
# thresholds = [[17.5, 12.5, 1, 0.24, 0.104, 0.007], [16, 11.5, 1, 0.185, 0.078, 0.0075], [17, 12, 1.75, 0.25, 0.13, 0.011], 
#               [17, 13, 1, 0.25, 0.08, 0.006]] # IDS GAN
# thresholds = [[1.8, 1.45, 0.4, 0.142, 0.015], [2.2, 1.75, 0.15, 0.015], [2.1, 1.7, 0.125, 0.016, 0.011]] # MAWI GAN
# thresholds = [[1.5, 1, 0.5, 0.25, 0.05, 0.0125]] # MAWI GANf [1.5, 1, 0.5, 0.3, 0.05, 0.0125], [1.5, 1, 0.3, 0.05, 0.0125], 
thresholds = [[2.4, 1.8, 0.5, 0.15, 0.05], [2, 1, 0.5, 0.175, 0.07], [1.6, 1.2, 0.2, 0.05, 0.016], 
              [1.55, 1.2, 0.15, 0.075, 0.025]] #, [1500, 750, 7.5, 1.9, 0.5, 0.1]] # IDS ZOOt

for index in range(len(gan_num)):
    # mawi_metrics(labeled_data, result_data[index], metrics_file[index], filtered_number, total_number + gan_num[index], thresholds[index])

    # Add the average precision score to the metrics files

    # Get the true labels and the score output by the NIDS
    if gan_num[index] != "test": 
        truth = pd.read_csv(labeled_data)['Label'].tolist()[(training_number - gan_num[index]):]
        score = pickle.load(open(result_data[index], 'rb'))[training_number:]
    else:
        truth = pd.read_csv(labeled_data)['Label'].tolist()[training_number:] + [1 for i in range(10000)]
        score = pickle.load(open(result_data[index], 'rb'))[training_number:]

    # # Run the function for computing the average precision score
    a_p_score = avg_precision_score(truth, score)
    print(a_p_score)

    # # Open the metrics file and append the average precision score
    metrics = open(metrics_file[index], 'a')
    metrics.write("\nAverage precision score: " + str(a_p_score))
    metrics.close()

# generate_data(labeled_unfiltered_data, robustness_path_root)
# compare_results("mawi_results_gan_39.p", "mawi_results_gan_features_39_.p")
# robustness_plots()
# test_thresh()

# help = pickle.load(open("Metrics/Robustness/AE_size/Results_5/mawi_results_rob_ae_5_0.p", 'rb'))
# print(len(help))