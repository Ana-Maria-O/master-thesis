import json
import pprint
import pandas as pd
from collections import OrderedDict
import numpy as np
import glob
import ast
import datetime

METRICS_LIST = ['Number of true positives', 'Number of true negatives', 'Number of false positives',
                'Number of false negatives', 'True positive rate', 'True negative rate',
                'False positive rate_Recall', 'False negative rate', 'Accuracy', 'Precision',
                'F1 score', 'P@n (n is 100000)', 'AUC ROC']

# How many external metrics are in the json metrics files per threshold
METRICS_NUMBER = len(METRICS_LIST)

# The metrics where lower values indicate better performance
LOW_PERFORMANCE_METRICS = ["Number of false positives", "Number of false negatives",
                    "False positive rate_Recall", "False negative rate"]

art_numbers = [100, 1000, 5000, 10000, "test"]
attack_names = ["normal", "gan", "ganf", "zoot", "zoou", "hsjt", "hsju"]

# Compare the attacked hardcoded thresholds againts the non-attacked thresholds
def compare_all_thresh(normal_results_file, attack_results_file, output_file):
    # Normal results
    normal_results = json.load(open(normal_results_file, 'r'))

    # Attacked results
    attack_results = json.load(open(attack_results_file, 'r'))

    # Match thresholds to each other
    threshold_matching = {}
    normal_thresholds = []
    attack_thresholds = []

    # Dictionary where the key is a tuple (normal metric, attack metric) and the value is dict with keys 
    # "better" and "equal". The "better" metrics have better performance for the normal set, and the "equal" 
    # metric has the same result for both sets.
    performance_tracker = {}

    # True if the keys of threshold_matching are the attack thresholds
    attack_key = True

    # Figure out threshold numbers
    for th in normal_results.keys():
        if th.replace('.', '').isdigit():
            normal_thresholds += [th]
    
    for th in attack_results.keys():
        if th.replace('.', '').isdigit():
            attack_thresholds += [th]

    # If the number of thresholds is equal, then the mapping is 1 to 1
    if len(normal_thresholds) == len(attack_thresholds):
        threshold_matching = {attack_thresholds[i]: normal_thresholds[i] for i in range(len(attack_thresholds))}
    elif len(normal_thresholds) > len(attack_thresholds):
        # Map the equal thresholds to each other and ignore the used thresholds from the list
        same_th = list(set(normal_thresholds).intersection(attack_results))
        threshold_matching = {i: i for i in same_th}

        # For the remaining attack thresholds, find the normal threshold closest to each one
        for index in reversed(range(len(attack_thresholds))):
            # Ignore the thresholds that have equal values to normal set thresholds
            if attack_thresholds[index] not in threshold_matching.keys():
                # Check the absolute difference between this attack threshold and the rest of the normal 
                # thresholds in order to find the closest available normal threshold
                differences = [abs(float(attack_thresholds[index]) - float(normal_thresholds[i])) for i in range(len(normal_thresholds))]

                while True:
                    # Find the smallest difference and find its corresponding normal threshold
                    # If the normal threshold is available, then map it to the attack threshold
                    mins = [i for i, j in enumerate(differences) if j == min(differences)]
                    # If there are multiple thresholds with the minimum difference, pick the one from the 
                    # smaller normal threshold since the attack thresholds following will be higher and may 
                    # need to be mapped to higher normal thresholds
                    min_dif = mins[-1]

                    # If the normal threshold is available, then map it to the attack threshold
                    if normal_thresholds[min_dif] not in list(threshold_matching.values()):
                        threshold_matching[attack_thresholds[index]] = normal_thresholds[min_dif]
                        break
                    # If not, then change the difference to the max and try again until you find an available
                    # threshold
                    else:
                        differences[min_dif] = max(differences)            
    else:
        # Map the equal thresholds to each other and remove the used thresholds from the list
        attack_key = False # The normal key is the first one in the thresholds tuple
        same_th = list(set(normal_thresholds).intersection(attack_results))
        threshold_matching = {i: i for i in same_th}

        # For the remaining normal thresholds, find the attack threshold closest to each one
        for index in reversed(range(len(normal_thresholds))):
            # Ignore the normal thresholds that have equal values to attack thresholds
            if normal_thresholds[index] not in threshold_matching.keys():
                # Check the absolute difference between this attack threshold and the rest of the normal 
                # thresholds in order to find the closest available normal threshold
                differences = [abs(float(normal_thresholds[index]) - float(attack_thresholds[i])) for i in range(len(attack_thresholds))]

                while True:
                    # Find the smallest difference and find its corresponding attack threshold
                    # If the attack threshold is available, then map it to the normal threshold
                    mins = [i for i, j in enumerate(differences) if j == min(differences)]
                    # If there are multiple thresholds with the minimum difference, pick the one from the 
                    # smaller attack threshold since the normal thresholds following will be higher and may 
                    # need to be mapped to higher attack thresholds
                    min_dif = mins[-1]

                    # If this attack threshold has not been mapped to a normal threshold, do that now
                    if attack_thresholds[min_dif] not in list(threshold_matching.values()):
                        threshold_matching[normal_thresholds[index]] = attack_thresholds[min_dif]
                        break
                    # If not, then change the difference to the max and try again until you find an available threshold
                    else:
                        differences[min_dif] = max(differences)

    # For each pair of thresholds, compare their corresponding metrics values
    for pair in threshold_matching:
        # Get the metrics for the attacked and normal sets based on the thresholds
        if attack_key:
            attack_thresh = pair
            normal_thresh = threshold_matching[pair]
        else:
            attack_thresh = threshold_matching[pair]
            normal_thresh = pair

        attack_metrics = attack_results[attack_thresh]
        normal_metrics = normal_results[normal_thresh]
        performance_tracker[(normal_thresh, attack_thresh)] = {"better": [], "equal": []}
        
    # Find and store which metrics have better or equal performance for this pair of thresholds
        for metric in attack_metrics:
            # Check if the metric should be higher or lower for better performance
            if normal_metrics[metric] == attack_metrics[metric]:
                performance_tracker[(normal_thresh, attack_thresh)]["equal"] += [metric]
            elif metric in LOW_PERFORMANCE_METRICS:
                if normal_metrics[metric] < attack_metrics[metric]:
                    performance_tracker[(normal_thresh, attack_thresh)]["better"] += [metric]
            elif normal_metrics[metric] > attack_metrics[metric]:
                performance_tracker[(normal_thresh, attack_thresh)]["better"] += [metric]

    # Sort the dictionary
    performance_tracker = OrderedDict(sorted(performance_tracker.items()))
    # Do some number crunching
    df_dict = {"Threshold pair": [pair for pair in performance_tracker],
               "# Metrics as expected out of all metrics": [str(len(performance_tracker[pair]["better"])) + "/" + str(METRICS_NUMBER) for pair in performance_tracker],
               "# Metrics as expected out of non-equal metrics": [str(len(performance_tracker[pair]["better"])) + "/" + 
                                                                str(METRICS_NUMBER - len(performance_tracker[pair]["equal"])) 
                                                                for pair in performance_tracker],
                "All metrics with better non-attack performance": [performance_tracker[pair]["better"] for pair in performance_tracker],
                "All metrics with worse non-attack performance": [metric for metric in [np.setdiff1d(list(attack_metrics.keys()),
                                                    performance_tracker[pair]["better"] + performance_tracker[pair]["equal"]).tolist()
                                                    for pair in performance_tracker]],
                "All metrics with the same non_attack performance": [performance_tracker[pair]["equal"] for pair in performance_tracker]}

    final_comp = pd.DataFrame(data=df_dict)
    final_comp.to_csv(open(output_file + ".csv", 'w'), index=False)
    final_comp.to_markdown(open(output_file + ".txt", 'w'), index=False)

    return performance_tracker

# Compare raw auc roc and average precision score of attacked sets to raw auc roc and average precision score
# of the normal set
def compare_pyod_raw_aucroc(metrics_files, threshold_comparison_files, output_file):
    # Load all the metric files
    normal_metrics = json.load(open(metrics_files['normal'][0], 'r'))

    # Dict with all the raw AUC ROC comparisons
    raw_auc_roc_dict = {"Attack" : ["normal"],
                        "Raw AUC ROC score": [normal_metrics["AUC ROC raw scores"]],
                        "Average precision score": [normal_metrics["Average precision score"]],
                        "Normal AUC ROC has better performance" : [None],
                        "Normal average precision score has better performance" : [None]}

    # For each attack, compare raw auc roc and pyod to their normal equivalents
    for attack in attack_names[1:]:
        # Take each case in each attack
        for case in metrics_files[attack]:
            attack_metrics = json.load(open(metrics_files[attack][case], 'r'))

            # Add to the dict to be exported
            raw_auc_roc_dict["Attack"] += [attack + ' ' + str(case)]
            raw_auc_roc_dict["Raw AUC ROC score"] += [attack_metrics["AUC ROC raw scores"]]
            raw_auc_roc_dict["Average precision score"] += [attack_metrics["Average precision score"]]
            raw_auc_roc_dict["Normal AUC ROC has better performance"] += [normal_metrics["AUC ROC raw scores"]
                                                                          > attack_metrics["AUC ROC raw scores"]]
            raw_auc_roc_dict["Normal average precision score has better performance"] += [normal_metrics[
                "Average precision score"] > attack_metrics["Average precision score"]]

            # Open this case's file of threshold pairs comparison
            file = [i for i in threshold_comparison_files 
                                                  if attack + '_' + str(case) + '_' in i][0]
            thresh_pair_comparison = pd.read_csv(file)
            
            # Equal metrics in this comparison
            equal_metrics = []
            # Metrics with better normal performance
            better_normal_metrics = []

            # Count how many pyod attack metrics have worse performance than the normal pyod metrics
            for metric in normal_metrics["null"]:
                if normal_metrics["null"][metric] == attack_metrics["null"][metric]:
                    equal_metrics.append(metric)
                elif metric in LOW_PERFORMANCE_METRICS:
                    if normal_metrics["null"][metric] < attack_metrics["null"][metric]:
                        better_normal_metrics.append(metric)
                else:
                    if normal_metrics["null"][metric] > attack_metrics["null"][metric]:
                        better_normal_metrics.append(metric)
            
            # Add a pyod row to the file where pairs of thresholds are compared
            thresh_pair_comparison.loc[
                len(thresh_pair_comparison.index)] = [('pyod', 'pyod'), 
                                                      str(len(better_normal_metrics)) + "/" + str(METRICS_NUMBER),
                                                      str(len(better_normal_metrics)) + "/" + 
                                                            str(METRICS_NUMBER - len(equal_metrics)),
                                                      better_normal_metrics,
                                                      [x for x in normal_metrics['null'] if x not in better_normal_metrics and x not in equal_metrics],
                                                      equal_metrics]
            
            # Export the new dataframe
            thresh_pair_comparison.to_csv(open(file, 'w'), index=False)
            thresh_pair_comparison.to_markdown(open(file[:-4] + ".txt", 'w'), index=False)

    # Export the raw auc roc comparisons
    json.dump(raw_auc_roc_dict, open(output_file + ".json", 'w'))
    raw_auc_roc_dict_df = pd.DataFrame(data=raw_auc_roc_dict)
    raw_auc_roc_dict_df.to_csv(open(output_file + ".csv", 'w'), index=False)
    raw_auc_roc_dict_df.to_markdown(open(output_file + ".txt", 'w'), index=False)

# Compare the sireos and em values of attacked sets to sireos and auc roc values of normal set
def compare_sireos_em(metrics_files, gan_numbers, ganf_numbers, output_file):
    '''Takes a dictionary of the metrics files, computes the average SIREOS and EM values then exports a 
    table with whether these values are better or worse than the values of the normal set'''

    # Dictionary with the values to be exported
    sireos_em_values_dict = {"Attack": [],
                             "Average SIREOS": [],
                             "Average EM": [],
                             "Is SIREOS worse than normal": [],
                             "Is EM worse than normal": []}
    
    normal_avg_em = None
    normal_avg_sireos = None
    
    for attack in metrics_files:
        if attack == 'gan':
            cases = gan_numbers
        elif attack == 'ganf':
            cases = ganf_numbers
        elif attack != 'normal':
            cases = art_numbers
        else:
            cases = [0]
        
        for case in cases:
            metrics = json.load(open(metrics_files[attack][case], 'r'))\

            # Get all the sireos and em values
            all_sireos = metrics['SIREOS']
            all_em = metrics['EM']

            average_sireos = sum(all_sireos.values()) / len(all_sireos)
            average_em = sum(all_em.values()) / len(all_em)

            sireos_em_values_dict['Attack'].append(attack + " " + str(case))
            sireos_em_values_dict['Average SIREOS'].append(average_sireos)
            sireos_em_values_dict['Average EM'].append(average_em)

            if attack == 'normal':
                normal_avg_em = average_em
                normal_avg_sireos = average_sireos
                sireos_em_values_dict["Is SIREOS worse than normal"].append("-")
                sireos_em_values_dict["Is EM worse than normal"].append("-")
            else:
                # Lower SIREOS is better
                sireos_em_values_dict["Is SIREOS worse than normal"].append(average_sireos > normal_avg_sireos)
                # Bigger EM is better
                sireos_em_values_dict["Is EM worse than normal"].append(average_em < normal_avg_em)

    sireos_em_values_df = pd.DataFrame(data=sireos_em_values_dict)
    sireos_em_values_df.to_csv(output_file + ".csv", index=False)
    sireos_em_values_df.to_markdown(output_file + ".txt", index=False)

# Find the best threshold
def find_best_threshold(metrics_file_name, output_file_name):
    ''' 
    Takes the filename of a metrics json file and the name of the file where to print the return table.
    Returns a dictionary with all the thresholds in the file and the metrics for which each threshold had the 
    best performance, a dataframe with the same information and the name of the best threshold(s)'''
    # Read the metrics file
    metrics_file = json.load(open(metrics_file_name, 'r'))

    # Dictionary with each threshold in the metrics file and how many of its metrics have the best value among all thresholds
    threshold_performance = {}

    # Get all the hardcoded thresholds
    for th in metrics_file.keys():
        if th.replace('.', '').isdigit():
            threshold_performance[th] = {}

    # Add the pyod threshold
    threshold_performance['null'] = {}

    # For each metric, find which threshold has the best value
    for metric in metrics_file['null']:
        # Variables holding the threshold with the current best performance
        max_performance = None
        max_threshold = None

        for threshold in threshold_performance:
            # If this is the fist threshold in the for-loop, put the values associated with it in the best 
            # perfrmance variables
            if max_performance == None:
                max_performance = [metrics_file[threshold][metric]]
                max_threshold = [threshold]
            
            # If this is not the first threshold, first check if the performance on this metric is equal to the
            # current best performance
            elif metrics_file[threshold][metric] == max_performance[0]:
                # max_performance += [metrics_file[threshold][metric]]
                max_threshold += [threshold]

            # Choose which comparisons to make based on whether the current metric reflect better performannce
            # with lower or higher values
            elif metric in LOW_PERFORMANCE_METRICS:
                if metrics_file[threshold][metric] < max_performance[0]:
                    max_performance = [metrics_file[threshold][metric]]
                    max_threshold = [threshold]
            elif metrics_file[threshold][metric] > max_performance[0]:
                max_performance = [metrics_file[threshold][metric]]
                max_threshold = [threshold]

        # Once the threshold with the best performance for this metric has been found, save that
        for index in range(len(max_threshold)):
            threshold_performance[max_threshold[index]][metric] = max_performance[0]

    # The best threshold
    # best_threshold = [th for th in threshold_performance if len(threshold_performance[th]) == max([len(threshold_performance[x]) for x in threshold_performance])]

    # Save and export the dict with the performance of each metric, then also export the best threshold. All of these in a dataframe
    # and table
    threshold_performance_df = pd.DataFrame(data = {"Threshold" : list(threshold_performance.keys()),
                                                  "Best metrics for threshold" : [[(y,metrics_file[th][y]) for y in x] for (th,x) in threshold_performance.items()],
                                                  "Number of best metrics for threshold" : [len(x) for x in list(threshold_performance.values())],})
    threshold_performance_df.to_markdown(open(output_file_name + ".txt", 'w'), index=False)

    # Dump the dict to a file
    thing = json.dumps(threshold_performance, indent = 4)
    jsonfile = open(output_file_name + ".json", "w")
    jsonfile.write(thing)

# Analyze if pyod or hardcoded thresholds are generally the best
def compare_hardcoded_to_pyod(thresholds_files:dict, gan_numbers, ganf_numbers, metrics_files, output_file):
    '''Takes a dict with the filenames of the best threshold comparison files (the json files produced 
    through main(2)), the gan and ganf numbers ans a dict with the files that have all the metrics for every 
    case. Creates a file with a table containing the best hardcoded thresholds and the
    best thresholds in general for each attack (and the normal) case. It also writes in
    standard output if pyod or hardcoded thresholds are better'''

    # Dictionary with the number of best metrics for each threshold in each case
    best_metrics_count = {}

    # Read every file
    for case in thresholds_files:
        # The number of the best metrics for each threhsold in every case
        best_metrics_count[case] = {}

        # Dict with all the info to be exported
        all_best_thresholds = {"Attack" : [],
                           "Best hardcoded threshold(s)" : [],
                           "Best hardcoded thresholds metrics" : [],
                           "Pyod thresholds metrics" : [],
                           "Best threshold(s)" : []}

        for num in range(len(thresholds_files[case])):
            # Figure out which index in this case dictionary to use
            # If this is a gan set, use the current gan number
            if case == 'gan':
                index = gan_numbers[num]
            # If this is a ganf set, use the current ganf number
            elif case == 'ganf':
                index = ganf_numbers[num]
            # If this is a zoo or hsj set, use the current art number
            elif case != 'normal':
                index = art_numbers[num]
            # If this is the normal case, then there is a single file in the list
            else:
                index = 0
            
            # Create a dictionary for this file in the case
            best_metrics_count[case][index] = {}
            dict = json.load(open(thresholds_files[case][num], "r"))

            # Count the number of best metrics for each threshold
            for threshold in dict:
                best_metrics_count[case][index][threshold] = len(dict[threshold])

    # For each instance in each case, make a df of the best hardcore and the pyod metrics with all their values
    # and decide which is the best one
    hard_pyod_comparison_dict = {}
    
    for case in best_metrics_count:
        hard_pyod_comparison_dict[case] = {}

        for num in best_metrics_count[case]:
            # Get the best hardcoded threshold
            best_thresholds = []
            best_metrics_num = 0

            for threshold in best_metrics_count[case][num]:
                # Only check the hardcoded thresholds
                if threshold != 'null':
                    # Check if the number of best values for the threshold in this case is higher than the
                    # previous highest number of best values
                    if best_metrics_count[case][num][threshold] > best_metrics_num:
                        best_thresholds = [threshold]
                        best_metrics_num = best_metrics_count[case][num][threshold]
                    # If the numbers are equal, then add this threshld to the list of thresholds with this 
                    # number of highest values
                    elif best_metrics_count[case][num][threshold] == best_metrics_num:
                        best_thresholds += [threshold]

            # Get the values for each metric corresonding to the best hardcoded threshold(s) and
            # the pyod threshold
            all_metrics = {}
            metrics_file = json.load(open(metrics_files[case][num], 'r'))
            

            for th in best_thresholds:
                all_metrics[th] = metrics_file[th]
            all_metrics['null'] = metrics_file['null']

            # Variable has the value of the threshold with the highest number of best metrics
            if best_metrics_num > best_metrics_count[case][num]['null']:
                best_metric = best_thresholds
            elif best_metrics_num < best_metrics_count[case][num]['null']:
                best_metric = 'pyod'
            else:
                best_metric = 'both'

            # Add the best hardcoded thresholds(s) for this case to the df to be exported
            all_best_thresholds["Best hardcoded threshold(s)"] += [best_thresholds]
            # Add the metris for the best hardcoded threshold(s) for this case to the df to be exported
            all_best_thresholds["Best hardcoded thresholds metrics"] += [[all_metrics[x] for x in best_thresholds]]
            # Add the pyod metrocs
            all_best_thresholds["Pyod thresholds metrics"] += [all_metrics["null"]]
            all_best_thresholds["Best threshold(s)"] += [best_metric]


    # Put the information into a dataframe and export it
    for attack in best_metrics_count:
        all_best_thresholds["Attack"] += [attack + ' ' + str(x) for x in best_metrics_count[attack]]
    
    all_best_thresholds_df = pd.DataFrame(data=all_best_thresholds)
    all_best_thresholds_df.to_csv(open(output_file + ".csv", 'w'), index=False)
    all_best_thresholds_df.to_markdown(open(output_file + ".txt", 'w'), index=False)

# KILLED See if the best threshold as found by main(3) is the same as that found by analysing the 
# output of main(1+4)
# def compare_best_thresholds(main1_best_thresholds_files, main3_best_thresholds_file, gan_numbers, ganf_numbers):
    # '''Takes the files of threshold comparisons produced by main(1+4) and main(3)'''
    # # Open the dataframe produced by main(3) - best threshold in an overall comparison
    # main3_best_thresholds = pd.read_csv(open(main3_best_thresholds_file, 'r'))

    for attack in attack_names:
        # For each case take the best threshold in each of its corresponding files and see if they're the same
        # select the right list of cases based on the attack
        if attack == 'gan':
            cases = gan_numbers
        elif attack == 'ganf':
            cases = ganf_numbers
        elif attack != "normal":
            cases = art_numbers
        else:
            cases = [0]

        # for case in 

    # Open the dataframe

# THIS FUNCTION SHOULD ONLY WORK WITH THE FORMAT OF THE *best_thresholds.csv FILES
def return_metrics_best_thresholds_file(source_row):
    # If the best metric is pyod, then save the pyod metrics. Save the hardcoded metrics otherwise
    if source_row["Best threshold(s)"] == "pyod":
        target_dicts = source_row["Pyod thresholds metrics"]
    # If both pyod and the hardcoded metrics are the best, then save all their metrics
    elif source_row["Best threshold(s)"] == "both":
        target_dicts = "["+ source_row["Pyod thresholds metrics"] + ","
        target_dicts += source_row["Best hardcoded thresholds metrics"][1:]
    # Otherwise, the hardcoded threshold(s) is/are the best
    else:
        target_dicts = source_row["Best hardcoded thresholds metrics"]

    return target_dicts

# Compare the best attacked thresholds againstthe best normal threshold
def compare_best_thresh(best_thresholds_file):
    '''Takes a file with a df that has all the attacks and the normal set with their best thresholds.
    Creates a file with the attacks and for which & how many thresholds they performed worse than 
    normal.'''

    # Read the thresholds dataframe
    best_thresholds = pd.read_csv(best_thresholds_file + ".csv")
    # print(best_thresholds["Best threshold(s)"])

    # Dict with metrics of the normal set
    normal_metrics = {}

    # Lists with the metrics worse than and equal to normal for each attacl case
    all_worse_metrics = [None]
    all_equal_metrics = [None]

    for index, row in best_thresholds.iterrows():
        # Get the metrics of the normal set
        if index == 0:
            normal_metrics = ast.literal_eval(return_metrics_best_thresholds_file(row))
        else:
            # If an attack, get its best metrics
            attack_metrics = ast.literal_eval(return_metrics_best_thresholds_file(row))

            # Number of metrics that are worse than normal
            worse_metrics = []
            # Number of metrics that are equal to normal
            equal_metrics = []

            # Take each set of metrics
            if type(attack_metrics) != list:
                attack_metrics = [attack_metrics]
            if type(normal_metrics) != list:
                normal_metrics = [normal_metrics]

            equal_metrics_for_row = []
            worse_metrics_for_row = [] 

            for metrics in attack_metrics:
                equal_metrics_per_attack = []
                worse_metrics_per_attack = []

                # Take each metric and compare it to normal
                for norm in normal_metrics:
                    equal_metrics_for_normal = []
                    worse_metrics_for_normal = []

                    for metric in norm:
                        # First check if the metrics' values are equal
                        if norm[metric] == metrics[metric]:
                            equal_metrics_for_normal.append(metric)
                        # Check if a lower or a higher value represents better metric performance
                        elif metric in LOW_PERFORMANCE_METRICS:
                            if norm[metric] < metrics[metric]:
                                worse_metrics_for_normal.append(metric)
                        elif norm[metric] > metrics[metric]:
                            worse_metrics_for_normal.append(metric)

                    # Once the lists of all the worse and equal metrics of this attack for this set of normal
                    # metrics is done, add them to the list of all attack metrics
                    equal_metrics_per_attack.append(equal_metrics_for_normal)
                    worse_metrics_per_attack.append(worse_metrics_for_normal)
                
                equal_metrics_for_row.append(equal_metrics_per_attack)
                worse_metrics_for_row.append(worse_metrics_per_attack)

            # Add the list of worse and equal metrics to the big lists of worse and equal metrics
            all_worse_metrics.append(worse_metrics_for_row)
            all_equal_metrics.append(equal_metrics_for_row)

    # Insert new rows into the best_thresholds dataframe
    best_thresholds["Metrics worse than normal"] = all_worse_metrics
    best_thresholds["Metrics equal to normal"] = all_equal_metrics
    best_thresholds["# of worse metrics than normal"] = [None] + [[[len(x) for x in y] for y in z] for z in
                                                                   all_worse_metrics[1:]]
    best_thresholds["# of equal metrics to normal"] = [None] + [[[len(x) for x in y] for y in z] for z in
                                                                   all_equal_metrics[1:]]
    best_thresholds["Worse than normal?"] = [None] + [[[(METRICS_NUMBER - len(a[index1])) < (len(y[index1]) * 2)
                                                         for index1 in range(len(y))] for y,a in zip(z, b)] 
                                                         for z,b in zip(all_worse_metrics[1:], 
                                                                        all_equal_metrics[1:])]
    best_thresholds.to_csv(open(best_thresholds_file + ".csv", 'w'), index=False)
    best_thresholds.to_markdown(open(best_thresholds_file + ".txt", 'w'), index=False)

# TODO: Compare memory and time usage
def memory_time_usage(memory_files, gan_numbers, ganf_numbers, ouput_file):
    memory_times_dict = {"Case" : [],
                         "Time for running the IDS (seconds)" : [],
                         "Time for running the IDS" : [],
                         "Minimum memory usage" : [],
                         "Maximum memory usage" : [],
                         "Average memory usage" : []}
    # for attack in attack_names:
    #     if attack == "gan":
    #         cases = gan_numbers
    #     elif attack == "ganf":
    #         cases = ganf_numbers
    #     elif attack != "normal":
    #         cases = art_numbers
    #     else:
    cases = [0]
        
    for case in cases:
        # memory_time = open(memory_files[attack][case], 'r').readlines()
        memory_time = open(memory_files, 'r').readlines()

        lines = [x.split(' ') for x in memory_time if "MEM" in x]
        first_line = lines[0]
        last_line = lines[-1]

        time = float(last_line[-1]) - float(first_line[-1])

        min_memory = float(first_line[1])
        max_memory = float(first_line[1])
        avg_memory = float(first_line[1])

        for line in lines[1:]:
            if float(line[1]) > max_memory:
                max_memory = float(line[1])
            if float(line[1]) < min_memory:
                min_memory = float(line[1])

            avg_memory += float(line[1])

        memory_times_dict["Case"].append(
            # attack + " " + 
            str(case))
        memory_times_dict["Time for running the IDS (seconds)"].append(time)
        memory_times_dict["Time for running the IDS"].append(datetime.timedelta(seconds=time))
        memory_times_dict["Minimum memory usage"].append(min_memory)
        memory_times_dict["Maximum memory usage"].append(max_memory)
        memory_times_dict["Average memory usage"].append(avg_memory / len(lines))

    memory_times_df = pd.DataFrame(data = memory_times_dict)
    memory_times_df.to_csv(open(ouput_file + ".csv", 'w'), index=False)
    memory_times_df.to_markdown(open(ouput_file + ".txt", 'w'), index=False)

    return None

# Searches all the files with all threshold comparisons to determine how threshold-dependent the metrics are
# Also looks at raw metrics values
def find_metric_volability(file_path, output_path):
    # Get the csvs with all thresholds' analysis
    all_thresholds_comp = glob.glob(file_path + "*all_thresholds_analysis.csv")

    # Dict with all the metrics
    metrics_comp = {met : {"Better than normal" : 0, "Worse than normal" : 0, "Equal to normal" : 0} for
                    met in METRICS_LIST}

    # Go through each threshold analysis file and add the data to the metrics dictionary
    for file in all_thresholds_comp:
        # Load the csv
        anal_csv = pd.read_csv(file)

        # Find the case this csv describes
        case = file.split("\\")[1].split("_")
        # If this is normal, then ignore it
        if case[1] == "normal":
            continue
        else:
            case = case[1:3]

        for index, row in anal_csv.iterrows():
            # Get all the metrics with better normal performance and modify the metrics dict accordingly
            metrics = row["All metrics with better non-attack performance"].replace("[", "").replace("]", "")\
                .replace("'", "").split(", ")
            
            if metrics[0] != '':
                for metric in metrics:
                    metrics_comp[metric]["Worse than normal"] += 1

            # Get all the metrics with worse normal performance and modify the metrics dict accordingly
            metrics = row["All metrics with worse non-attack performance"].replace("[", "").replace("]", "")\
                .replace("'", "").split(", ")
            
            if metrics[0] != '':
                for metric in metrics:
                    metrics_comp[metric]["Better than normal"] += 1

            # Get all the metrics with equal attack and normal performances and modify the metrics dict 
            # accordingly
            metrics = row["All metrics with the same non_attack performance"].replace("[", "").replace("]", "")\
                .replace("'", "").split(", ")
            
            if metrics[0] != '':
                for metric in metrics:
                    metrics_comp[metric]["Equal to normal"] += 1
        # Take each metric in each non-pyod case and count whether it has better performance than normal or not

    # Take the dict and edit it to fit into a csv
    metrics_df_dict = { "Metric" : metrics_comp.keys(),
                       "# Of instances better than normal" : [metrics_comp[i]["Better than normal"] for i in metrics_comp],
                        "# Of instances worse than normal" : [metrics_comp[i]["Worse than normal"] for i in metrics_comp],
                        "# Of instances equal to normal" : [metrics_comp[i]["Equal to normal"] for i in metrics_comp]
    }

    metrics_df = pd.DataFrame(data = metrics_df_dict)
    metrics_df.to_csv(output_path + ".csv", index = False)
    metrics_df.to_markdown(output_path + ".txt", index=False)
    print("aaaaa")


def main(option):
    # What type of output files will be made
    output_name = None
    input_name = None

    if option == 1:
        output_name = "_all_thresholds_analysis"
    if option == 2:
        output_name = "_best_threshold_comparison"
    if option == 3:
        input_name = "_best_threshold_comparison"
        output_name = ""
    if option == 4:
        output_name = "raw_auc_roc_comparison"
    if option in [5, 6, 7, 8]:
        output_name = ""

    folder_name = "Analyses/"
    # Fill in with paths to store the "Analyses" folder
    mawi_file_base = ""
    ids_file_base = ""

    mawi_gan_numbers = [1, 10, 24]
    mawi_ganf_numbers = [1, 60, 113]
    ids_gan_numbers = [1, 10, 300, 603]
    ids_ganf_numbers = [1, 100, 480, 961]

    mawi_normal_file = mawi_file_base + "mawi_normal_metrics.json"
    mawi_gan_files = [mawi_file_base + "mawi_gan_" + str(x) + "_metrics.json" for x in mawi_gan_numbers]
    mawi_ganf_files = [mawi_file_base + "mawi_ganf_" + str(x) + "_metrics.json" for x in mawi_ganf_numbers]
    mawi_zoot_files = [mawi_file_base + "mawi_zoot_" + str(x) + "_metrics.json" for x in art_numbers]
    mawi_zoou_files = [mawi_file_base + "mawi_zoou_" + str(x) + "_metrics.json" for x in art_numbers]
    mawi_hsjt_files = [mawi_file_base + "mawi_hsjt_" + str(x) + "_metrics.json" for x in art_numbers]
    mawi_hsju_files = [mawi_file_base + "mawi_hsju_" + str(x) + "_metrics.json" for x in art_numbers]

    ids_normal_file = ids_file_base + "ids_normal_metrics.json"
    ids_gan_files = [ids_file_base + "ids_gan_" + str(x) + "_metrics.json" for x in ids_gan_numbers]
    ids_ganf_files = [ids_file_base + "ids_ganf_" + str(x) + "_metrics.json" for x in ids_ganf_numbers]
    ids_zoot_files = [ids_file_base + "ids_zoot_" + str(x) + "_metrics.json" for x in art_numbers]
    ids_zoou_files = [ids_file_base + "ids_zoou_" + str(x) + "_metrics.json" for x in art_numbers]
    ids_hsjt_files = [ids_file_base + "ids_hsjt_" + str(x) + "_metrics.json" for x in art_numbers]
    ids_hsju_files = [ids_file_base + "ids_hsju_" + str(x) + "_metrics.json" for x in art_numbers]

    # The names of the output files
    # No file extension
    mawi_normal_output = "mawi_normal" + output_name
    mawi_gan_output = ["mawi_gan_" + str(x) + output_name for x in mawi_gan_numbers]
    mawi_ganf_output = ["mawi_ganf_" + str(x) + output_name for x in mawi_ganf_numbers]
    mawi_zoot_output = ["mawi_zoot_" + str(x) + output_name for x in art_numbers]
    mawi_zoou_output = ["mawi_zoou_" + str(x) + output_name for x in art_numbers]
    mawi_hsjt_output = ["mawi_hsjt_" + str(x) + output_name for x in art_numbers]
    mawi_hsju_output = ["mawi_hsju_" + str(x) + output_name for x in art_numbers]

    ids_normal_output = "ids_normal" + output_name
    ids_gan_output = ["ids_gan_" + str(x) + output_name for x in ids_gan_numbers]
    ids_ganf_output = ["ids_ganf_" + str(x) + output_name for x in ids_ganf_numbers]
    ids_zoot_output = ["ids_zoot_" + str(x) + output_name for x in art_numbers]
    ids_zoou_output = ["ids_zoou_" + str(x) + output_name for x in art_numbers]
    ids_hsjt_output = ["ids_hsjt_" + str(x) + output_name for x in art_numbers]
    ids_hsju_output = ["ids_hsju_" + str(x) + output_name for x in art_numbers]

# Create dictionaries with all metrics files
    if option in [3, 4, 6]:
        # Dictionaries with all the metrics files
        mawi_metrics_files = {}

        for attack in attack_names:
            mawi_metrics_files[attack] = {}
            
            if attack == 'gan':
                for index in range(len(mawi_gan_numbers)):
                    mawi_metrics_files[attack][mawi_gan_numbers[index]] = mawi_gan_files[index]
            # If this is a ganf set, use the current ganf number
            elif attack == 'ganf':
                for index in range(len(mawi_ganf_numbers)):
                    mawi_metrics_files[attack][mawi_ganf_numbers[index]] = mawi_ganf_files[index]
            # If this is a zoo or hsj set, use the current art number
            elif attack == 'zoot':
                for index in range(len(art_numbers)):
                    mawi_metrics_files[attack][art_numbers[index]] = mawi_zoot_files[index]
            elif attack == 'zoou':
                for index in range(len(art_numbers)):
                    mawi_metrics_files[attack][art_numbers[index]] = mawi_zoou_files[index]
            elif attack == 'hsjt':
                for index in range(len(art_numbers)):
                    mawi_metrics_files[attack][art_numbers[index]] = mawi_hsjt_files[index]
            elif attack == 'hsju':
                for index in range(len(art_numbers)):
                    mawi_metrics_files[attack][art_numbers[index]] = mawi_hsju_files[index]
            # If this is the normal case, then there is a single file in the list
            else:
                mawi_metrics_files[attack][0] =  mawi_normal_file
                
        ids_metrics_files = {}
        for attack in attack_names:
            ids_metrics_files[attack] = {}
            
            if attack == 'gan':
                for index in range(len(ids_gan_numbers)):
                    ids_metrics_files[attack][ids_gan_numbers[index]] = ids_gan_files[index]
            # If this is a ganf set, use the current ganf number
            elif attack == 'ganf':
                for index in range(len(ids_ganf_numbers)):
                    ids_metrics_files[attack][ids_ganf_numbers[index]] = ids_ganf_files[index]
            # If this is a zoo or hsj set, use the current art number
            elif attack == 'zoot':
                for index in range(len(art_numbers)):
                    ids_metrics_files[attack][art_numbers[index]] = ids_zoot_files[index]
            elif attack == 'zoou':
                for index in range(len(art_numbers)):
                    ids_metrics_files[attack][art_numbers[index]] = ids_zoou_files[index]
            elif attack == 'hsjt':
                for index in range(len(art_numbers)):
                    ids_metrics_files[attack][art_numbers[index]] = ids_hsjt_files[index]
            elif attack == 'hsju':
                for index in range(len(art_numbers)):
                    ids_metrics_files[attack][art_numbers[index]] = ids_hsju_files[index]
            # If this is the normal case, then there is a single file in the list
            else:
                ids_metrics_files[attack][0] = ids_normal_file

# Create dictionary with mprofile files
# Fill in with the paths to the .dat files output through the memory profiler
    if option == 7:
        mawi_mprofiles = {
            "normal" : {0: "mprofile_mawinormal.dat"},
            "gan" : {
                1 : "mprofile_mawigan1.dat",
                10 : "mprofile_mawigan10.dat",
                24 : "mprofile_mawigan24.dat"
            },
            "ganf" : {
                1 : "mprofile_mawiganf1.dat",
                60 : "mprofile_mawiganf60.dat",
                113 : "mprofile_gan113.dat"
            },
            "zoot" : {
                100 : "mprofile_zoot100.dat",
                1000 : "mprofile_zoot1000.dat",
                5000 : "mprofile_zoot5000.dat",
                10000 : "mprofile_zoot10000.dat",
                "test" : "mprofile_zoottest.dat"
            },
            "zoou" : {
                100 : "mprofile_zoou100.dat",
                1000 : "mprofile_zoou1000.dat",
                5000 : "mprofile_zoou5000.dat",
                10000 : "mprofile_zoou10000.dat",
                "test" : "mprofile_zooutest.dat"
            },
            "hsjt" : {
                100 : "mprofile_hsjt100.dat",
                1000 : "mprofile_hsj1000.dat",
                5000 : "mprofile_hsjt5000.dat",
                10000 : "mprofile_hsjt10000.dat",
                "test" : "mprofile_hsjttest.dat"
            },
            "hsju" : {
                100 : "mprofile_hsj100.dat",
                1000 : "mprofile_hsj1000.dat",
                5000 : "mprofile_hsj5000.dat",
                10000 : "mprofile_hsj10000.dat",
                "test" : "mprofile_hsjtest.dat"
            }
        }

        ids_mprofiles = {
            "normal" : {0: "mprofile_idsnormal.dat"},
            "gan" : {
                1 : "mprofile_idsgan1.dat",
                10 : "mprofile_idsgan10.dat",
                300 : "mprofile_idsgan300.dat",
                603 : "mprofile_idsgan603.dat"
            },
            "ganf" : {
                1 : "mprofile_idsganf1.dat",
                100 : "mprofile_idsganf100.dat",
                480 : "mprofile_idsganf480.dat",
                961 : "mprofile_idsganf961.dat"
            },
            "zoot" : {
                100 : "mprofile_zoot100.dat",
                1000 : "mprofile_zoot1000.dat",
                5000 : "mprofile_zoot5000.dat",
                10000 : "mprofile_zoot10000.dat",
                "test" : "mprofile_zoottest.dat"
            },
            "zoou" : {
                100 : "mprofile_zoou100.dat",
                1000 : "mprofile_zoou1000.dat",
                5000 : "mprofile_zoou5000.dat",
                10000 : "mprofile_zoou10000.dat",
                "test" : "mprofile_zooutest.dat"
            },
            "hsjt" : {
                100 : "mprofile_hsjt100.dat",
                1000 : "mprofile_hsjt1000.dat",
                5000 : "mprofile_hsjt5000.dat",
                10000 : "mprofile_hsjt10000.dat",
                "test" : "mprofile_hsjttest.dat"
            },
            "hsju" : {
                100 : "mprofile_hsju100.dat",
                1000 : "mprofile_hsju1000.dat",
                5000 : "mprofile_hsju5000.dat",
                10000 : "mprofile_hsju10000.dat",
                "test" : "mprofile_hsjutest.dat"
            }
        }

    if option == 1:
        # Run the comparison between all metrics
        # GAN and GANf
        for num in range(len(mawi_gan_numbers)):
            compare_all_thresh(mawi_normal_file, mawi_gan_files[num], mawi_file_base + folder_name + mawi_gan_output[num])
            compare_all_thresh(mawi_normal_file, mawi_ganf_files[num], mawi_file_base + folder_name + mawi_ganf_output[num])

        for num in range(len(ids_gan_numbers)):
            compare_all_thresh(ids_normal_file, ids_gan_files[num], ids_file_base + folder_name + ids_gan_output[num])
            compare_all_thresh(ids_normal_file, ids_ganf_files[num], ids_file_base + folder_name + ids_ganf_output[num])

        # ZOO and HSJ
        for num in range(len(art_numbers)):
            compare_all_thresh(mawi_normal_file, mawi_zoot_files[num], mawi_file_base + folder_name + mawi_zoot_output[num])
            compare_all_thresh(mawi_normal_file, mawi_zoou_files[num], mawi_file_base + folder_name + mawi_zoou_output[num])
            compare_all_thresh(mawi_normal_file, mawi_hsjt_files[num], mawi_file_base + folder_name + mawi_hsjt_output[num])
            compare_all_thresh(mawi_normal_file, mawi_hsju_files[num], mawi_file_base + folder_name + mawi_hsju_output[num])

        # ZOO and HSJ
        for num in range(len(art_numbers)):
            compare_all_thresh(ids_normal_file, ids_zoot_files[num], ids_file_base + folder_name + ids_zoot_output[num])
            compare_all_thresh(ids_normal_file, ids_zoou_files[num], ids_file_base + folder_name + ids_zoou_output[num])
            compare_all_thresh(ids_normal_file, ids_hsjt_files[num], ids_file_base + folder_name + ids_hsjt_output[num])
            compare_all_thresh(ids_normal_file, ids_hsju_files[num], ids_file_base + folder_name + ids_hsju_output[num])

    # Find the best threshold based on external metrics
    if option == 2:
        # Normal results
        find_best_threshold(mawi_normal_file, mawi_file_base + folder_name + mawi_normal_output)
        find_best_threshold(ids_normal_file, ids_file_base + folder_name + ids_normal_output)

        # GAN and GANf
        for num in range(len(mawi_gan_numbers)):
            find_best_threshold(mawi_gan_files[num], mawi_file_base + folder_name + mawi_gan_output[num])
            find_best_threshold(mawi_ganf_files[num], mawi_file_base + folder_name + mawi_ganf_output[num])

        for num in range(len(ids_gan_numbers)):
            find_best_threshold(ids_gan_files[num], ids_file_base + folder_name + ids_gan_output[num])
            find_best_threshold(ids_ganf_files[num], ids_file_base + folder_name + ids_ganf_output[num])

        # ZOO and HSJ
        for num in range(len(art_numbers)):
            find_best_threshold(mawi_zoot_files[num], mawi_file_base + folder_name + mawi_zoot_output[num])
            find_best_threshold(mawi_zoou_files[num], mawi_file_base + folder_name + mawi_zoou_output[num])
            find_best_threshold(mawi_hsjt_files[num], mawi_file_base + folder_name + mawi_hsjt_output[num])
            find_best_threshold(mawi_hsju_files[num], mawi_file_base + folder_name + mawi_hsju_output[num])

        # ZOO and HSJ
        for num in range(len(art_numbers)):
            find_best_threshold(ids_zoot_files[num], ids_file_base + folder_name + ids_zoot_output[num])
            find_best_threshold(ids_zoou_files[num], ids_file_base + folder_name + ids_zoou_output[num])
            find_best_threshold(ids_hsjt_files[num], ids_file_base + folder_name + ids_hsjt_output[num])
            find_best_threshold(ids_hsju_files[num], ids_file_base + folder_name + ids_hsju_output[num])

    if option == 3:
        # Make a dict with all the file names with the dictionaries output in option 2
        mawi_normal_input = "mawi_normal" + input_name
        mawi_gan_input = ["mawi_gan_" + str(x) + input_name for x in mawi_gan_numbers]
        mawi_ganf_input = ["mawi_ganf_" + str(x) + input_name for x in mawi_ganf_numbers]
        mawi_zoot_input = ["mawi_zoot_" + str(x) + input_name for x in art_numbers]
        mawi_zoou_input = ["mawi_zoou_" + str(x) + input_name for x in art_numbers]
        mawi_hsjt_input = ["mawi_hsjt_" + str(x) + input_name for x in art_numbers]
        mawi_hsju_input = ["mawi_hsju_" + str(x) + input_name for x in art_numbers]

        ids_normal_input = "ids_normal" + input_name
        ids_gan_input = ["ids_gan_" + str(x) + input_name for x in ids_gan_numbers]
        ids_ganf_input = ["ids_ganf_" + str(x) + input_name for x in ids_ganf_numbers]
        ids_zoot_input = ["ids_zoot_" + str(x) + input_name for x in art_numbers]
        ids_zoou_input = ["ids_zoou_" + str(x) + input_name for x in art_numbers]
        ids_hsjt_input = ["ids_hsjt_" + str(x) + input_name for x in art_numbers]
        ids_hsju_input = ["ids_hsju_" + str(x) + input_name for x in art_numbers]

        compare_hardcoded_to_pyod(dict(zip(attack_names, 
          [[mawi_file_base + folder_name + mawi_normal_input + ".json"],
           [mawi_file_base + folder_name + mawi_gan_input[x]  + ".json" for x in range(len(mawi_gan_numbers))],
           [mawi_file_base + folder_name + mawi_ganf_input[y]  + ".json" for y in range(len(mawi_ganf_numbers))],
           [mawi_file_base + folder_name + mawi_zoot_input[z]  + ".json" for z in range(len(art_numbers))],
           [mawi_file_base + folder_name + mawi_zoou_input[a]  + ".json" for a in range(len(art_numbers))],
           [mawi_file_base + folder_name + mawi_hsjt_input[b]  + ".json" for b in range(len(art_numbers))],
           [mawi_file_base + folder_name + mawi_hsju_input[c]  + ".json" for c in range(len(art_numbers))]])),
           mawi_gan_numbers, mawi_ganf_numbers, mawi_metrics_files, mawi_file_base + folder_name + "mawi_best_thresholds")
        
        compare_hardcoded_to_pyod(dict(zip(attack_names, 
          [[ids_file_base + folder_name + ids_normal_input + ".json"],
           [ids_file_base + folder_name + ids_gan_input[x]  + ".json" for x in range(len(ids_gan_numbers))],
           [ids_file_base + folder_name + ids_ganf_input[y]  + ".json" for y in range(len(ids_ganf_numbers))],
           [ids_file_base + folder_name + ids_zoot_input[z]  + ".json" for z in range(len(art_numbers))],
           [ids_file_base + folder_name + ids_zoou_input[a]  + ".json" for a in range(len(art_numbers))],
           [ids_file_base + folder_name + ids_hsjt_input[b]  + ".json" for b in range(len(art_numbers))],
           [ids_file_base + folder_name + ids_hsju_input[c]  + ".json" for c in range(len(art_numbers))]])),
           ids_gan_numbers, ids_ganf_numbers, ids_metrics_files, ids_file_base + folder_name + "ids_best_thresholds")
        # compare_all_thresh(mawi_normal_file, mawi_ganf_files[0])

    # Compare pyod and raw AUC ROC
    if option == 4:
        compare_pyod_raw_aucroc(mawi_metrics_files, glob.glob(mawi_file_base + folder_name +
                         "*all_thresholds_analysis.csv"), mawi_file_base + folder_name + 
                                                            "mawi_raw_auc_roc_comparison")
        
        compare_pyod_raw_aucroc(ids_metrics_files, glob.glob(ids_file_base + folder_name +
                         "*all_thresholds_analysis.csv"), ids_file_base + folder_name + 
                                                            "ids_raw_auc_roc_comparison")

    if option == 5:
        compare_best_thresh(mawi_file_base + folder_name + "mawi_best_thresholds")
        compare_best_thresh(ids_file_base + folder_name + "ids_best_thresholds")

    if option == 6:
        compare_sireos_em(mawi_metrics_files, mawi_gan_numbers, mawi_ganf_numbers,
                          mawi_file_base + folder_name + "mawi_sireos_em_comparison")
        compare_sireos_em(ids_metrics_files, ids_gan_numbers, ids_ganf_numbers,
                          ids_file_base + folder_name + "ids_sireos_em_comparison")

    if option == 7:
        memory_time_usage(mawi_mprofiles, mawi_gan_numbers, mawi_ganf_numbers, mawi_file_base + folder_name + "mawi_runtime_and_memory")
        memory_time_usage(ids_mprofiles, ids_gan_numbers, ids_ganf_numbers, ids_file_base + folder_name + "ids_runtime_and_memory")

    if option == 8:
        find_metric_volability(mawi_file_base + folder_name,
                               mawi_file_base + folder_name + "mawi_metrics_volability_analysis")
        
        find_metric_volability(ids_file_base + folder_name,
                               ids_file_base + folder_name + "ids_metrics_volability_analysis")


if __name__ == "__main__":
    # Compare all hardcoded thresholds of attacked sets to normal hardcoded thresholds
    main(1)

    # Analyze what and how many metrics have the best performance for which threshold (one of the hardcoded
    # or pyod)
    main(2)

    # Compare the best hardcoded threshold to the pyod threshold of the normal and each attack set
    #  and see which type of threshold (hardcoded or pyod) has the best performance overall (when comparing the 
    # number of best overall metric value for each case) for mawi and ids respectively
    main(3)

    # Compare the pyod results of the attack sets to the normal set, as well as the raw AUC ROC scores and the 
    # average precision score
    main(4)

    # Compare the best attack thresholds against the best normal threshold
    main(5)
    
    # Compare the average SIREOS and EM values for each attack to the normal set
    main(6)

    # Compare different time and memory usages
    main(7)

    # See how threshold dependent different metrics are
    main(8) 
