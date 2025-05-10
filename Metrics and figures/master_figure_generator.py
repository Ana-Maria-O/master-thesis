import matplotlib.pyplot as plt
import pandas as pd
import pickle as p
import json
import os

# Compare different metrics
def process_metrics_file(metrics_file_name:str, x_thresh_list:list=[None]):
    lines_per_thresh = 18

    # y: value of metrics
    metrics_file = open(metrics_file_name, 'r').read().splitlines()
    metrics_file = [line.split(': ') for line in metrics_file]

    metrics_per_thresh = {}
    # Get each metric for each threshold
    for i in range(len(x_thresh_list)):
        index = lines_per_thresh * i

        # check that threshold matches
        # if metrics_file[index][1] != str(x_thresh_list[i]):
        #     raise Exception("Thresholds in metrics file doesn't match threshold in threshold file")
        
        dictionary = {}
        '''
        True positives
        '''
        # y_true_pos_mawi_normal = [1054006, 1210660, 1318893, 1366238, 1391071]
        dictionary[metrics_file[index + 2][0]] = float(metrics_file[index + 2][1])

        '''
        True Negatives
        '''
        # y_true_neg_mawi_normal = [494118, 492568, 476531, 433894, 371509]
        dictionary[metrics_file[index + 3][0]] = float(metrics_file[index + 3][1])

        '''
        False Positives
        '''
        # y_false_pos_mawi_normal = [6995, 8545, 24582, 67219, 129604]
        dictionary[metrics_file[index + 4][0]] = float(metrics_file[index + 4][1])

        '''
        False Negatives
        '''
        # y_false_neg_mawi_normal = [444881, 288227, 179994, 132649, 107816]
        dictionary[metrics_file[index + 5][0]] = float(metrics_file[index + 5][1])

        '''
        True positive rate
        '''
        # y_true_pos_rate_mawi_normal = [0.703, 0.808, 0.88, 0.912, 0.928]
        dictionary[metrics_file[index + 7][0]] = float(metrics_file[index + 7][1])

        '''
        True Negative rate
        '''
        # y_true_neg_rate_mawi_normal = [0.986, 0.983, 0.951, 0.866, 0.741]
        dictionary[metrics_file[index + 8][0]] = float(metrics_file[index + 8][1])

        '''
        False Positive rate
        '''
        # y_false_pos_rate_mawi_normal = [0.014, 0.017, 0.049, 0.134, 0.259]
        dictionary[metrics_file[index + 9][0]] = float(metrics_file[index + 9][1])

        '''
        False Negative rate
        '''
        # y_false_neg_rate_mawi_normal = [0.297, 0.192, 0.120, 0.088, 0.072]
        dictionary[metrics_file[index + 10][0]] = float(metrics_file[index + 10][1])

        '''
        Accuracy
        '''
        # y_acc_mawi_normal = [0.774, 0.852, 0.898, 0.9, 0.881]
        dictionary[metrics_file[index + 12][0]] = float(metrics_file[index + 12][1])

        '''
        Precision
        '''
        # y_prec_mawi_normal = [0.993, 0.993, 0.982, 0.953, 0.915]
        dictionary[metrics_file[index + 13][0]] = float(metrics_file[index + 13][1])

        '''
        F1
        '''
        # y_f1_mawi_normal = [0.823, 0.891, 0.928, 0.932, 0.921, 0.711]
        dictionary[metrics_file[index + 14][0]] = float(metrics_file[index + 14][1])

        '''
        P @ n
        '''
        # y_pn_mawi_normal = [0.7895, 0.772, 0.773, 0.757, 0.773]
        dictionary[metrics_file[index + 15][0]] = float(metrics_file[index + 15][1])

        '''
        AUC ROC
        '''
        # y_auc_mawi_normal = [0.943, 0.943, 0.943, 0.943, 0.943, 0.776]
        dictionary[metrics_file[index + 16][0]] = float(metrics_file[index + 16][1])

        metrics_per_thresh[x_thresh_list[i]] = dictionary

    if len(x_thresh_list) > 0 and x_thresh_list[0] != None:
        # AUC ROC with raw scores
        metrics_per_thresh[metrics_file[lines_per_thresh * len(x_thresh_list) + 1][0]] = float(
            metrics_file[lines_per_thresh * len(x_thresh_list) + 1][1])
        
        # Average precision score
        metrics_per_thresh[metrics_file[-1][0]] = float(metrics_file[-1][1])

    return metrics_per_thresh

# x: Thresholds
def generate_dict_for_plot(metrics_file_name:str, x_thresh_list:list, sireos_file_name:str, em_file_name:str,
                            metrics_pyod_file_name:str):
    
    metrics_per_thresh = process_metrics_file(metrics_file_name, x_thresh_list)
    
    metrics_per_thresh.update(process_metrics_file(metrics_pyod_file_name))
    
    sireos_values = open(sireos_file_name, 'r').read().splitlines()
    metrics_per_thresh["SIREOS"] = {}
    for i in range(len(sireos_values)):
        metrics_per_thresh["SIREOS"][i] = float(sireos_values[i])
    
    em_values = open(em_file_name, 'r').read().splitlines()
    metrics_per_thresh["EM"] = {}
    for i in range(len(em_values)):
        metrics_per_thresh["EM"][i] = float(em_values[i])

    return metrics_per_thresh

def gen_pickle_json_metrics_files(file, sireos, em, output_file_root, thresh_list, pyod_file:str):
    metrics_dict = generate_dict_for_plot(file, thresh_list, sireos, em, pyod_file)
    # Dump the pickle file
    p.dump(metrics_dict, open(output_file_root + ".p", "wb"))

    # Dump the json file
    thing = json.dumps(metrics_dict, indent = 4)
    jsonfile = open(output_file_root + ".json", "w")
    jsonfile.write(thing)

def gen_mawi_normal():
    file = "mawi_metrics_benign.txt" # Fill in the path of the txt file with the metrics corresponding to the normal MAWI results, hardcoded thresholding
    pyod_file = "mawi_metrics_benign_pyod.txt" # Fill in the path of the txt file with the metrics corresponding to the normal MAWI results, pyod thresholding
    sireos = "sireos_results.txt" # Fill in the path of the txt file with the SIREOS values corresponding to the normal MAWI results
    em = "em_mawi_results.txt" # Fill in the path of the txt file with the EM values corresponding to the normal MAWI results
    output_file_root = "Results Comparison/normal_mawi_metrics"
    thresh_list = [2, 1.25, 0.3, 0.13, 0.015]
    gen_pickle_json_metrics_files(file, sireos, em, output_file_root, thresh_list, pyod_file)

def gen_mawi_gan(gan_numbers:list):
    thresholds = [[1.8, 1.45, 0.4, 0.142, 0.015], [2.2, 1.75, 0.15, 0.015], [2.1, 1.7, 0.125, 0.016, 0.011]]
    for i in range(len(gan_numbers)):
        num = gan_numbers[i]
        file = "mawi_gan_" + str(num) + "_metrics_hard.txt" # Fill in the path of the txt file with the metrics corresponding to the GAN MAWI results, hardcoded thresholding
        pyod_file = "mawi_gan_" + str(num) + "_metrics_pyod.txt" # Fill in the path of the txt file with the metrics corresponding to the GAN MAWI results, pyod thresholding
        sireos = "sireos_mawi_gan_" + str(num) + ".txt" # Fill in the path of the txt file with the SIREOS values corresponding to the GAN MAWI results
        em = "em_mawi_gan_" + str(num) + "_results.txt" # Fill in the path of the txt file with the EM values corresponding to the GAN MAWI results
        output_file_root = "Results Comparison/mawi_gan_" + str(num) + "_metrics"
        thresh_list = thresholds[i]

        gen_pickle_json_metrics_files(file, sireos, em, output_file_root, thresh_list, pyod_file)

def gen_mawi_ganf(ganf_numbers):
    thresholds = [[1.5, 1, 0.5, 0.3, 0.05, 0.0125], [1.5, 1, 0.3, 0.05, 0.0125], [1.5, 1, 0.5, 0.25, 0.05, 0.0125]]
    for i in range(len(ganf_numbers)):
        num = ganf_numbers[i]
        file = "mawi_metrics_ganf_" + str(num) + ".txt" # Fill in the path of the txt file with the metrics corresponding to the GANf MAWI results, hardcoded thresholding
        pyod_file = "mawi_metrics_ganf_pyod_" + str(num) + ".txt" # Fill in the path of the txt file with the metrics corresponding to the GANf MAWI results, pyod thresholding
        sireos = "mawi_sireos_ganf_" + str(num) + ".txt" # Fill in the path of the txt file with the SIREOS values corresponding to the GANf MAWI results
        em = "em_mawi_results_ganf_" + str(num) + ".txt" # Fill in the path of the txt file with the EM values corresponding to the GANf MAWI results
        output_file_root = "Results Comparison/mawi_ganf_" + str(num) + "_metrics"
        thresh_list = thresholds[i]

        gen_pickle_json_metrics_files(file, sireos, em, output_file_root, thresh_list, pyod_file)

def gen_mawi_zoo(art_numbers):
    thresholds_zoot = [[2.4, 1.8, 0.5, 0.15, 0.05], [2, 1, 0.5, 0.175, 0.07], [1.6, 1.2, 0.2, 0.05, 0.016],
                        [1.55, 1.2, 0.15, 0.075, 0.025], [1500, 750, 7.5, 1.9, 0.5, 0.1]]
    thresholds_zoou = [[1.6, 1.2, 0.2, 0.1, 0.015], [1.55, 1.25, 0.4, 0.2, 0.065, 0.02], [1.75, 1.3, 0.2, 0.07, 0.024, 0.015],
                       [1.5, 1, 0.6, 0.175, 0.032, 0.02], [1500, 700, 8, 1.9, 0.05, 0.01]]
    zoo_tu = ["zoot", "zoou"]
    
    # Trained sets
    for i in range(len(art_numbers)):
        num = art_numbers[i]

        file = ["mawi_" + z + "_metrics_" + str(num) + ".txt" for z in zoo_tu] # Fill in the path of the txt files with the metrics corresponding to the ZOO targeted + untargeted MAWI results, hardcoded thresholding
        pyod_file = ["mawi_" + z + "_metrics_pyod_" + str(num) + ".txt" for z in zoo_tu] # Fill in the path of the txt files with the metrics corresponding to the ZOO targeted + untargeted MAWI results, pyod thresholding
        sireos = ["mawi_sireos_" + z + "_" + str(num) + ".txt" for z in zoo_tu] # Fill in the path of the txt files with the SIREOS values corresponding to the ZOO targeted + untargeted MAWI results
        em = ["mawi_em_" + z + "_" + str(num) + "_results.txt" for z in zoo_tu] # Fill in the path of the txt files with the EM values corresponding to the ZOO targeted + untargeted MAWI results
        output_file_root = ["Results Comparison/mawi_" + z + "_" + str(num) + "_metrics" for z in zoo_tu]
        thresh_list = [thresholds_zoot[i], thresholds_zoou[i]]

        for j in range(2):
            gen_pickle_json_metrics_files(file[j], sireos[j], em[j], output_file_root[j], thresh_list[j], pyod_file[j])
    
def gen_mawi_hsj(art_numbers):
    thresholds_hsjt = [[1.7, 1.35, 0.15, 0.05, 0.0125], [1.6, 1.2, 0.6, 0.175, 0.01], [1.6, 1.25, 0.2, 0.025, 0.015],
                        [1.6, 1.2, 0.6, 0.2, 0.035, 0.015],  [1500, 750, 8, 0.185, 0.05, 0.015]]
    thresholds_hsju = [[2, 1.45, 0.16, 0.06, 0.012], [1.55, 1.3, 0.32, 0.2, 0.07, 0.02], [1.6, 1.2, 0.27, 0.15, 0.06, 0.024, 0.015],
                       [1.5, 1, 0.3, 0.16, 0.032, 0.015], [1500, 750, 8, 0.2, 0.05, 0.01]]
    hsj_tu = ["hsjt", "hsju"]
    
    # Trained sets
    for i in range(len(art_numbers)):
        num = art_numbers[i]

        file = ["mawi_" + z + "_metrics_" + str(num) + ".txt" for z in hsj_tu] # Fill in the path of the txt files with the metrics corresponding to the HSJ targeted + untargeted MAWI results, hardcoded thresholding
        pyod_file = ["mawi_" + z + "_metrics_pyod_" + str(num) + ".txt" for z in hsj_tu] # Fill in the path of the txt files with the metrics corresponding to the HSJ targeted + untargeted MAWI results, pyod thresholding
        sireos = ["sireos_mawi" + z + "_" + str(num) + ".txt" for z in hsj_tu] # Fill in the path of the txt files with the SIREOS values corresponding to the HSJ targeted + untargeted MAWI results
        em = ["em_mawi_" + z + "_" + str(num) + "_results.txt" for z in hsj_tu] # Fill in the path of the txt files with the EM values corresponding to the HSJ targeted + untargeted MAWI results
        output_file_root = ["Results Comparison/mawi_" + z + "_" + str(num) + "_metrics" for z in hsj_tu]
        thresh_list = [thresholds_hsjt[i], thresholds_hsju[i]]

        for j in range(2):
            gen_pickle_json_metrics_files(file[j], sireos[j], em[j], output_file_root[j], thresh_list[j], pyod_file[j])

def gen_ids_normal():
    file = "ids_metrics.txt" # Fill in the path of the txt file with the metrics corresponding to the normal IDS results, hardcoded thresholding
    pyod_file = "ids_metrics_pyod.txt" # Fill in the path of the txt file with the metrics corresponding to the normal IDS results, pyod thresholding
    sireos = "sireos_ids.txt" # Fill in the path of the txt file with the SIREOS values corresponding to the normal IDS results
    em = "em_ids_results.txt" # Fill in the path of the txt file with the EM values corresponding to the normal IDS results
    output_file_root = "Results Comparison/normal_ids_metrics"
    thresh_list = [30, 10, 1.2, 0.3, 0.11, 0.012, 0.006]
    gen_pickle_json_metrics_files(file, sireos, em, output_file_root, thresh_list, pyod_file)

def gen_ids_gan(gan_numbers:list):
    thresholds = [[17.5, 12.5, 1, 0.24, 0.104, 0.007], [16, 11.5, 1, 0.185, 0.078, 0.0075], [17, 12, 1.75, 0.25, 0.13, 0.011],
                  [17, 13, 1, 0.25, 0.08, 0.006]]
    for i in range(len(gan_numbers)):
        num = gan_numbers[i]
        file = "ids_gan_" + str(num) + "_metrics_hard.txt" # Fill in the path of the txt file with the metrics corresponding to the GAN IDS results, hardcoded thresholding
        pyod_file = "ids_gan_" + str(num) + "_metrics_pyod.txt" # Fill in the path of the txt file with the metrics corresponding to the GAN IDS results, pyod thresholding
        sireos = "sireos_ids_gan_" + str(num) + ".txt" # Fill in the path of the txt file with the SIREOS values corresponding to the GAN IDS results
        em = "em_ids_gan_" + str(num) + "_results.txt" # Fill in the path of the txt file with the EM values corresponding to the GAN IDS results
        output_file_root = "Results Comparison/ids_gan_" + str(num) + "_metrics"
        thresh_list = thresholds[i]

        gen_pickle_json_metrics_files(file, sireos, em, output_file_root, thresh_list, pyod_file)

def gen_ids_ganf(ganf_numbers):
    thresholds = [[20, 10, 1.5, 0.3, 0.104, 0.007], [15, 7, 2, 0.4, 0.06, 0.006], [15, 6, 2, 0.3, 0.07, 0.006],
                   [20, 10, 1.75, 0.35, 0.065, 0.005]]
    for i in range(len(ganf_numbers)):
        num = ganf_numbers[i]
        file = "ids_ganf_" + str(num) + "_metrics_hard.txt" # Fill in the path of the txt file with the metrics corresponding to the GANf IDS results, hardcoded thresholding
        pyod_file = "ids_ganf_" + str(num) + "_metrics_pyod.txt" # Fill in the path of the txt file with the metrics corresponding to the GANf IDS results, pyod thresholding
        sireos = "sireos_ids_ganf_" + str(num) + ".txt" # Fill in the path of the txt file with the SIREOS values corresponding to the GANf IDS results
        em = "em_ids_ganf_" + str(num) + "_results.txt" # Fill in the path of the txt file with the EM values corresponding to the GANf IDS results
        output_file_root = "Results Comparison/ids_ganf_" + str(num) + "_metrics"
        thresh_list = thresholds[i]

        gen_pickle_json_metrics_files(file, sireos, em, output_file_root, thresh_list, pyod_file)

def gen_ids_zoo(art_numbers):
    thresholds_zoot = [[15, 10, 2, 0.35, 0.1, 0.005], [19, 10, 1.8, 0.325, 0.08, 0.006], [12.5, 6, 2.5, 0.3, 0.085, 0.007],
                       [70, 30, 1.8, 0.375, 0.14, 0.006], [20, 10, 1.3, 0.35, 0.11, 0.006]]
    thresholds_zoou = [[15, 10, 1.9, 0.318, 0.1, 0.006], [16, 10, 1.8, 0.4, 0.08, 0.006], [12.5, 7.5, 2.5, 0.3, 0.09, 0.006],
                       [80, 35, 1.775, 0.375, 0.135, 0.006], [20, 10, 1.3, 0.35, 0.11, 0.006]]
    zoo_tu = ["zoot", "zoou"]
    
    # Trained sets
    for i in range(len(art_numbers)):
        num = art_numbers[i]

        file = ["ids_" + z + "_" + str(num) + "_metrics_hard.txt" for z in zoo_tu] # Fill in the path of the txt files with the metrics corresponding to the ZOO targeted + untargeted IDS results, hardcoded thresholding
        pyod_file = ["ids_" + z + "_" + str(num) +"_metrics_pyod.txt" for z in zoo_tu] # Fill in the path of the txt files with the metrics corresponding to the ZOO targeted + untargeted IDS results, pyod thresholding
        sireos = ["sireos_ids_" + z + "_" + str(num) + ".txt" for z in zoo_tu] # Fill in the path of the txt files with the SIREOS values corresponding to the ZOO targeted + untargeted IDS results
        em = ["em_ids_" + z + "_" + str(num) + "_results.txt" for z in zoo_tu] # Fill in the path of the txt files with the EM values corresponding to the ZOO targeted + untargeted IDS results
        output_file_root = ["Results Comparison/ids_" + z + "_" + str(num) + "_metrics" for z in zoo_tu]
        thresh_list = [thresholds_zoot[i], thresholds_zoou[i]]

        for j in range(2):
            gen_pickle_json_metrics_files(file[j], sireos[j], em[j], output_file_root[j], thresh_list[j], pyod_file[j])
    
def gen_ids_hsj(art_numbers):
    thresholds_hsjt = [[15, 7, 2, 0.325, 0.1, 0.006], [15, 7, 1.75, 0.325, 0.075, 0.006], [12, 7.5, 2.5, 0.26, 0.1, 0.006],
                       [70, 45, 1.75, 0.375, 0.136, 0.006], [20, 10, 1.3, 0.35, 0.11, 0.006]]
    thresholds_hsju = [[20, 7.5, 1.87, 0.4, 0.1, 0.006], [19, 10, 1.8, 0.39, 0.0925, 0.006], [30, 12, 2.5, 0.315, 0.09, 0.006],
                       [70, 30, 1.78, 0.37, 0.12, 0.006], [20, 10, 1.3, 0.34, 0.11, 0.006]]
    zoo_tu = ["hsjt", "hsju"]
    
    # Trained sets
    for i in range(len(art_numbers)):
        num = art_numbers[i]

        file = ["metrics_ids_" + z + "_" + str(num) + "_hard.txt" for z in zoo_tu] # Fill in the path of the txt files with the metrics corresponding to the HSJ targeted + untargeted IDS results, hardcoded thresholding
        pyod_file = ["metrics_ids_" + z + "_" + str(num) + "_pyod.txt" for z in zoo_tu] # Fill in the path of the txt files with the metrics corresponding to the HSJ targeted + untargeted IDS results, pyod thresholding
        sireos = ["sireos_ids_" + z + "_" + str(num) + ".txt" for z in zoo_tu] # Fill in the path of the txt files with the SIREOS values corresponding to the HSJ targeted + untargeted IDS results
        em = ["em_ids_" + z + "_" + str(num) + "_results.txt" for z in zoo_tu] # Fill in the path of the txt files with the EM values corresponding to the HSJ targeted + untargeted IDS results
        output_file_root = ["Results Comparison/ids_" + z + "_" + str(num) + "_metrics" for z in zoo_tu]
        thresh_list = [thresholds_hsjt[i], thresholds_hsju[i]]

        for j in range(2):
            gen_pickle_json_metrics_files(file[j], sireos[j], em[j], output_file_root[j], thresh_list[j], pyod_file[j])

def generate_pictures(th, metrics_file, fig_name, h_line:bool=False):
    # Normal thresholds metrics comparison
     metrics = json.load(open(metrics_file, 'rb'))

     for met in metrics[str(th[0])].keys():
        # if "Number" in met:
        fig, ax = plt.subplots()
        
        ax.set_xlabel("Threshold")
        ax.set_ylabel(met)
        
        ax.ticklabel_format(style='plain')

        if h_line:
            plt.axhline(y=metrics["null"][met], linestyle=':')
        
        mets = [metrics[str(i)][met] for i in th]

        ax.plot(th, mets)

            # plt.show()
        # plt.savefig("Results comparison/Pics/Comparison to normal/Pyod/" + fig_name + met + ".png")
        # if "Number" not in met:
        #     plt.savefig("Results Comparison/Pics/" + fig_name + met + ".png")
        # else:
        plt.show()

def generate_comparison_metrics(normal_metrics_file:str, normal_thresh:list, gan_nums:list, gan_thresh:list, gan_metrics_files:list,
                                ganf_nums:list, ganf_thresh:list, ganf_metrics_files:list, art_nums:list, zoot_thresh:list,
                                zoot_metrics_files:list, zoou_thresh:list, zoou_metrics_files:list, hsjt_thresh:list,
                                hsjt_metrics_files:list, hsju_thresh:list, hsju_metrics_files:list):
    normal_metrics = json.load(open(normal_metrics_file, 'r'))
    gan_metrics = [json.load(open(gan_metrics_files[i], 'r')) for i in range(len(gan_thresh))]
    ganf_metrics = [json.load(open(ganf_metrics_files[i], 'r')) for i in range(len(ganf_thresh))]
    zoot_metrics = [json.load(open(zoot_metrics_files[i], 'r')) for i in range(len(zoot_thresh))]
    zoou_metrics = [json.load(open(zoou_metrics_files[i], 'r')) for i in range(len(zoou_thresh))]
    hsjt_metrics = [json.load(open(hsjt_metrics_files[i], 'r')) for i in range(len(hsjt_thresh))]
    hsju_metrics = [json.load(open(hsju_metrics_files[i], 'r')) for i in range(len(hsju_thresh))]
    
    metrics = normal_metrics[str(normal_thresh[0])].keys()
    for metric in metrics:
        # Set up the empty plot
        fig, ax = plt.subplots()
        ax.set_xlabel("Threshold")
        ax.set_ylabel(metric)
        ax.ticklabel_format(style='plain')

        # Add normal line:
        ax.plot(normal_thresh, [normal_metrics[str(th)][metric] for th in normal_thresh], label="Normal")

        # Add GAN lines
        # for index in range(len(gan_nums)):
            # ax.plot(gan_thresh[index], [gan_metrics[index][str(th)][metric] for th in gan_thresh[index]], label = "GAN " + str(gan_nums[index]))

        # Add GANf line
        # for index in range(len(ganf_nums)):
        #     ax.plot(ganf_thresh[index], [ganf_metrics[index][str(th)][metric] for th in ganf_thresh[index]], label = "GANf " + str(ganf_nums[index]))
        
        # for index in range(len(art_nums) - 1):
        for index in [len(art_nums) - 1]:
            # Add ZOO lines
            # ax.plot(zoot_thresh[index], [zoot_metrics[index][str(th)][metric] for th in zoot_thresh[index]], label = "ZOOt " + str(art_nums[index]))
            # ax.plot(zoou_thresh[index], [zoou_metrics[index][str(th)][metric] for th in zoou_thresh[index]], label = "ZOOu " + str(art_nums[index]))
        
        #     # Add HSJ lines
            # ax.plot(hsjt_thresh[index], [hsjt_metrics[index][str(th)][metric] for th in hsjt_thresh[index]], label = "HSJt " + str(art_nums[index]))
            ax.plot(hsju_thresh[index], [hsju_metrics[index][str(th)][metric] for th in hsju_thresh[index]], label = "HSJu " + str(art_nums[index]))
        
        plt.legend(loc="upper right")
        # plt.savefig("all_hsjt_ids_" + metric + ".png")
        # if "Number" in metric:
        plt.show()

def plot_one_line(x:list, y:list, x_name:str, y_name:str, save:bool, label=None, name:str=None, multiple:bool=False, h_line=None):
    
    fig, ax = plt.subplots()

    ax.set_xlabel(x_name)
    ax.set_ylabel(y_name)
    # ax.ticklabel_format(style='plain')

    if multiple:
        for index in range(len(x)):
            fuck = x[index]
            you = y[index]
            ax.plot(x[index], y[index], label=label[index])
    else: 
        ax.plot(x, y, label=label)

    if label != None:
        plt.legend(loc="upper right")

    if h_line != None:
        plt.axhline(y=h_line, linestyle=':')

    if save:
        if name == None:
            raise Exception("No file name for figure has been provided")
        
        plt.savefig(name + ".png")
    else:
        plt.show()

def generate_ireos_sireos_comparison(normal_sireos_file_name, gan_sireos_file_name:list, ganf_sireos_file_name:list, zoot_sireos_file_name:list,
                                      zoou_sireos_file_name:list, hsjt_sireos_file_name:list, hsju_sireos_file_name:list, iteration_number, 
                                      gan_numbers, ganf_numbers, art_numbers):
    
    # Get the SIREOS and EM values
    normal_sireos = list(json.load(open(normal_sireos_file_name, 'r'))["SIREOS"].values())
    gan_sireos = [json.load(open(x, 'r'))["SIREOS"].values() for x in gan_sireos_file_name]
    ganf_sireos = [json.load(open(x, 'r'))["SIREOS"].values() for x in ganf_sireos_file_name]
    zoot_sireos = [json.load(open(x, 'r'))["SIREOS"].values() for x in zoot_sireos_file_name]
    zoou_sireos = [json.load(open(x, 'r'))["SIREOS"].values() for x in zoou_sireos_file_name]
    hsjt_sireos = [json.load(open(x, 'r'))["SIREOS"].values() for x in hsjt_sireos_file_name]
    hsju_sireos = [json.load(open(x, 'r'))["SIREOS"].values() for x in hsju_sireos_file_name]

    normal_em = list(json.load(open(normal_sireos_file_name, 'r'))["EM"].values())
    gan_em = [json.load(open(x, 'r'))["EM"].values() for x in gan_sireos_file_name]
    ganf_em = [json.load(open(x, 'r'))["EM"].values() for x in ganf_sireos_file_name]
    zoot_em = [json.load(open(x, 'r'))["EM"].values() for x in zoot_sireos_file_name]
    zoou_em = [json.load(open(x, 'r'))["EM"].values() for x in zoou_sireos_file_name]
    hsjt_em = [json.load(open(x, 'r'))["EM"].values() for x in hsjt_sireos_file_name]
    hsju_em = [json.load(open(x, 'r'))["EM"].values() for x in hsju_sireos_file_name]

    # SIREOS + EM graphs for different cases, x axis is the iteration number
    x_name = "Iteration name"
    y_s_name = "SIREOS value"
    y_e_name = "EM value"

    # plot_one_line(range(iteration_number), normal_sireos, x_name, y_s_name, True,name="normal_mawi_sireos")
    # plot_one_line([range(iteration_number) for i in gan_sireos], gan_sireos, x_name, y_s_name, True,name="gan_mawi_sireos"
    #               , multiple=True, label=["GAN " + str(x) for x in gan_numbers])
    # plot_one_line([range(iteration_number) for i in ganf_sireos], ganf_sireos, x_name, y_s_name, True,name="ganf_mawi_sireos"
    #               , multiple=True, label=["GANf " + str(x) for x in ganf_numbers])
    # plot_one_line([range(iteration_number) for i in zoot_sireos], zoot_sireos, x_name, y_s_name, True,name="zoot_mawi_sireos"
    #               , multiple=True, label=["ZOOt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in zoou_sireos], zoou_sireos, x_name, y_s_name, True,name="zoou_mawi_sireos"
    #               , multiple=True, label=["ZOOu " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in hsjt_sireos], hsjt_sireos, x_name, y_s_name, True,name="hsjt_mawi_sireos"
    #               , multiple=True, label=["HSJt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in hsju_sireos], hsju_sireos, x_name, y_s_name, True,name="hsju_mawi_sireos"
    #               , multiple=True, label=["HSJu " + str(x) for x in art_numbers])

    # plot_one_line(range(iteration_number), normal_sireos, x_name, y_s_name, True,name="normal_ids_sireos")
    # plot_one_line([range(iteration_number) for i in gan_sireos], gan_sireos, x_name, y_s_name, True,name="gan_ids_sireos"
    #               , multiple=True, label=["GAN " + str(x) for x in gan_numbers])
    # plot_one_line([range(iteration_number) for i in ganf_sireos], ganf_sireos, x_name, y_s_name, True,name="ganf_ids_sireos"
    #               , multiple=True, label=["GANf " + str(x) for x in ganf_numbers])
    # plot_one_line([range(iteration_number) for i in zoot_sireos], zoot_sireos, x_name, y_s_name, True,name="zoot_ids_sireos"
    #               , multiple=True, label=["ZOOt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in zoou_sireos], zoou_sireos, x_name, y_s_name, True,name="zoou_ids_sireos"
                #   , multiple=True, label=["ZOOu " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in hsjt_sireos], hsjt_sireos, x_name, y_s_name, True,name="hsjt_ids_sireos"
    #               , multiple=True, label=["HSJt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in hsju_sireos], hsju_sireos, x_name, y_s_name, True,name="hsju_ids_sireos"
    #               , multiple=True, label=["HSJu " + str(x) for x in art_numbers])

    # plot_one_line(range(iteration_number), normal_em, x_name, y_e_name, True,name="normal_mawi_em")
    # plot_one_line([range(iteration_number) for i in gan_em], gan_em, x_name, y_e_name, True,name="gan_mawi_em"
    #               , multiple=True, label=["GAN " + str(x) for x in gan_numbers])
    # plot_one_line([range(iteration_number) for i in ganf_em], ganf_em, x_name, y_e_name, True,name="ganf_mawi_em"
    #               , multiple=True, label=["GANf " + str(x) for x in ganf_numbers])
    # plot_one_line([range(iteration_number) for i in zoot_em], zoot_em, x_name, y_e_name, True,name="zoot_mawi_em"
    #               , multiple=True, label=["ZOOt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in zoou_em], zoou_em, x_name, y_e_name, True,name="zoou_mawi_em"
    #               , multiple=True, label=["ZOOu " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in hsjt_em], hsjt_em, x_name, y_e_name, True,name="hsjt_mawi_em"
    #               , multiple=True, label=["HSJt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in hsju_em], hsju_em, x_name, y_e_name, True,name="hsju_mawi_em"
    #               , multiple=True, label=["HSJu " + str(x) for x in art_numbers])

    # plot_one_line(range(iteration_number), normal_em, x_name, y_e_name, True,name="normal_ids_em")
    # plot_one_line([range(iteration_number) for i in gan_em], gan_em, x_name, y_e_name, True,name="gan_ids_em"
    #               , multiple=True, label=["GAN " + str(x) for x in gan_numbers])
    # plot_one_line([range(iteration_number) for i in ganf_em], ganf_em, x_name, y_e_name, True,name="ganf_ids_em"
    #               , multiple=True, label=["GANf " + str(x) for x in ganf_numbers])
    # plot_one_line([range(iteration_number) for i in zoot_em], zoot_em, x_name, y_e_name, True,name="zoot_ids_em"
    #               , multiple=True, label=["ZOOt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in zoou_em], zoou_em, x_name, y_e_name, True,name="zoou_ids_em"
    #               , multiple=True, label=["ZOOu " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in hsjt_em], hsjt_em, x_name, y_e_name, True,name="hsjt_ids_em"
    #               , multiple=True, label=["HSJt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in hsju_em], hsju_em, x_name, y_e_name, True,name="hsju_ids_em"
    #               , multiple=True, label=["HSJu " + str(x) for x in art_numbers])

    # Compare SIREOS + EM 
    # SIREOS
    plot_one_line([range(iteration_number) for i in range(len(gan_sireos) + 1)], [normal_sireos] + gan_sireos, x_name, y_s_name, True,name="gan_mawi_sireos_comp"
                  , multiple=True, label= ["Normal GAN"] + ["GAN " + str(x) for x in gan_numbers])
    plot_one_line([range(iteration_number) for i in range(len(ganf_sireos) + 1)], [normal_sireos] + ganf_sireos, x_name, y_s_name, True,name="ganf_mawi_sireos_comp"
                  , multiple=True, label= ["Normal GANf"] + ["GANf " + str(x) for x in ganf_numbers])
    plot_one_line([range(iteration_number) for i in range(len(zoot_sireos) + 1)], [normal_sireos] + zoot_sireos, x_name, y_s_name, True,name="zoot_mawi_sireos_comp"
                  , multiple=True, label= ["Normal ZOOt"] + ["ZOOt " + str(x) for x in art_numbers])
    plot_one_line([range(iteration_number) for i in range(len(zoou_sireos) + 1)], [normal_sireos] + zoou_sireos, x_name, y_s_name, True,name="zoou_mawi_sireos_comp"
                  , multiple=True, label= ["Normal ZOOu"] + ["ZOOu " + str(x) for x in art_numbers])
    plot_one_line([range(iteration_number) for i in range(len(hsjt_sireos) + 1)], [normal_sireos] + hsjt_sireos, x_name, y_s_name, True,name="hsjt_mawi_sireos_comp"
                  , multiple=True, label= ["Normal HSJt"] + ["HSJt " + str(x) for x in art_numbers])
    plot_one_line([range(iteration_number) for i in range(len(hsju_sireos) + 1)], [normal_sireos] + hsju_sireos, x_name, y_s_name, True,name="hsju_mawi_sireos_comp"
                  , multiple=True, label= ["Normal HSJu"] + ["HSJu " + str(x) for x in art_numbers])


    # plot_one_line([range(iteration_number) for i in range(len(gan_sireos) + 1)], [normal_sireos] + gan_sireos, x_name, y_s_name, True,name="gan_ids_sireos_comp"
    #               , multiple=True, label= ["Normal GAN"] + ["GAN " + str(x) for x in gan_numbers])
    # plot_one_line([range(iteration_number) for i in range(len(ganf_sireos) + 1)], [normal_sireos] + ganf_sireos, x_name, y_s_name, True,name="ganf_ids_sireos_comp"
    #               , multiple=True, label= ["Normal GANf"] + ["GANf " + str(x) for x in ganf_numbers])
    # plot_one_line([range(iteration_number) for i in range(len(zoot_sireos) + 1)], [normal_sireos] + zoot_sireos, x_name, y_s_name, True,name="zoot_ids_sireos_comp"
    #               , multiple=True, label= ["Normal ZOOt"] + ["ZOOt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in range(len(zoou_sireos) + 1)], [normal_sireos] + zoou_sireos, x_name, y_s_name, True,name="zoou_ids_sireos_comp"
    #               , multiple=True, label= ["Normal ZOOu"] + ["ZOOu " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in range(len(hsjt_sireos) + 1)], [normal_sireos] + hsjt_sireos, x_name, y_s_name, True,name="hsjt_ids_sireos_comp"
    #               , multiple=True, label= ["Normal HSJt"] + ["HSJt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in range(len(hsju_sireos) + 1)], [normal_sireos] + hsju_sireos, x_name, y_s_name, True,name="hsju_ids_sireos_comp"
    #               , multiple=True, label= ["Normal HSJu"] + ["HSJu " + str(x) for x in art_numbers])
    
    plot_one_line([range(iteration_number) for i in range(len(gan_em) + 1)], [normal_em] + gan_em, x_name, y_e_name, True,name="gan_mawi_em_comp"
                  , multiple=True, label= ["Normal GAN"] + ["GAN " + str(x) for x in gan_numbers])
    plot_one_line([range(iteration_number) for i in range(len(ganf_em) + 1)], [normal_em] + ganf_em, x_name, y_e_name, True,name="ganf_mawi_em_comp"
                  , multiple=True, label= ["Normal GANf"] + ["GANf " + str(x) for x in ganf_numbers])
    plot_one_line([range(iteration_number) for i in range(len(zoot_em) + 1)], [normal_em] + zoot_em, x_name, y_e_name, True,name="zoot_mawi_em_comp"
                  , multiple=True, label= ["Normal ZOOt"] + ["ZOOt " + str(x) for x in art_numbers])
    plot_one_line([range(iteration_number) for i in range(len(zoou_em) + 1)], [normal_em] + zoou_em, x_name, y_e_name, True,name="zoou_mawi_em_comp"
                  , multiple=True, label= ["Normal ZOOu"] + ["ZOOu " + str(x) for x in art_numbers])
    plot_one_line([range(iteration_number) for i in range(len(hsjt_em) + 1)], [normal_em] + hsjt_em, x_name, y_e_name, True,name="hsjt_mawi_em_comp"
                  , multiple=True, label= ["Normal HSJt"] + ["HSJt " + str(x) for x in art_numbers])
    plot_one_line([range(iteration_number) for i in range(len(hsju_em) + 1)], [normal_em] + hsju_em, x_name, y_e_name, True,name="hsju_mawi_em_comp"
                  , multiple=True, label= ["Normal HSJu"] + ["HSJu " + str(x) for x in art_numbers])

    # plot_one_line([range(iteration_number) for i in range(len(gan_em) + 1)], [normal_em] + gan_em, x_name, y_e_name, True,name="gan_ids_em_comp"
    #               , multiple=True, label= ["Normal GAN"] + ["GAN " + str(x) for x in gan_numbers])
    # plot_one_line([range(iteration_number) for i in range(len(ganf_em) + 1)], [normal_em] + ganf_em, x_name, y_e_name, True,name="ganf_ids_em_comp"
    #               , multiple=True, label= ["Normal GANf"] + ["GANf " + str(x) for x in ganf_numbers])
    # plot_one_line([range(iteration_number) for i in range(len(zoot_em) + 1)], [normal_em] + zoot_em, x_name, y_e_name, True,name="zoot_ids_em_comp"
    #               , multiple=True, label= ["Normal ZOOt"] + ["ZOOt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in range(len(zoou_em) + 1)], [normal_em] + zoou_em, x_name, y_e_name, True,name="zoou_ids_em_comp"
    #               , multiple=True, label= ["Normal ZOOu"] + ["ZOOu " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in range(len(hsjt_em) + 1)], [normal_em] + hsjt_em, x_name, y_e_name, True,name="hsjt_ids_em_comp"
    #               , multiple=True, label= ["Normal HSJt"] + ["HSJt " + str(x) for x in art_numbers])
    # plot_one_line([range(iteration_number) for i in range(len(hsju_em) + 1)], [normal_em] + hsju_em, x_name, y_e_name, True,name="hsju_ids_em_comp"
    #               , multiple=True, label= ["Normal HSJu"] + ["HSJu " + str(x) for x in art_numbers])

    # Graph with the different sireos/em average values, each point is a value and the x axis are the different cases
    # normal_sireos_avg = sum(normal_sireos) / len(normal_sireos)
    # gan_sireos_avg = [sum(x) / len(x) for x in gan_sireos]
    # ganf_sireos_avg = [sum(x) / len(x) for x in ganf_sireos]
    # zoot_sireos_avg = [sum(x) / len(x) for x in zoot_sireos]
    # zoou_sireos_avg = [sum(x) / len(x) for x in zoou_sireos]
    # hsjt_sireos_avg = [sum(x) / len(x) for x in hsjt_sireos]
    # hsju_sireos_avg = [sum(x) / len(x) for x in hsju_sireos]

    # normal_em_avg = sum(normal_em) / len(normal_em)
    # gan_em_avg = [sum(x) / len(x) for x in gan_em]
    # ganf_em_avg = [sum(x) / len(x) for x in ganf_em]
    # zoot_em_avg = [sum(x) / len(x) for x in zoot_em]
    # zoou_em_avg = [sum(x) / len(x) for x in zoou_em]
    # hsjt_em_avg = [sum(x) / len(x) for x in hsjt_em]
    # hsju_em_avg = [sum(x) / len(x) for x in hsju_em]

    # plot_one_line(gan_numbers, gan_sireos_avg,"GAN number", "SIREOS value", True, name="average_sireos_gan_comp", h_line=normal_sireos_avg)
    # plot_one_line(ganf_numbers, ganf_sireos_avg,"GANf number", "SIREOS value", True, name="average_sireos_ganf_comp", h_line=normal_sireos_avg)
    # plot_one_line(art_numbers, zoot_sireos_avg,"ZOOt number", "SIREOS value", True, name="average_sireos_zoot_comp", h_line=normal_sireos_avg)
    # plot_one_line(art_numbers, zoou_sireos_avg,"ZOOu number", "SIREOS value", True, name="average_sireos_zoou_comp", h_line=normal_sireos_avg)
    # plot_one_line(art_numbers, hsjt_sireos_avg,"HSJt number", "SIREOS value", True, name="average_sireos_hsjt_comp", h_line=normal_sireos_avg)
    # plot_one_line(art_numbers, hsju_sireos_avg,"HSJu number", "SIREOS value", True, name="average_sireos_hsju_comp", h_line=normal_sireos_avg)

    # plot_one_line(gan_numbers, gan_em_avg,"GAN number", "EM value", True, name="average_sireos_gan_comp", h_line=normal_em_avg)
    # plot_one_line(ganf_numbers, ganf_em_avg,"GANf number", "EM value", True, name="average_sireos_ganf_comp", h_line=normal_em_avg)
    # plot_one_line(art_numbers, zoot_em_avg,"ZOOt number", "EM value", True, name="average_sireos_zoot_comp", h_line=normal_em_avg)
    # plot_one_line(art_numbers, zoou_em_avg,"ZOOu number", "EM value", True, name="average_sireos_zoou_comp", h_line=normal_em_avg)
    # plot_one_line(art_numbers, hsjt_em_avg,"HSJt number", "EM value", True, name="average_sireos_hsjt_comp", h_line=normal_em_avg)
    # plot_one_line(art_numbers, hsju_em_avg,"HSJu number", "EM value", True, name="average_sireos_hsju_comp", h_line=normal_em_avg)

def generate_raw_and_pyod(normal_metrics_file, gan_metrics_file, ganf_metrics_file, zoot_metrics_file, zoou_metrics_file,
                          hsjt_metrics_file, hsju_metrics_file, gan_num, ganf_num, art_num):
    
    pyod_key = "null"

    normal_metrics = json.load(open(normal_metrics_file, 'r'))
    gan_metrics = [json.load(open(x, 'r')) for x in gan_metrics_file]
    ganf_metrics = [json.load(open(x, 'r')) for x in ganf_metrics_file]
    zoot_metrics = [json.load(open(x, 'r')) for x in zoot_metrics_file]
    zoou_metrics = [json.load(open(x, 'r')) for x in zoou_metrics_file]
    hsjt_metrics = [json.load(open(x, 'r')) for x in hsjt_metrics_file]
    hsju_metrics = [json.load(open(x, 'r')) for x in hsju_metrics_file]

    # Compare raw AUC ROC scores
    normal_raw = normal_metrics["AUC ROC raw scores"]
    gan_raw = [x["AUC ROC raw scores"] for x in gan_metrics]
    ganf_raw = [x["AUC ROC raw scores"] for x in ganf_metrics]
    zoot_raw = [x["AUC ROC raw scores"] for x in zoot_metrics]
    zoou_raw = [x["AUC ROC raw scores"] for x in zoou_metrics]
    hsjt_raw = [x["AUC ROC raw scores"] for x in hsjt_metrics]
    hsju_raw = [x["AUC ROC raw scores"] for x in hsju_metrics]

    # plot_one_line(gan_num, gan_raw, "GAN number", "AUC ROC value", True, name="gan_raw_auc_roc", h_line=normal_raw)
    # plot_one_line(ganf_num, ganf_raw, "GANf number", "AUC ROC value", True, name="ganf_raw_auc_roc", h_line=normal_raw)
    plot_one_line(art_num, zoot_raw, "ZOOt number", "AUC ROC value", True, name="zoot_raw_auc_roc", h_line=normal_raw)
    plot_one_line(art_num, zoou_raw, "ZOOu number", "AUC ROC value", True, name="zoou_raw_auc_roc", h_line=normal_raw)
    plot_one_line(art_num, hsjt_raw, "HSJt number", "AUC ROC value", True, name="hsjt_raw_auc_roc", h_line=normal_raw)
    plot_one_line(art_num, hsju_raw, "HSJu number", "AUC ROC value", True, name="hsju_raw_auc_roc", h_line=normal_raw)

    # Compare PYOD metrics
    normal_pyod = normal_metrics[pyod_key]
    for metric in normal_pyod.keys():

        gan_pyod = [x[pyod_key][metric] for x in gan_metrics]
        ganf_pyod = [x[pyod_key][metric] for x in ganf_metrics]
        zoot_pyod = [x[pyod_key][metric] for x in zoot_metrics]
        zoou_pyod = [x[pyod_key][metric] for x in zoou_metrics]
        hsjt_pyod = [x[pyod_key][metric] for x in hsjt_metrics]
        hsju_pyod = [x[pyod_key][metric] for x in hsju_metrics]
        
        # plot_one_line(gan_num, gan_pyod, "GAN number", metric, True, name="gan_pyod_" + metric, h_line=normal_pyod[metric])
        # plot_one_line(ganf_num, ganf_pyod, "GANf number", metric, True, name="ganf_pyod_" + metric, h_line=normal_pyod[metric])
        plot_one_line(art_num, zoot_pyod, "ZOOt number", metric, True, name="zoot_pyod_" + metric, h_line=normal_pyod[metric])
        plot_one_line(art_num, zoou_pyod, "ZOOu number", metric, True, name="zoou_pyod_" + metric, h_line=normal_pyod[metric])
        plot_one_line(art_num, hsjt_pyod, "HSJt number", metric, True, name="hsjt_pyod_" + metric, h_line=normal_pyod[metric])
        plot_one_line(art_num, hsju_pyod, "HSJu number", metric, True, name="hsju_pyod_" + metric, h_line=normal_pyod[metric])

# MAWI
gan_numbers_mawi = [1, 10, 24]
gan_numbers_ids = [1, 10, 300, 603] # IDS

ganf_numbers_mawi = [1, 60, 113]
ganf_numbers_ids =[1, 100, 480, 961]

art_numbers = [100, 1000, 5000, 10000, "test"]

gen_mawi_normal()
gen_mawi_gan(gan_numbers_mawi)
gen_mawi_ganf(ganf_numbers_mawi)
gen_mawi_zoo(art_numbers)
gen_mawi_hsj(art_numbers)

# IDS
gen_ids_normal()
gen_ids_gan(gan_numbers_ids)
gen_ids_ganf(ganf_numbers_ids)
gen_ids_zoo(art_numbers)
gen_ids_hsj(art_numbers)


# normal_mawi_thresh = [2, 1.25, 0.3, 0.13, 0.015]
# gan_mawi_thresh = [[1.8, 1.45, 0.4, 0.142, 0.015], [2.2, 1.75, 0.15, 0.015], [2.1, 1.7, 0.125, 0.016, 0.011]]
# ganf_mawi_thresh = [[1.5, 1, 0.5, 0.3, 0.05, 0.0125], [1.5, 1, 0.3, 0.05, 0.0125], [1.5, 1, 0.5, 0.25, 0.05, 0.0125]]
# zoot_mawi_thresh = [[2.4, 1.8, 0.5, 0.15, 0.05], [2, 1, 0.5, 0.175, 0.07], [1.6, 1.2, 0.2, 0.05, 0.016],
#                         [1.55, 1.2, 0.15, 0.075, 0.025], [1500, 750, 7.5, 1.9, 0.5, 0.1]]
# zoou_mawi_thresh = [[1.6, 1.2, 0.2, 0.1, 0.015], [1.55, 1.25, 0.4, 0.2, 0.065, 0.02], [1.75, 1.3, 0.2, 0.07, 0.024, 0.015],
#                        [1.5, 1, 0.6, 0.175, 0.032, 0.02], [1500, 700, 8, 1.9, 0.05, 0.01]]
# hsjt_mawi_thresh = [[1.7, 1.35, 0.15, 0.05, 0.0125], [1.6, 1.2, 0.6, 0.175, 0.01], [1.6, 1.25, 0.2, 0.025, 0.015],
#                         [1.6, 1.2, 0.6, 0.2, 0.035, 0.015],  [1500, 750, 8, 0.185, 0.05, 0.015]]
# hsju_mawi_thresh = [[2, 1.45, 0.16, 0.06, 0.012], [1.55, 1.3, 0.32, 0.2, 0.07, 0.02], [1.6, 1.2, 0.27, 0.15, 0.06, 0.024, 0.015],
#                        [1.5, 1, 0.3, 0.16, 0.032, 0.015], [1500, 750, 8, 0.2, 0.05, 0.01]]

# normal_ids_thresh = [30, 10, 1.2, 0.3, 0.11, 0.012, 0.006]
# gan_ids_thresh = [[17.5, 12.5, 1, 0.24, 0.104, 0.007], [16, 11.5, 1, 0.185, 0.078, 0.0075], [17, 12, 1.75, 0.25, 0.13, 0.011],
#                   [17, 13, 1, 0.25, 0.08, 0.006]]
# ganf_ids_thresh = [[20, 10, 1.5, 0.3, 0.104, 0.007], [15, 7, 2, 0.4, 0.06, 0.006], [15, 6, 2, 0.3, 0.07, 0.006],
#                    [20, 10, 1.75, 0.35, 0.065, 0.005]]
# zoot_ids_thresh = [[15, 10, 2, 0.35, 0.1, 0.005], [19, 10, 1.8, 0.325, 0.08, 0.006], [12.5, 6, 2.5, 0.3, 0.085, 0.007],
#                        [70, 30, 1.8, 0.375, 0.14, 0.006], [20, 10, 1.3, 0.35, 0.11, 0.006]]
# zoou_ids_thresh = [[15, 10, 1.9, 0.318, 0.1, 0.006], [16, 10, 1.8, 0.4, 0.08, 0.006], [12.5, 7.5, 2.5, 0.3, 0.09, 0.006],
#                        [80, 35, 1.775, 0.375, 0.135, 0.006], [20, 10, 1.3, 0.35, 0.11, 0.006]]
# hsjt_ids_thresh = [[15, 7, 2, 0.325, 0.1, 0.006], [15, 7, 1.75, 0.325, 0.075, 0.006], [12, 7.5, 2.5, 0.26, 0.1, 0.006],
#                        [70, 45, 1.75, 0.375, 0.136, 0.006], [20, 10, 1.3, 0.35, 0.11, 0.006]]
# hsju_ids_thresh = [[20, 7.5, 1.87, 0.4, 0.1, 0.006], [19, 10, 1.8, 0.39, 0.0925, 0.006], [30, 12, 2.5, 0.315, 0.09, 0.006],
#                        [70, 30, 1.78, 0.37, 0.12, 0.006], [20, 10, 1.3, 0.34, 0.11, 0.006]]

# normal_mawi_metrics =  "normal_mawi_metrics.json"
# gan_mawi_metrics = ["mawi_gan_" + str(num) + "_metrics.json" for num in gan_numbers_mawi]
# ganf_mawi_metrics = ["mawi_ganf_" + str(num) + "_metrics.json" for num in ganf_numbers_mawi]
# zoot_mawi_metrics = ["mawi_zoot_" + str(num) + "_metrics.json" for num in art_numbers]
# zoou_mawi_metrics = ["mawi_zoou_" + str(num) + "_metrics.json" for num in art_numbers]
# hsjt_mawi_metrics = ["mawi_hsjt_" + str(num) + "_metrics.json" for num in art_numbers]
# hsju_mawi_metrics = ["mawi_hsju_" + str(num) + "_metrics.json" for num in art_numbers]

# normal_ids_metrics = "Results Comparison/normal_ids_metrics.json"
# gan_ids_metrics = ["Results comparison/ids_gan_" + str(num) + "_metrics.json" for num in gan_numbers_ids]
# ganf_ids_metrics = ["Results comparison/ids_ganf_" + str(num) + "_metrics.json" for num in ganf_numbers_ids]
# zoot_ids_metrics = ["Results comparison/ids_zoot_" + str(num) + "_metrics.json" for num in art_numbers]
# zoou_ids_metrics = ["Results comparison/ids_zoou_" + str(num) + "_metrics.json" for num in art_numbers]
# hsjt_ids_metrics = ["Results comparison/ids_hsjt_" + str(num) + "_metrics.json" for num in art_numbers]
# hsju_ids_metrics = ["Results comparison/ids_hsju_" + str(num) + "_metrics.json" for num in art_numbers]

# normal_mawi_fig = "normal_mawi_"
# gan_mawi_fig = ["gan_mawi_" + str(num) + "_" for num in gan_numbers_mawi]
# ganf_mawi_fig = ["ganf_mawi_" + str(num) + "_" for num in ganf_numbers_mawi]
# zoot_mawi_fig = ["zoot_mawi_" + str(num) + "_" for num in art_numbers]
# zoou_mawi_fig = ["zoou_mawi_" + str(num) + "_" for num in art_numbers]
# hsjt_mawi_fig = ["hsjt_mawi_" + str(num) + "_" for num in art_numbers]
# hsju_mawi_fig = ["hsju_mawi_" + str(num) + "_" for num in art_numbers]

# normal_ids_fig = "normal_ids_"
# normal_ids_fig = "normal_pyod_ids_"

# gan_ids_fig = ["gan_ids_" + str(num) + "_" for num in gan_numbers_ids]
# ganf_ids_fig = ["ganf_ids_" + str(num) + "_" for num in ganf_numbers_ids]
# zoot_ids_fig = ["zoot_ids_" + str(num) + "_" for num in art_numbers]
# zoou_ids_fig = ["zoou_ids_" + str(num) + "_" for num in art_numbers]
# hsjt_ids_fig = ["hsjt_ids_" + str(num) + "_" for num in art_numbers]
# hsju_ids_fig = ["hsju_ids_" + str(num) + "_" for num in art_numbers]

# generate_pictures(normal_mawi_thresh, normal_mawi_metrics, normal_mawi_fig)
# generate_pictures(normal_ids_thresh, normal_ids_metrics, normal_ids_fig)

# Normal metrics with dashed line where the pyod value is
# generate_pictures(normal_mawi_thresh, normal_mawi_metrics, normal_mawi_fig, h_line=True)
# generate_pictures(normal_ids_thresh, normal_ids_metrics, normal_ids_fig, h_line=True)


# for i in range(len(art_numbers)):
    # generate_pictures(gan_mawi_thresh[i], gan_mawi_metrics[i], gan_mawi_fig[i])
    # generate_pictures(ganf_mawi_thresh[i], ganf_mawi_metrics[i], ganf_mawi_fig[i])
    # generate_pictures(zoot_mawi_thresh[i], zoot_mawi_metrics[i], zoot_mawi_fig[i])
    # generate_pictures(zoou_mawi_thresh[i], zoou_mawi_metrics[i], zoou_mawi_fig[i])
    # generate_pictures(hsjt_mawi_thresh[i], hsjt_mawi_metrics[i], hsjt_mawi_fig[i])
    # generate_pictures(hsju_mawi_thresh[i], hsju_mawi_metrics[i], hsju_mawi_fig[i])

    # generate_pictures(gan_ids_thresh[i], gan_ids_metrics[i], gan_ids_fig[i])
    # generate_pictures(ganf_ids_thresh[i], ganf_ids_metrics[i], ganf_ids_fig[i])
    # generate_pictures(zoot_ids_thresh[i], zoot_ids_metrics[i], zoot_ids_fig[i])
    # generate_pictures(zoou_ids_thresh[i], zoou_ids_metrics[i], zoou_ids_fig[i])

# Compare all metrics accross scenarios PLUS raw auc roc
# generate_comparison_metrics(normal_mawi_metrics, normal_mawi_thresh, gan_numbers_mawi, gan_mawi_thresh, gan_mawi_metrics,
#                             ganf_numbers_mawi, ganf_mawi_thresh, ganf_mawi_metrics, art_numbers, zoot_mawi_thresh, zoot_mawi_metrics,
#                             zoou_mawi_thresh, zoou_mawi_metrics, hsjt_mawi_thresh, hsjt_mawi_metrics, hsju_mawi_thresh,
#                             hsju_mawi_metrics)

# HSJ left
# generate_comparison_metrics(normal_ids_metrics, normal_ids_thresh, gan_numbers_ids, gan_ids_thresh, gan_ids_metrics,
#                             ganf_numbers_ids, ganf_ids_thresh, ganf_ids_metrics, art_numbers, zoot_ids_thresh, zoot_ids_metrics,
#                             zoou_ids_thresh, zoou_ids_metrics, hsjt_ids_thresh, hsjt_ids_metrics, hsju_ids_thresh,
#                             hsju_ids_metrics)

# Compare each graph of IREOS + EM
# generate_ireos_sireos_comparison(normal_mawi_metrics, gan_mawi_metrics, ganf_mawi_metrics, zoot_mawi_metrics, zoou_mawi_metrics, hsjt_mawi_metrics, hsju_mawi_metrics,
#                                  10, gan_numbers_mawi, ganf_numbers_mawi, art_numbers)

# HSJ left
# generate_ireos_sireos_comparison(normal_ids_metrics, gan_ids_metrics, ganf_ids_metrics, zoot_ids_metrics, zoou_ids_metrics, hsjt_ids_metrics, hsju_ids_metrics,
#                                  10, gan_numbers_ids, ganf_numbers_ids, art_numbers)

# Compare raw auc rocs and pyod metrics
# generate_raw_and_pyod(normal_mawi_metrics, gan_mawi_metrics, ganf_mawi_metrics, zoot_mawi_metrics, zoou_mawi_metrics, hsjt_mawi_metrics, hsju_mawi_metrics,
#                                                                                                           gan_numbers_mawi, ganf_numbers_mawi, art_numbers)


# HSJ left
# generate_raw_and_pyod(normal_ids_metrics, gan_ids_metrics, ganf_ids_metrics, zoot_ids_metrics, zoou_ids_metrics, hsjt_ids_metrics, hsju_ids_metrics,
#                        gan_numbers_ids, ganf_numbers_ids, art_numbers)




'''
SIREOS
sireos_mawi_normal =[0.0098, 0.0076, 0.0103, 0.009, 0.0092, 0.0081, 0.0076, 0.0085, 0.0083, 0.0091]

EM
em_mawi_normal= [9.42E-16, 3.13E-11, 2.66E-07, 5.66E-12, 1.39E-07, 1.52E-12, 2.57E-08, 1.25E-13, 7.91E-14, 1.35E-07]
'''