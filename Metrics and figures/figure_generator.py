from scipy.stats import norm
import numpy as np
import pickle

# Name of the pickle file to be imported
pickle_file = "ids_zoou_test_results.p"

# Number of instances for learning the feature mapping
# FMinstances = 55236 # mawi
FMinstances = 80155
# Number of instances for training the anomaly detector
# ADinstances = 497127 # mawi
ADinstances = 721399

# Import the array of RMSEs
RMSEs = pickle.load(open(pickle_file, "rb"))

# benignSample = np.log(RMSEs[FMinstances+ADinstances+1:600000]) # mawi
benignSample = np.log(RMSEs[FMinstances+ADinstances+1:810000])

# benignSample = RMSEs[FMinstances+ADinstances+1:600000]
logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))

# plot the RMSE anomaly scores
print("Plotting results")
from matplotlib import pyplot as plt
from matplotlib import cm
plt.figure(figsize=(10,5))
fig = plt.scatter(range(FMinstances+ADinstances+1,len(RMSEs)),RMSEs[FMinstances+ADinstances+1:],s=0.1,c=logProbs[FMinstances+ADinstances+1:],cmap='RdYlGn')
plt.yscale("linear")
plt.title("Anomaly Scores from Kitsune's Execution Phase")
plt.ylabel("RMSEs")
plt.xlabel("Time elapsed [min]")
figbar=plt.colorbar()
figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
plt.show()
