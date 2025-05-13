# Generated attacks folder
This folder contains the generated attacks that were used in the master thesis project associated with this repo. Each folder corresponds to one of the attacks. The attacks in the files from the folder were inserted into the files with the original packets or the features of the original packets, depending on the attack.

## GAN
This folder contains the filtered adversarial examples that were generated using GAN. MAWI and CIC-IDS2017 have sets of adversarial examples of different sizes. In the case of both original datasets, the files with the smaller number of adversarial examples are sampled from the file with the largest number of examples.

## GAN on features
This folder contains the adversarial examples generated using GAN on the features of the original datasets. As with GAN, the files with the fewer adversarial examples are sampled from the largest file.

## HSJ
This folder contains the adversarial examples generated using HopSkipJump. For each of the main datasets (MAWI and CIC-IDS2017), 10 000 adversarial examples were generated based on the features of a sample of the original set. In the thesis, the 10 000 adversarial examples were inserted at the end of the testing set. The files with fewer examples (100, 1 000 and 5 000) are random samples of the file with 10 000 examples. These were inserted at the beginning of the training set. Each one of these new sets ran through Kitsune and was analyzed, but was ultimately excluded from the thesis as HopSkipJump attacks are meant to be inserted in the test set.

## ZOO
The generation, insertion and sampling process is the same as HSJ. The only difference is that the adversarial examples were generated using Zeroth Order Optimisation. ZOO used a different sample of features from HSJ, even when the samples were taken from the same dataset.

