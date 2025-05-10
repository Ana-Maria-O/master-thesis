import os

# Generate the mergecap command
def generate_command(directory, merge_path, output):
    command = merge_path + " -F pcap -w " + output + " "

    # Get a list of all the files in the directory
    files = os.listdir(directory)

    # Add the files to the command
    for file in files:
        command += file + " "
        
    print(command)

# Directory with pcap files to be merged
FILE_DIR = "Original Network Traffic and Log data\Friday-02-03-2018\pcap"

# Path of the output file
OUTPUT_PATH = "Original Network Traffic and Log data\\Wednesday-14-02-2018\\merged.pcap"

# Path of mergecap.exe
MERGE_PATH = "\"C:\\Program Files\\Wireshark\\mergecap.exe\""

generate_command(FILE_DIR, MERGE_PATH, OUTPUT_PATH)