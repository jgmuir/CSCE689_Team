import os
import shutil
import logging

def parse_locations(samples_directory, num_sections, reset):
    locations = {}

    # Assigning reference variables for each sample directory locations
    locations["samples_directory"] = samples_directory
    locations["benign_directory"] = locations["samples_directory"] + "benign/"
    locations["malicious_directory"] = locations["samples_directory"] + "malicious/"
    locations["adversarial_directory"] = locations["samples_directory"] + "adversarial/"

    # Assigning reference variables for temporary directory locations
    locations["tmp_directory"] = "tmp/"
    locations["donors_file_location"] = locations["tmp_directory"] + "donors.txt"
    locations["sections_directory"] = locations["tmp_directory"] + "sections/"
    locations["feature_vector_location"] = locations["tmp_directory"] + "FeatureVector.csv"

    # Assigning reference variable for log storage
    locations["logs_directory"] = "logs/"

    # Verifying that the sample directory exists
    if not os.path.isdir(locations["samples_directory"]):
        raise Exception("sample directory not found")

    # Verifying if the sample directory has been divided into benign and malicious subdirectories
    if not os.path.isdir(locations["benign_directory"]) or not os.path.isdir(locations["malicious_directory"]):
        raise Exception("invalid sample directory format (must seperate into benign and malicious folders)")
    
    # Verifying that the section count is valid
    if (num_sections < 1):
        raise Exception("invalid section count specified (must be greater than 1)")

    # Resetting the contents of previous runs if reset is true
    if reset == True:
        logging.info("Reset initiated, removing files from previous executions")
        logging.info("This may take a couple minutes, please be patient :)")
        print("Reset initiated, removing files from previous executions")
        print("This may take a couple minutes, please be patient :)")
        shutil.rmtree(locations["tmp_directory"], ignore_errors=True)
        shutil.rmtree(locations["logs_directory"], ignore_errors=True)
        shutil.rmtree(locations["adversarial_directory"], ignore_errors=True)

    # Creating the adversarial directory if it doesnt exist
    if not os.path.isdir(locations["adversarial_directory"]):
        os.mkdir(locations["adversarial_directory"])

    # Checking if a temporary directory already exists
    if not os.path.isdir(locations["tmp_directory"]):
        os.mkdir(locations["tmp_directory"])
    if not os.path.isdir(locations["sections_directory"]):
        os.mkdir(locations["sections_directory"])

    # Checking is a log directory already exists and creating it
    if not os.path.isdir(locations["logs_directory"]):
        os.mkdir(locations["logs_directory"])
    
    return locations