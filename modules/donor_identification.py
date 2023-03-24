import os
import datetime
import logging
import pandas as pd
import pefile

def donor_identification(locations):
    # Setting start time for donor identification process
    section_start = datetime.datetime.now()
    logging.info("  Starting donor identification process at: {0}".format(section_start))
    print("  Starting donor identification process at: " + str(section_start))

    # Checking if the feature vector file has already been created
    if not os.path.isfile(locations["feature_vector_tmp_location"]):
        # Generating feature vectors for all benign and malicious samples
        sub_start = datetime.datetime.now()
        logging.info("    Starting feature vector creation at: {0}".format(sub_start))
        print("    Starting feature vector creation at: " + str(sub_start))
        if not create_feature_vectors(locations["samples_directory"], locations["feature_vector_location"]):
            raise Exception("problem creating feature vector")
        sub_stop = datetime.datetime.now()
        logging.info("    Finished feature vector creation at: {0}".format(sub_stop))
        print("    Finished feature vector creation at: " + str(sub_stop))
        logging.info("    Time taken: {0}".format(sub_stop-sub_start))
        print("    Time taken: " + str(sub_stop-sub_start))
    else:
        logging.info("Feature vector already exists, skipping to donor selection")
        print("Feature vector already exists, skipping to donor selection")

    # Identifying benign donors for each malicious sample based on feature vector
    sub_start = datetime.datetime.now()
    logging.info("    Starting donor selection at: {0}".format(sub_start))
    print("    Starting donor selection at: " + str(sub_start))
    if not select_donors(locations["feature_vector_location"], locations["donors_file_location"]):
        raise Exception("problem selecting donors")
    sub_stop = datetime.datetime.now()
    logging.info("    Finished donor selection at: {0}".format(sub_stop))
    print("    Finished donor selection at: " + str(sub_stop))
    logging.info("    Time taken: {0}".format(sub_stop-sub_start))
    print("    Time taken: " + str(sub_stop-sub_start))

    # Calculating the total duration of the donor identification process
    section_stop = datetime.datetime.now()
    logging.info("  Finished donor identification process at: {0}".format(section_stop))
    print("  Finished donor identification process at: " + str(section_stop))
    logging.info("  Time taken: {0}".format(section_stop-section_start))
    print("  Time taken: " + str(section_stop-section_start))
    return

# Iterates through each sample in opcode_directory and generates a n-gram feature vector
def create_feature_vectors(sample_directory, feature_vector_location):
    try:
        # Creating initial feature dataframe
        feature_df = pd.DataFrame()
        # Creating initial byte n-gram dataframe
        byte_bi_gram_features = pd.DataFrame(columns=["SAMPLE"])

        # Iterating through all samples in the samples subdirectory
        for root, dirs, files in os.walk(sample_directory):
            for file in files:
                try:
                    # Collecting PE Header features from current sample
                    pe = pefile.PE(root+file)
                    features = {}
                    features["SAMPLE"] = file
                    features["CLASSIFICATION"] = [1 if ("malicious" in root) else 0]
                    features["FILE_HEADER.MACHINE"] = [pe.FILE_HEADER.Machine if (pe.FILE_HEADER != None) else 0]
                    features["FILE_HEADER.SIZEOFOPTIONALHEADER"] = [pe.FILE_HEADER.SizeOfOptionalHeader if (pe.FILE_HEADER != None) else 0]
                    features["FILE_HEADER.CHARACTERISTICS"] = [pe.FILE_HEADER.Characteristics if (pe.FILE_HEADER != None) else 0]
                    features["OPTIONAL_HEADER.IMAGEBASE"] = [pe.OPTIONAL_HEADER.ImageBase if (pe.OPTIONAL_HEADER != None) else 0]
                    features["OPTIONAL_HEADER.MAJOROPERATINGSYSTEM"] = [pe.OPTIONAL_HEADER.MajorOperatingSystemVersion if (pe.OPTIONAL_HEADER != None) else 0]
                    features["OPTIONAL_HEADER.MAJORSUBSYSTEMVERSION"] = [pe.OPTIONAL_HEADER.MajorSubsystemVersion if (pe.OPTIONAL_HEADER != None) else 0]
                    features["OPTIONAL_HEADER.DLLCHARACTERISTICS"] = [pe.OPTIONAL_HEADER.DllCharacteristics if (pe.OPTIONAL_HEADER != None) else 0]
                    features["OPTIONAL_HEADER.SUBSYSTEM"] = [pe.OPTIONAL_HEADER.Subsystem if (pe.OPTIONAL_HEADER != None) else 0]
                    entropies = []
                    if (pe.OPTIONAL_HEADER != None):
                        for section in pe.sections:
                            entropies.append(section.get_entropy())
                    else:
                        entropies.append(0)
                    features["PE_SECTIONS.MAXENTROPY"] = max(entropies)
                    features["PE_SECTIONS.MINENTROPY"] = min(entropies)
                    features["PE_SECTIONS.MEANENTROPY"] = sum(entropies) / len(entropies)
                    if (pe.OPTIONAL_HEADER != None):
                        for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                            features["DATA_DIRECTORY."+str(directory.name)] = [1 if ((directory.VirtualAddress != 0) and (directory.Size != 0)) else 0]
                    features["VS_VERSIONINFO.Length"] = [pe.VS_VERSIONINFO[0].Length if (pe.VS_VERSIONINFO != None) else 0]
                    feature_df = feature_df.append(features, ignore_index=True)
                except Exception as e:
                    logging.error("      {0}".format(e))
                    print("      " + str(e))
                feature_df.filna(0)
                
                # Collecting total byte n-gram features in current sample
                new_bi_grams = set()
                try:
                    with open(root+file, "rb") as f:
                        byte_bi_gram_features = byte_bi_gram_features.append({"SAMPLE": file}, ignore_index=True)
                        cur_byte = f.read(1)
                        prev_byte = None
                        while (cur_byte != b""):
                            if prev_byte != None:
                                bi_gram = prev_byte.hex() + " " + cur_byte.hex()
                                if not bi_gram in byte_bi_gram_features.columns:
                                    new_bi_grams.add(bi_gram)
                                else:
                                    byte_bi_gram_features.loc[byte_bi_gram_features["SAMPLE"]==file , [bi_gram]] = 1
                            prev_byte = cur_byte
                            cur_byte = f.read(1)
                except Exception as e:
                    logging.error("      {0}".format(e))
                    print("      " + str(e))
                new_feature_array = []
                for index, row in byte_bi_gram_features.iterrows():
                    if row["SAMPLE"] == file:
                        new_feature_array.append([1 for x in new_bi_grams])
                    else:
                        new_feature_array.append([0 for x in new_bi_grams])
                byte_bi_gram_features = pd.concat([byte_bi_gram_features, pd.DataFrame(new_feature_array, columns=new_bi_grams)], axis=1)

                # Creating final feature space and saving it to file
                sample_df = pd.concat([feature_df, byte_bi_gram_features])
                sample_df.to_csv(feature_vector_location)
                return True
    except Exception as e:
        logging.error("      {0}".format(e))
        print("      " + str(e))
        return False

# Load the feature vector at feature_vector_location and compare features to find donor pairs and store them in donors_file
def select_donors(feature_vector_location, donors_file):
    try:
        feature_vector_df = pd.read_csv(feature_vector_location)
        donor_entries = []

        for malicious_sample in feature_vector_df.loc[feature_vector_df["class"] == 0].iterrows():
            logging.info("      Selecting donor for sample {0}".format(malicious_sample[1]["sample"]))
            print("      Selecting donor for sample " + str(malicious_sample[1]["sample"]))
            max_similarity = 0
            cur_donor = ""
            try:
                for benign_sample in feature_vector_df.loc[feature_vector_df["class"] == 1].iterrows():
                    benign_features = benign_sample[1].iloc[2:]
                    malicious_features = malicious_sample[1].iloc[2:]
                    total_count = 0
                    similar_count = 0
                    for i in range(len(benign_sample[1].iloc[2:])):
                        total_count += 1
                        if benign_features[i] == malicious_features[i]:
                            similar_count += 1
                    cur_similarity = similar_count / total_count
                    if cur_similarity > max_similarity:
                        max_similarity = cur_similarity
                        cur_donor = benign_sample[1]["sample"]
                logging.info("      Donor sample {0} selected for sample {1}".format(cur_donor, malicious_sample[1]["sample"]))
                print("      Donor sample " + cur_donor + " selected for sample " + str(malicious_sample[1]["sample"]))
                new_entry = malicious_sample[1]["sample"] + "#" + cur_donor + "\n"
                donor_entries.append(new_entry)
            except Exception as e:
                logging.error("      Problem selecting donor for sample {0}, skipping".format(malicious_sample[1]["sample"]))
                logging.error("{0}".format(e))
                print("      Problem selecting donor for sample " + str(malicious_sample[1]["sample"]) + ", skipping")
                continue

        with open(donors_file, "a") as ifile:
            for donor_entry in donor_entries:
                ifile.write(donor_entry)
        return True
    except Exception as e:
        logging.error("{0}".format(e))
        print(str(e))
        return False