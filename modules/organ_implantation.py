import os
import sys
import shutil
import datetime
import logging
import random
import pandas as pd
import pefile

classifier_docker = "example/location"

def organ_implantation(locations, classifier):
    # Implanting the organs inside the malicious samples
    sub_start = datetime.datetime.now()
    logging.info("  Starting organ implantation at: {0}".format(sub_start))
    print("  Starting organ implantation at: " + str(sub_start))
    if not create_adversarial_samples(locations["sections_directory"], locations["donors_file_location"], locations["malicious_directory"], locations["adversarial_directory"], locations["feature_vector_location"], classifier):
        raise Exception("problem implanting organs")
    sub_stop = datetime.datetime.now()
    logging.info("  Finished organ implantation at: {0}".format(sub_stop))
    print("  Finished organ implantation at: " + str(sub_stop))
    logging.info("  Time taken: {0}".format(sub_stop-sub_start))
    print("  Time taken: " + str(sub_stop-sub_start))
    return

# Iterates through each malicious sample and continually embeds sections from its designated donor until it is deemed benign
def create_adversarial_samples(sections_directory, donors_location, malicious_directory, adversarial_directory, feature_vector, classifier):
    with open(donors_location, "r") as ifile:
        reader = ifile.read()
        donor_pairs = [x.split("#") for x in reader.split("\n")]
        for donor_pair in donor_pairs:
            if len(donor_pair) > 1:
                donor_sections_directory = sections_directory + donor_pair[1] + ".sections/"
                malicious_location = malicious_directory + donor_pair[0]
                adversarial_location = adversarial_directory + donor_pair[0]
                query_budget = len(os.listdir(donor_sections_directory))
                if not os.path.isfile(adversarial_location):
                    try:
                        logging.info("    Creating adversarial malware sample from sample {0} with sections extracted from donor sample {1}".format(donor_pair[0], donor_pair[1]))
                        print("    Creating adversarial malware sample from sample " + donor_pair[0] + " with sections extracted from donor sample " + donor_pair[1])
                        create_adversarial_sample(donor_sections_directory, malicious_location, adversarial_location, query_budget, donor_pair[0], feature_vector, classifier) 
                    except Exception as e:
                        logging.error("    Problem creating adversarial malware sample from sample {0}, skipping".format(donor_pair[0]))
                        logging.error("    {0}".format(e))
                        print("    Problem creating adversarial malware sample from sample " + str(donor_pair[0]) + ", skipping", file=sys.stderr)
                        print("    " + str(e), file=sys.stderr)
                        continue
                else:
                    logging.info("    Adversarial malware sample already created from sample {0}, skipping".format(donor_pair[0]))
                    print("    Adversarial malware sample already created from sample " + donor_pair[0] + ", skipping")
                    continue
    return True
    
# Converts the given malicious sample into a benign sample by iteratively inserting sections
def create_adversarial_sample(donor_sections_directory, malicious_location, adversarial_location, query_budget, malicious_name, feature_vector, classifier):
    num_skipped_in_row = 0
    query_cost = 1
    best_loss = 1
    feature_vector_df = pd.read_csv(feature_vector)
    sections = os.listdir(donor_sections_directory)
    used_sections = set()
    tmp_adversarial_location = adversarial_location.split(".exe")[0] + "-tmp.exe"
    shutil.copyfile(malicious_location, adversarial_location)
    while (query_cost <= query_budget) and (classify_sample(adversarial_location, malicious_name, num_skipped_in_row) == "malicious"):
        logging.info("      Adversarial sample classified as malicious, selecting random section to embed")
        print("      Adversarial sample classified as malicious, selecting random section to embed")
        query_cost += 1
        selected_section = random.choice(sections)
        while selected_section in used_sections:
            selected_section = random.choice(sections)
        used_sections.add(selected_section)
        section_location = os.path.join(donor_sections_directory, selected_section)
        if os.path.isfile(tmp_adversarial_location):
            os.remove(tmp_adversarial_location)
        shutil.copyfile(adversarial_location, tmp_adversarial_location)
        logging.info("      Embedding section {0} into adversarial sample".format(query_cost-1))
        print("      Embedding section " + str(query_cost-1) + " into adversarial sample")
        embed_section(tmp_adversarial_location, section_location)
        logging.info("      Calculating if the new section moved sample closer to benign similarity")
        print("      Calculating if the new section moved sample closer to benign similarity")
        cur_loss = calculate_loss(tmp_adversarial_location, feature_vector_df)
        if cur_loss <= best_loss:
            num_skipped_in_row = 0
            os.remove(adversarial_location)
            shutil.copyfile(tmp_adversarial_location, adversarial_location)
            logging.info("      Gadget increases benign similarity, creating new adversarial sample")
            print("      Gadget increases benign similarity, creating new adversarial sample")
            best_loss = cur_loss
        else:
            num_skipped_in_row += 1
            logging.info("      Section decreases benign similarity, reverting to previous adversarial sample")
            print("      Section decreases benign similarity, reverting to previous adversarial sample")

    if query_cost > query_budget:
        logging.info("      Adversarial sample {0} still classified as malicious, but out of sections :(".format(malicious_name))
        print("      Adversarial sample " + malicious_name + " still classified as malicious, but out of sections :(")
    else:
        logging.info("      Adversarial sample {0} classified as benign :)".format(malicious_name))
        print("      Adversarial sample " + malicious_name + " classified as benign :)")
    return

# Classifies the given sample as benign or malicious
def classify_sample(sample_location, name, num_skipped):
    # TODO: Implement this
    logging.info("      Classifying sample {0}".format(name))
    print("      Classifying sample " + name)
    if num_skipped > 10: # Send sample to classifier docker
        return "benign"
    else:
        return "malicious"

# Converts the given sample into a feature vector
def create_feature_list(sample_location):
    # Collecting PE Header features from current sample
    pe = pefile.PE(sample_location)
    header_features = {}
    header_features["FILE_HEADER.MACHINE"] = [pe.FILE_HEADER.Machine if (pe.FILE_HEADER != None) else 0]
    header_features["FILE_HEADER.SIZEOFOPTIONALHEADER"] = [pe.FILE_HEADER.SizeOfOptionalHeader if (pe.FILE_HEADER != None) else 0]
    header_features["FILE_HEADER.CHARACTERISTICS"] = [pe.FILE_HEADER.Characteristics if (pe.FILE_HEADER != None) else 0]
    header_features["OPTIONAL_HEADER.IMAGEBASE"] = [pe.OPTIONAL_HEADER.ImageBase if (pe.OPTIONAL_HEADER != None) else 0]
    header_features["OPTIONAL_HEADER.MAJOROPERATINGSYSTEM"] = [pe.OPTIONAL_HEADER.MajorOperatingSystemVersion if (pe.OPTIONAL_HEADER != None) else 0]
    header_features["OPTIONAL_HEADER.MAJORSUBSYSTEMVERSION"] = [pe.OPTIONAL_HEADER.MajorSubsystemVersion if (pe.OPTIONAL_HEADER != None) else 0]
    header_features["OPTIONAL_HEADER.DLLCHARACTERISTICS"] = [pe.OPTIONAL_HEADER.DllCharacteristics if (pe.OPTIONAL_HEADER != None) else 0]
    header_features["OPTIONAL_HEADER.SUBSYSTEM"] = [pe.OPTIONAL_HEADER.Subsystem if (pe.OPTIONAL_HEADER != None) else 0]
    entropies = []
    if (pe.OPTIONAL_HEADER != None):
        for section in pe.sections:
            entropies.append(section.get_entropy())
    else:
        entropies.append(0)
    header_features["PE_SECTIONS.MAXENTROPY"] = max(entropies)
    header_features["PE_SECTIONS.MINENTROPY"] = min(entropies)
    header_features["PE_SECTIONS.MEANENTROPY"] = sum(entropies) / len(entropies)
    if (pe.OPTIONAL_HEADER != None):
        for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            header_features["DATA_DIRECTORY."+str(directory.name)] = [1 if ((directory.VirtualAddress != 0) and (directory.Size != 0)) else 0]
    header_features["VS_VERSIONINFO.Length"] = [pe.VS_VERSIONINFO[0].Length if (pe.VS_VERSIONINFO != None) else 0]
                
    # Collecting total byte bi-gram features in current sample
    bi_gram_features = {}
    try:
        with open(sample_location, "rb") as f:
            cur_byte = f.read(1)
            prev_byte = None
            while (cur_byte != b""):
                if prev_byte != None:
                    bi_gram = prev_byte.hex() + " " + cur_byte.hex()
                    bi_gram_features[bi_gram] = 1
                prev_byte = cur_byte
                cur_byte = f.read(1)
    except Exception as e:
        logging.error("      {0}".format(e))
        print("      " + str(e))

    # Creating final feature list
    total_features = header_features + bi_gram_features
    return total_features

# Calculates the feature similarity between the adversarial_sample and all benign samples
def calculate_loss(adversarial_location, feature_vector_df):
    adversarial_feature_list = create_feature_list(adversarial_location)
    max_similarity = 0
    for benign_sample in feature_vector_df.loc[feature_vector_df["class"] == 1].iterrows():
        benign_features = benign_sample[1].iloc[2:]
        similar_count = 0
        for feature in adversarial_feature_list.keys():
            if feature in benign_features:
                if benign_features[feature] == 1:
                    similar_count += 1
        cur_similarity = similar_count / len(adversarial_feature_list)
        if cur_similarity > max_similarity:
            max_similarity = cur_similarity
    return max_similarity

# Parses the section file and embedds it inside the given sample
def embed_section(sample_location, section_file):
    print("      Selected section: " + section_file)
    pe = pefile.PE(sample_location)
    # TODO: Implement this
    return