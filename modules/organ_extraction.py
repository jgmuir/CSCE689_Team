import os
import datetime
import logging
import pefile
import random

def organ_extraction(locations, num_sections):
    # Setting start time for organ extraction process
    section_start = datetime.datetime.now()
    logging.info("  Starting organ extraction process at: {0}".format(section_start))
    print("  Starting organ extraction process at: " + str(section_start))
    
    # Importing malicious-donor sample pairs
    sub_start = datetime.datetime.now()
    logging.info("    Starting importing malicious-donor sample pairs from {0} at: {1}".format(locations["donors_file_location"], sub_start))
    print("    Starting importing malicious-donor sample pairs from " + str(locations["donors_file_location"]) + " at: " + str(sub_start))
    donor_sample_pairs = import_donors_file(locations["donors_file_location"])
    sub_stop = datetime.datetime.now()
    logging.info("    Finished reading {0} total malicious-donor sample pairs at: {1}".format(len(donor_sample_pairs), sub_stop))
    print("    Finished reading " + str(len(donor_sample_pairs)) + " total malicious-donor sample pairs at: " + str(sub_stop))
    logging.info("    Time taken: {0}".format(sub_stop-sub_start))
    print("    Time taken: " + str(sub_stop-sub_start))

    # Extracting and storing organs from combined donor sample files
    sub_start = datetime.datetime.now()
    logging.info("    Starting organ extraction at: {0}".format(sub_start))
    print("    Starting organ extraction at: " + str(sub_start))
    if not extract_sections_from_donors(donor_sample_pairs, locations["samples_directory"], locations["sections_directory"], num_sections):
        raise Exception("problem extracting organs")
    sub_stop = datetime.datetime.now()
    logging.info("    Finished organ extraction at: {0}".format(sub_stop))
    print("    Finished organ extraction at: " + str(sub_stop))
    logging.info("    Time taken: {0}".format(sub_stop-sub_start))
    print("    Time taken: " + str(sub_stop-sub_start))

    # Calculating the total duration of the organ extraction process
    section_stop = datetime.datetime.now()
    logging.info("  Finished sample organ extraction process at: {0}".format(section_stop))
    print("  Finished sample organ extraction process at: " + str(section_stop))
    logging.info("  Total time taken: {0}".format(section_stop-section_start))
    print("  Total time taken: " + str(section_stop-section_start))
    
    return

# Reads the list of donor pairs in donors_file and returns them in a dictionary
def import_donors_file(donors_file):
    try:
        donor_dict = {} # Key=malicious sample, Value=benign donor sample
        with open(donors_file, mode="r") as ifile:
            reader = ifile.read()
            for line in reader.split('\n'):
                if line.strip():
                    donor_pair_line = line.strip().split("#")
                    donor_dict[donor_pair_line[0]] = donor_pair_line[1]
        return donor_dict
    except Exception as e:
        raise Exception(e)
    
# Iterates through each donor sample pair and extracts num_sections PE sections and stores them in the sections_directory
def extract_sections_from_donors(donor_sample_pairs, samples_directory, sections_directory, num_sections):
    try:
        for donor in donor_sample_pairs.values():
            sections = extract_sections_from_donor(os.path.join(samples_directory, "benign/" + donor), num_sections)
            donor_section_directory = os.path.join(sections_directory, (donor + ".sections/"))
            if not os.path.isdir(donor_section_directory):
                os.mkdir(donor_section_directory)
            for section in sections:
                with open(os.path.join(donor_section_directory, (section + ".section")), 'w') as ofile:
                    ofile.write(section)
        return True
    except Exception as e:
        logging.error("      {0}".format(e))
        print("      " + str(e))
        return False
    
# Iterates through a given donor sample and extracts num_sections PE sections
def extract_sections_from_donor(donor_location, num_sections):
    sections = set()
    try:
        pe = pefile.PE(donor_location)
        total_sections = 0
        if (pe.OPTIONAL_HEADER != None):
            total_sections = len(pe.sections)
        while (len(sections) < num_sections) or (len(sections) == total_sections):
            section = extract_section(donor_location)
            if section != None:
                sections.add(section)
        return sections
    except Exception as e:
        logging.error("      {0}".format(e))
        print("      " + str(e))
        return sections
    
# Extracts a single PE section from a given donor sample
def extract_section(donor_location):
    section = None
    try:
        pe = pefile.PE(donor_location)
        idx = random.randint(0, len(pe.sections)-1)
        section = pe.sections[idx]
        return section
    except Exception as e:
        logging.error("      {0}".format(e))
        print("      " + str(e))
        return section