#!/usr/bin/env python
import os
import datetime
import logging
import argparse
import sys

import modules.parser as parser
from modules.donor_identification import donor_identification
from modules.organ_extraction import organ_extraction
from modules.organ_implantation import organ_implantation

def main():
    # Parsing the input arguments
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-s", "--samples", type=str, help="Sample Directory: location of the sample directory", required=True)
    argparser.add_argument("-g", "--sections", type=int, help="Section Count: number of sections to extract", required=False, default=30)
    argparser.add_argument("-c", "--clas", type=str, help="Classifier: classifier used for optimization (NOT WORKING)", required=False, default="classifer")
    argparser.add_argument("-r", "--reset", type=bool, help="Reset History: reset the contents from previous executions", required=False, default=False)
    args = argparser.parse_args()
    
    samples_directory = args.samples
    num_sections = args.sections
    classifier = args.clas
    reset = args.reset

    try:
        locations = parser.parse_locations(samples_directory, num_sections, reset)
    except Exception as e:
        print("Error parsing input arguments: " + str(e))
        return

    # Created a log file in the tmp/logs directory
    logging.basicConfig(filename=locations["logs_directory"]+"gen-adversarial"+datetime.datetime.now().strftime("%Y%m%d-%H%M%S")+".log", level=logging.DEBUG)

    # Setting start time for entire program
    main_start = datetime.datetime.now()
    logging.info("Starting gen-adversarial at: {0}\n".format(main_start))
    print("Starting gen-adversarial at: " + str(main_start) + "\n")
    
    # Setting start time for preparation stage
    stage_start = datetime.datetime.now()
    logging.info("Starting preparation stage at: {0}".format(stage_start))
    print("Starting preparation stage at: " + str(stage_start))

    try:
        if not os.path.isfile(locations["donors_file_location"]):
            donor_identification(locations)
        else:
            logging.info("  Donor list already exists, skipping donor identification")
            print("  Donor list already exists, skipping donor identification")
    except Exception as e:
        logging.error("Error during donor identification: {0}".format(e))
        print("Error during donor identification: " + str(e), file=sys.stderr)
        return

    try:
        organ_extraction(locations, num_sections)
    except Exception as e:
        logging.error("Error during organ extraction: {0}".format(e))
        print("Error during organ extraction: " + str(e), file=sys.stderr)
        return

    # Calculating the total duration of the preparation stage
    stage_stop = datetime.datetime.now()
    logging.info("Finished preparation stage at: {0}".format(stage_stop))
    print("Finished preparation stage at: " + str(stage_stop))
    logging.info("Total time taken: {0}".format(stage_stop-stage_start))
    print("Stage time taken: " + str(stage_stop-stage_start))

    # Setting start time for manipulation stage
    stage_start = datetime.datetime.now()
    logging.info("Starting manipulation stage at: {0}".format(stage_start))
    print("Starting manipulation stage at: " + str(stage_start))

    try:
        organ_implantation(locations, classifier)
    except Exception as e:
        logging.error("Error during organ implantation: {0}".format(e))
        print("Error during organ implantation: " + str(e), file=sys.stderr)
        return

    # Calculating the total duration of the manipulation stage
    stage_stop = datetime.datetime.now()
    logging.info("Finished manipulation stage at: {0}".format(stage_stop))
    print("Finished manipulation stage at: " + str(stage_stop))
    logging.info("Total time taken: {0}".format(stage_stop-stage_start))
    print("Stage time taken: " + str(stage_stop-stage_start))

    # Calculating the total duration of the program
    main_stop = datetime.datetime.now()
    logging.info("\nFinished gen-adversarial at: {0}".format(main_stop))
    print("\nFinished gen-adversarial at: " + str(main_stop))
    logging.info("Total time taken: {0}".format(main_stop-main_start))
    print("Total time taken: " + str(main_stop-main_start))

    return

# Main function that is executed when the program is called
if __name__ == '__main__':
    main()