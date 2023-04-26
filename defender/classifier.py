# REQUIRED IMPORTS
import os                                               # Directory walking for file loading
import math                                             # Logarithm function
import pandas as pd                                     # Dataframe managment
import pefile                                           # Header feature extraction
import dis                                              # x86 disassembly
import pickle                                           # Model saving
from io import StringIO                                 # Reading disassembly result
from sklearn.feature_selection import SelectFromModel   # Feature dimensionality reduction
from sklearn.ensemble import RandomForestClassifier     # Random Forest Classifier
from collections import Counter                         # Entropy calculations

# EVALUATION IMPORTS
from matplotlib import pyplot as plt                    # Output plotting
import seaborn as sns                                   # Heatmap of confusion matrix
from sklearn.metrics import confusion_matrix            # Confusion matrix
from sklearn.metrics import classification_report       # Classification report

# GLOBAL VARIABLES
MAX_BYTES = 50000

def entropy(data):
    """Calculate the entropy of a chunk of data."""
    if not data:
        return 0.0
    occurences = Counter(bytearray(data))
    entropy = 0
    for x in occurences.values():
        p_x = float(x) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def get_header_features(pe, features):
    # Get FILE_HEADER features
    if (hasattr(pe, "FILE_HEADER")):
        features["FILE_HEADER.MACHINE"] = pe.FILE_HEADER.Machine
        features["FILE_HEADER.SIZEOFOPTIONALHEADER"] = pe.FILE_HEADER.SizeOfOptionalHeader
        features["FILE_HEADER.CHARACTERISTICS"] = pe.FILE_HEADER.Characteristics
    else:
        features["FILE_HEADER.MACHINE"] = 0
        features["FILE_HEADER.SIZEOFOPTIONALHEADER"] = 0
        features["FILE_HEADER.CHARACTERISTICS"] = 0
    # Get OPTIONAL_HEADER features
    if (hasattr(pe, "OPTIONAL_HEADER")):
        features["OPTIONAL_HEADER.IMAGEBASE"] = pe.OPTIONAL_HEADER.ImageBase
        features["OPTIONAL_HEADER.MAJOROPERATINGSYSTEM"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        features["OPTIONAL_HEADER.MAJORSUBSYSTEMVERSION"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        features["OPTIONAL_HEADER.DLLCHARACTERISTICS"] = pe.OPTIONAL_HEADER.DllCharacteristics
        features["OPTIONAL_HEADER.SUBSYSTEM"] = pe.OPTIONAL_HEADER.Subsystem
        entropies = []
        if hasattr(pe.sections):
            for section in pe.sections:
                entropies.append(section.get_entropy())
        else:
            entropies.append(0)
        features["PE_SECTIONS.MAXENTROPY"] = max(entropies)
        features["PE_SECTIONS.MINENTROPY"] = min(entropies)
        features["PE_SECTIONS.MEANENTROPY"] = sum(entropies) / len(entropies)
    else:
        features["OPTIONAL_HEADER.IMAGEBASE"] = 0
        features["OPTIONAL_HEADER.MAJOROPERATINGSYSTEM"] = 0
        features["OPTIONAL_HEADER.MAJORSUBSYSTEMVERSION"] = 0
        features["OPTIONAL_HEADER.DLLCHARACTERISTICS"] = 0
        features["OPTIONAL_HEADER.SUBSYSTEM"] = 0
        features["PE_SECTIONS.MAXENTROPY"] = 0
        features["PE_SECTIONS.MINENTROPY"] = 0
        features["PE_SECTIONS.MEANENTROPY"] = 0
    # Get DIRECTORY_ENTRY_RESOURCE features
    if (hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")):
        # Find all resources in the PE and calculate their entropy
        entropies = []
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = str(resource_type.name)
            else:
                name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
            if name is None:
                name = str(resource_type.struct.Id)
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            if hasattr(resource_lang, "data"):
                                try:
                                    data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    entropies.append(entropy(data))
                                except:
                                    entropies.append(0)
        if len(entropies) > 0:
            features["RESOURCES.MAXENTROPY"] = max(entropies)
            features["RESOURCES.MINENTROPY"] = min(entropies)
        else:
            features["RESOURCES.MAXENTROPY"] = 0
            features["RESOURCES.MINENTROPY"] = 0
    else:
        features["RESOURCES.MAXENTROPY"] = 0
        features["RESOURCES.MINENTROPY"] = 0   
    # Get VS_VERSIONINFO feature
    if (hasattr(pe, "VS_VERSIONINFO")):
        features["VS_VERSIONINFO.Length"] = pe.VS_VERSIONINFO[0].Length
    else:
        features["VS_VERSIONINFO.Length"] = 0
    # Return the final header features
    return features

def get_byte_file(pe):
    try:
        global MAX_BYTES
        if pe.OPTIONAL_HEADER.SizeOfCode > MAX_BYTES:
            byte_file = pe.get_data(pe.OPTIONAL_HEADER.BaseOfCode, MAX_BYTES)
        else:
            byte_file = pe.get_data(pe.OPTIONAL_HEADER.BaseOfCode, pe.OPTIONAL_HEADER.SizeOfCode)
        return byte_file
    except:
        return bytearray()
    
def get_training_byte_features(byte_files, classifications):
    # Initialize the set of unique bi-gram byte features
    all_unique_bi_grams = set()
    each_file_bi_grams = []
    # Iterate over the byte files
    for sample, byte_file in byte_files.items():
        print("Collecting bi-gram byte features for sample " + str(sample))
        # Identify new unique bi-grams in the current byte file
        cur_unique_bi_grams = set()
        prev_byte = None
        for i, byte in enumerate(byte_file):
            # Creating the bi-gram if enough history exists
            if prev_byte != None:
                bi_gram = hex(prev_byte) + " " + hex(byte)
                # If the current bi-gram has not been seen in the current file
                if not bi_gram in cur_unique_bi_grams:
                    cur_unique_bi_grams.add(bi_gram)
                # If the current bi-gram has not been seen in any file
                if not bi_gram in all_unique_bi_grams:
                    all_unique_bi_grams.add(bi_gram)
            # Moving the sliding window
            prev_byte = byte
        # Add the set of unique bi-grams for the current file to the list
        each_file_bi_grams.append(cur_unique_bi_grams)
    # Initialize the bi-gram byte feature matrix
    num_rows = len(byte_files)
    num_cols = len(list(all_unique_bi_grams))
    byte_bi_gram_features_list = [[0]*num_cols for i in range(num_rows)]              
    # One-hot-encoding every sample with the combination of all encountered features
    for row, file_bi_grams in enumerate(each_file_bi_grams):
        print("One-hot-encoding bi-gram byte features for sample " + str(list(byte_files)[row]))
        for col, bi_gram in enumerate(all_unique_bi_grams):
            if bi_gram in file_bi_grams:
                byte_bi_gram_features_list[row][col] = 1
    # Creating the feature selector model for top 200 features
    selector = SelectFromModel(estimator=RandomForestClassifier(n_estimators=1000), max_features=200)
    # Selecting top 200 bi-gram byte features
    print("Selecting top 200 bi-gram byte features")
    selector.fit(byte_bi_gram_features_list, list(classifications))
    selections = selector.get_support()
    # Copy the selected features to another matrix
    print("Copying selected bi-gram byte features")
    selected_byte_bi_gram_features_dict = {}
    selected_indicies = [i for i, e in enumerate(selections) if e == True]
    for index in selected_indicies:
        selected_byte_bi_gram_features_dict[list(all_unique_bi_grams)[index]] = [row[index] for row in byte_bi_gram_features_list]
    print("Converting selected bi-gram byte features to DataFrame")
    byte_bi_gram_features = pd.DataFrame(selected_byte_bi_gram_features_dict)
    return byte_bi_gram_features

def get_validation_byte_features(byte_files, selected_byte_features):
    # Initialize the set of unique bi-gram byte features
    each_file_bi_grams = []
    # Iterate over the byte files
    for sample, byte_file in byte_files.items():
        print("Collecting bi-gram byte features for sample " + str(sample))
        # Identify new unique bi-grams in the current byte file
        cur_unique_bi_grams = set()
        prev_byte = None
        for i, byte in enumerate(byte_file):
            # Creating the bi-gram if enough history exists
            if prev_byte != None:
                bi_gram = hex(prev_byte) + " " + hex(byte)
                # If the current bi-gram has not been seen in the current file
                if not bi_gram in cur_unique_bi_grams:
                    cur_unique_bi_grams.add(bi_gram)
            # Moving the sliding window
            prev_byte = byte
        # Add the set of unique bi-grams for the current file to the list
        each_file_bi_grams.append(cur_unique_bi_grams)
    # Initialize the bi-gram byte feature matrix
    num_rows = len(byte_files)
    num_cols = len(selected_byte_features)
    byte_bi_gram_features_list = [[0]*num_cols for i in range(num_rows)]             
    # One-hot-encoding every sample with the combination of all encountered features
    for row, file_bi_grams in enumerate(each_file_bi_grams):
        print("One-hot-encoding bi-gram byte features for sample " + str(list(byte_files)[row]))
        for col, bi_gram in enumerate(selected_byte_features):
            if bi_gram in file_bi_grams:
                byte_bi_gram_features_list[row][col] = 1
    # Convert the bi-gram byte features into a dataframe object
    print("Converting bi-gram byte features to DataFrame")
    byte_bi_gram_features = pd.DataFrame(byte_bi_gram_features_list, columns=selected_byte_features)
    return byte_bi_gram_features

def get_classification_byte_features(byte_file, selected_byte_features):
    # Identify new unique bi-grams in the byte file
    unique_bi_grams = set()
    prev_byte = None
    for i, byte in enumerate(byte_file):
        # Creating the bi-gram if enough history exists
        if prev_byte != None:
            bi_gram = hex(prev_byte) + " " + hex(byte)
            # If the current bi-gram has not been seen in the current file
            if not bi_gram in unique_bi_grams:
                unique_bi_grams.add(bi_gram)
        # Moving the sliding window
        prev_byte = byte
    # Initialize the bi-gram byte feature matrix
    byte_bi_gram_features = dict.fromkeys(selected_byte_features, 0)          
    # One-hot-encoding the sample with the combination of all encountered features
    for bi_gram in selected_byte_features:
        if bi_gram in list(unique_bi_grams):
            byte_bi_gram_features[bi_gram] = 1
    return byte_bi_gram_features
    
def get_asm_file(pe):
    # Try reading the instructions as bytes
    try:
        global MAX_BYTES
        if pe.OPTIONAL_HEADER.SizeOfCode > MAX_BYTES:
            file_bytes = pe.get_data(pe.OPTIONAL_HEADER.BaseOfCode, MAX_BYTES)
        else:
            file_bytes = pe.get_data(pe.OPTIONAL_HEADER.BaseOfCode, pe.OPTIONAL_HEADER.SizeOfCode)
    except:
        # If fails return list of no instructions found
        return []
    # Do weird try/catch since dis.dis is broken
    out = StringIO()
    try:
        dis.dis(x=file_bytes, file=out)
    except:
        pass
    # Parse the disasembled instructions and create a list of OPCODES
    lines = out.getvalue().split('\n')
    lines = lines[0:len(lines)-1]
    asm_file = [line.strip().strip('>>').strip().split(' ')[1] for line in lines if line.strip().strip('>>').strip()]
    return asm_file
    
def get_training_asm_features(asm_files, classifications):
    # Initialize the set of unique bi-gram and tri-gram OPCODE features
    all_unique_bi_grams = set()
    all_unique_tri_grams = set()
    each_file_bi_grams = []
    each_file_tri_grams = []
    # Iterate over the ASM files
    for sample, asm_file in asm_files.items():
        print("Collecting bi-gram and tri-gram OPCODE features for sample " + str(sample))
        # Identify new unique bi-grams and tri-grams in the current ASM file
        cur_unique_bi_grams = set()
        cur_unique_tri_grams = set()
        prev_opcode1 = None
        prev_opcode2 = None
        for i, opcode in enumerate(asm_file):
            # Creating the bi-gram if enough history exists
            if prev_opcode1 != None:
                bi_gram = prev_opcode1 + " " + opcode
                # If the current bi-gram has not been seen in the current file
                if not bi_gram in cur_unique_bi_grams:
                    cur_unique_bi_grams.add(bi_gram)
                # If the current bi-gram has not been seen in any file
                if not bi_gram in all_unique_bi_grams:
                    all_unique_bi_grams.add(bi_gram)
            # Creating the tri-gram if enough history exists
            if prev_opcode2 != None:
                tri_gram = prev_opcode2 + " " + prev_opcode1 + " " + opcode
                # If the current tri-gram has not been seen in the current file
                if not tri_gram in cur_unique_tri_grams:
                    cur_unique_tri_grams.add(tri_gram)
                # If the current tri-gram has not been seen in any file
                if not tri_gram in all_unique_tri_grams:
                    all_unique_tri_grams.add(tri_gram)
            # Moving the sliding window
            prev_opcode2 = prev_opcode1
            prev_opcode1 = opcode
        # Add the set of unique bi-grams and tri-grams for the current file to the list
        each_file_bi_grams.append(cur_unique_bi_grams)
        each_file_tri_grams.append(cur_unique_tri_grams)
    # Initialize the bi-gram OPCODE feature matrix
    num_rows = len(asm_files)
    num_cols1 = len(list(all_unique_bi_grams))
    num_cols2 = len(list(all_unique_tri_grams))
    opcode_bi_gram_features_list = [[0]*num_cols1 for i in range(num_rows)]
    opcode_tri_gram_features_list = [[0]*num_cols2 for i in range(num_rows)]             
    # One-hot-encoding every sample with the combination of all encountered features
    for row, file_bi_grams in enumerate(each_file_bi_grams):
        print("One-hot-encoding bi-gram OPCODE features for sample " + str(list(asm_files)[row]))
        for col, bi_gram in enumerate(all_unique_bi_grams):
            if bi_gram in file_bi_grams:
                opcode_bi_gram_features_list[row][col] = 1
    for row, file_tri_grams in enumerate(each_file_tri_grams):
        print("One-hot-encoding tri-gram OPCODE features for sample " + str(list(asm_files)[row]))
        for col, tri_gram in enumerate(all_unique_tri_grams):
            if tri_gram in file_tri_grams:
                opcode_tri_gram_features_list[row][col] = 1
    # Creating the feature selector model for top 100 features
    selector = SelectFromModel(estimator=RandomForestClassifier(n_estimators=1000), max_features=100)
    # Selecting top 100 bi-gram opcode features
    print("Selecting top 100 bi-gram OPCODE features")
    selector.fit(opcode_bi_gram_features_list, list(classifications))
    selections = selector.get_support()
    # Copying the selected bi-gram features to another matrix
    print("Copying selected bi-gram OPCODE features")
    selected_opcode_bi_gram_features_dict = {}
    selected_indicies = [i for i, e in enumerate(selections) if e == True]
    for index in selected_indicies:
        selected_opcode_bi_gram_features_dict[list(all_unique_bi_grams)[index]] = [row[index] for row in opcode_bi_gram_features_list]
    print("Converting selected bi-gram byte features to DataFrame")
    opcode_bi_gram_features = pd.DataFrame(selected_opcode_bi_gram_features_dict)
    # Selecting top 100 tri-gram opcode features
    print("Selecting top 100 tri-gram OPCODE features")
    selector.fit(opcode_tri_gram_features_list, list(classifications))
    selections = selector.get_support()
    # Copy the selected features to another matrix
    print("Copying selected tri-gram OPCODE features")
    selected_opcode_tri_gram_features_dict = {}
    selected_indicies = [i for i, e in enumerate(selections) if e == True]
    for index in selected_indicies:
        selected_opcode_tri_gram_features_dict[list(all_unique_tri_grams)[index]] = [row[index] for row in opcode_tri_gram_features_list]
    print("Converting selected bi-gram byte features to DataFrame")
    opcode_tri_gram_features = pd.DataFrame(selected_opcode_tri_gram_features_dict)
    return opcode_bi_gram_features, opcode_tri_gram_features

def get_validation_asm_features(asm_files, selected_opcode_features_1, selected_opcode_features_2):
    # Initialize the set of unique bi-gram and tri-gram OPCODE features
    each_file_bi_grams = []
    each_file_tri_grams = []
    # Iterate over the ASM files
    for sample, asm_file in asm_files.items():
        print("Collecting bi-gram and tri-gram OPCODE features for sample " + str(sample))
        # Identify new unique bi-grams and tri-grams in the current ASM file
        cur_unique_bi_grams = set()
        cur_unique_tri_grams = set()
        prev_opcode1 = None
        prev_opcode2 = None
        for i, opcode in enumerate(asm_file):
            # Creating the bi-gram if enough history exists
            if prev_opcode1 != None:
                bi_gram = prev_opcode1 + " " + opcode
                # If the current bi-gram has not been seen in the current file
                if not bi_gram in cur_unique_bi_grams:
                    cur_unique_bi_grams.add(bi_gram)
            # Creating the tri-gram if enough history exists
            if prev_opcode2 != None:
                tri_gram = prev_opcode2 + " " + prev_opcode1 + " " + opcode
                # If the current tri-gram has not been seen in the current file
                if not tri_gram in cur_unique_tri_grams:
                    cur_unique_tri_grams.add(tri_gram)
            # Moving the sliding window
            prev_opcode2 = prev_opcode1
            prev_opcode1 = opcode
        # Add the set of unique bi-grams and tri-grams for the current file to the list
        each_file_bi_grams.append(cur_unique_bi_grams)
        each_file_tri_grams.append(cur_unique_tri_grams)
    # Initialize the bi-gram OPCODE feature matrix
    num_rows = len(asm_files)
    num_cols1 = len(selected_opcode_features_1)
    num_cols2 = len(selected_opcode_features_2)
    opcode_bi_gram_features_list = [[0]*num_cols1 for i in range(num_rows)]
    opcode_tri_gram_features_list = [[0]*num_cols2 for i in range(num_rows)]              
    # One-hot-encoding every sample with the combination of all encountered features
    for row, file_bi_grams in enumerate(each_file_bi_grams):
        print("One-hot-encoding bi-gram OPCODE features for sample " + str(list(asm_files)[row]))
        for col, bi_gram in enumerate(selected_opcode_features_1):
            if bi_gram in file_bi_grams:
                opcode_bi_gram_features_list[row][col] = 1
    for row, file_tri_grams in enumerate(each_file_tri_grams):
        print("One-hot-encoding tri-gram OPCODE features for sample " + str(list(asm_files)[row]))
        for col, tri_gram in enumerate(selected_opcode_features_2):
            if tri_gram in file_tri_grams:
                opcode_tri_gram_features_list[row][col] = 1
    # Convert the bi-gram OPCODE features into a dataframe object
    print("Converting bi-gram OPCODE features to DataFrame")
    opcode_bi_gram_features = pd.DataFrame(opcode_bi_gram_features_list, columns=selected_opcode_features_1)
    # Convert the tri-gram OPCODE features into a dataframe object
    print("Converting tri-gram OPCODE features to DataFrame")
    opcode_tri_gram_features = pd.DataFrame(opcode_tri_gram_features_list, columns=selected_opcode_features_2)
    return opcode_bi_gram_features, opcode_tri_gram_features

def get_classification_asm_features(asm_file, selected_opcode_features_1, selected_opcode_features_2):
    # Identify unique bi-grams and tri-grams
    unique_bi_grams = set()
    unique_tri_grams = set()
    prev_opcode1 = None
    prev_opcode2 = None
    for i, opcode in enumerate(asm_file):
        # Creating the bi-gram if enough history exists
        if prev_opcode1 != None:
            bi_gram = prev_opcode1 + " " + opcode
            # If the current bi-gram has not been seen
            if not bi_gram in unique_bi_grams:
                unique_bi_grams.add(bi_gram)
        # Creating the tri-gram if enough history exists
        if prev_opcode2 != None:
            tri_gram = prev_opcode2 + " " + prev_opcode1 + " " + opcode
            # If the current tri-gram has not been seen
            if not tri_gram in unique_tri_grams:
                unique_tri_grams.add(tri_gram)
        # Moving the sliding window
        prev_opcode2 = prev_opcode1
        prev_opcode1 = opcode

    # Initialize the bi-gram OPCODE feature matrix
    opcode_bi_gram_features = dict.fromkeys(selected_opcode_features_1, 0)          
    # One-hot-encoding the sample with the combination of all encountered features
    for bi_gram in selected_opcode_features_1:
        if bi_gram in list(unique_bi_grams):
            opcode_bi_gram_features[bi_gram] = 1
    # Initialize the tri-gram OPCODE feature matrix
    opcode_tri_gram_features = dict.fromkeys(selected_opcode_features_2, 0)          
    # One-hot-encoding the sample with the combination of all encountered features
    for tri_gram in selected_opcode_features_2:
        if tri_gram in list(unique_tri_grams):
            opcode_tri_gram_features[tri_gram] = 1
    return opcode_bi_gram_features, opcode_tri_gram_features

def create_training_feature_vectors(sample_dir):
    csv_file = pd.read_csv(".\\samples\\training\\samples.csv")
    # Creating initial header feature dataframe
    header_feature_df = pd.DataFrame()
    # Creating structure to store all byte and ASM files
    byte_files = {}
    asm_files = {}
    # Iterating through all samples in the samples directory
    for root, dirs, files in os.walk(sample_dir):
        for file in files:
            sample = os.path.join(root,file)
            print("Processing sample " + str(sample))
            # Creating initial entry for the current sample
            header_features = {}
            header_features["SAMPLE"] = (sample)
            header_features["CLASSIFICATION"] = csv_file.loc[csv_file["ID"] == file]["classification"] # Debug this line
            # Try to process the sample as a PE file
            try:
                pe = pefile.PE(sample)
            except:
                # Sample not a PE file so put empty features and add it to the feature dataframe
                print("Sample " + str(sample) + " is not a PE file, creating empty feature vector")
                header_feature_df = header_feature_df.append(header_features, ignore_index=True)
                byte_files[sample] = bytearray()
                asm_files[sample] = []
                continue
            # Collecting PE header features from the current sample
            print("Collecting header features for sample " + str(sample))
            header_features = get_header_features(pe, header_features)
            header_feature_df = header_feature_df.append(header_features, ignore_index=True)
            # Gathering byte file for the current sample
            print("Gathering byte file for sample " + str(sample))
            byte_files[sample] = get_byte_file(pe)
            # Gathering ASM file for the current sample
            print("Gathering ASM file for sample " + str(sample))
            asm_files[sample] = get_asm_file(pe)
    # Creating byte-based feature matrix
    print("Creating byte-based feature matrix")
    byte_bi_gram_features = get_training_byte_features(byte_files, list(header_feature_df["CLASSIFICATION"]))
    # Creating opcode-based feature matrix
    print("Creating opcode-based feature matrix")
    opcode_bi_gram_features, opcode_tri_gram_features = get_training_asm_features(asm_files, list(header_feature_df["CLASSIFICATION"]))
    # Creating final dataset with full feature matrix
    final_feature_df = pd.concat([header_feature_df, byte_bi_gram_features, opcode_bi_gram_features, opcode_tri_gram_features])
    # Fill empty spaces in the dataframe with 0s
    final_feature_df = final_feature_df.fillna(0)
    return final_feature_df, byte_bi_gram_features.columns, opcode_bi_gram_features.columns, opcode_tri_gram_features.columns

def create_validation_feature_vectors(sample_dir, selected_byte_features, selected_opcode_features_1, selected_opcode_features_2):
    # Creating initial header feature dataframe
    header_feature_df = pd.DataFrame()
    # Creating structure to store all byte and ASM files
    byte_files = {}
    asm_files = {}
    # Iterating through all samples in the samples directory
    for root, dirs, files in os.walk(sample_dir):
        for file in files:
            sample = os.path.join(root,file)
            print("Processing sample " + str(sample))
            # Creating initial entry for the current sample
            header_features = {}
            header_features["SAMPLE"] = (sample)
            if ("malicious" in root):
                header_features["CLASSIFICATION"] = 1 
            else:
                header_features["CLASSIFICATION"] = 0
            # Try to process the sample as a PE file
            try:
                pe = pefile.PE(sample)
            except:
                # Sample not a PE file so put empty features and add it to the feature dataframe
                print("Sample " + str(sample) + " is not a PE file, creating empty feature vector")
                header_feature_df = header_feature_df.append(header_features, ignore_index=True)
                byte_files[sample] = bytearray()
                asm_files[sample] = []
                continue
            # Collecting PE header features from the current sample
            print("Collecting header features for sample " + str(sample))
            header_features = get_header_features(pe, header_features)
            header_feature_df = header_feature_df.append(header_features, ignore_index=True)
            # Gathering byte file for the current sample
            print("Gathering byte file for sample " + str(sample))
            byte_files[sample] = get_byte_file(pe)
            # Gathering ASM file for the current sample
            print("Gathering ASM file for sample " + str(sample))
            asm_files[sample] = get_asm_file(pe)
    # Creating byte-based feature matrix
    print("Creating byte-based feature matrix")
    byte_bi_gram_features = get_validation_byte_features(byte_files, selected_byte_features)
    # Creating opcode-based feature matrix
    print("Creating opcode-based feature matrix")
    opcode_bi_gram_features, opcode_tri_gram_features = get_validation_asm_features(asm_files, selected_opcode_features_1, selected_opcode_features_2)
    # Creating final dataset with full feature matrix
    final_feature_df = pd.concat([header_feature_df, byte_bi_gram_features, opcode_bi_gram_features, opcode_tri_gram_features])
    # Fill empty spaces in the dataframe with 0s
    final_feature_df = final_feature_df.fillna(0)
    return final_feature_df

def create_classification_feature_vector(sample, selected_feature_path):
    selected_byte_features, selected_opcode_features_1, selected_opcode_features_2=parse_selected_features(selected_feature_path)
    # Collecting PE header features from the sample
    header_features = {}
    try:
        pe = pefile.PE(sample)
        # Collecting PE header features from the current sample
        header_features = get_header_features(pe, header_features)
        # Gathering byte file for the sample
        byte_file = get_byte_file(pe)
        # Gathering ASM file for the sample
        asm_file = get_asm_file(pe)
    except:
        # Sample not a PE file so put empty features
        byte_file = bytearray()
        asm_file = []
    # Creating byte-based features
    byte_bi_gram_features = get_classification_byte_features(byte_file, selected_byte_features)
    # Creating opcode-based features
    opcode_bi_gram_features, opcode_tri_gram_features = get_classification_asm_features(asm_file, selected_opcode_features_1, selected_opcode_features_2)
    # Creating final feature vector
    features = {**header_features, **byte_bi_gram_features}
    features = {**features, **opcode_bi_gram_features}
    features = {**features, **opcode_tri_gram_features}
    features_df = pd.DataFrame(features.items(), columns=features.keys())
    return features_df

def parse_selected_features(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    bi_gram_byte_features = []
    bi_gram_opcode_features = []
    tri_gram_opcode_features = []

    current_section = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line == "BI-GRAM BYTE FEATURES":
            current_section = "bi_gram_byte"
        elif line == "BI-GRAM OPCODE FEATURES":
            current_section = "bi_gram_opcode"
        elif line == "TRI-GRAM OPCODE FEATURES":
            current_section = "tri_gram_opcode"
        else:
            if current_section == "bi_gram_byte":
                bi_gram_byte_features.append(line)
            elif current_section == "bi_gram_opcode":
                bi_gram_opcode_features.append(line)
            elif current_section == "tri_gram_opcode":
                tri_gram_opcode_features.append(line)
    print(len(bi_gram_byte_features), len(bi_gram_opcode_features), len(tri_gram_opcode_features))
    return bi_gram_byte_features, bi_gram_opcode_features, tri_gram_opcode_features

def evaluate_model(model, x_test, y_test):
    y_pred = model.predict(x_test)
    print('Classification Report')
    print(classification_report(y_test, y_pred))
    print('Confusion Matrix')
    confused = confusion_matrix(y_test, y_pred)
    f = plt.figure(figsize=(15,15))
    ax = f.add_subplot()
    sns.heatmap(confused, annot=True, fmt='g', ax=ax)
    ax.set_xlabel('Predicted Labels')
    ax.set_ylabel('True Labels')
    ax.set_title('Confusion Matrix')
    ax.xaxis.set_ticklabels(["Malicious", "Benign"])
    ax.yaxis.set_ticklabels(["Malicious", "Benign"])
    plt.show()
    print('True Negative: ' + str(confused[0][0]))
    print('True Positive: ' + str(confused[1][1]))
    print('False Negative: ' + str(confused[0][1]))
    print('False Positive: ' + str(confused[1][0]))
    return

def main():
    # MODEL OUTPUT LOCATION
    model_file = "model.sav"
    # SELECTED FEATURES OUTPUT LOCATION
    feature_file = "selected_features.txt"
    # TRAINING SAMPLE LOCATION
    train_dir = ".\samples\\training"
    # TESTING SAMPLE LOCATION
    test_dir = ".\samples\\validation"
    # CREATING THE TRAINING DATASET
    print("Creating feature matrix for training data")
    train, selected_byte_features, selected_opcode_features_1, selected_opcode_features_2 = create_training_feature_vectors(train_dir)
    x_train = train.loc[:, train.columns != "CLASSIFICATION"]
    x_train = x_train.drop(columns=["SAMPLE"])
    y_train = train["CLASSIFICATION"]
    # CREATING AND TRAINING THE RFC CLASSIFIER
    print("Training the model")
    model = RandomForestClassifier(n_estimators=1000).fit(x_train, y_train)
    # CREATING THE TESTING DATASET
    print("Creating feature matrix for validation data")
    test = create_validation_feature_vectors(test_dir, selected_byte_features, selected_opcode_features_1, selected_opcode_features_2)
    x_test = test.loc[:, test.columns != "CLASSIFICATION"]
    x_test = x_test.drop(columns=["SAMPLE"])
    y_test = test["CLASSIFICATION"]
    # EVALUATING THE RFC CLASSIFIER
    print("Evaluating the model")
    evaluate_model(model, x_test, y_test)
    # SAVING THE TRAINED MODEL
    pickle.dump(model, open(model_file, 'wb'))
    # SAVING THE SELECTED FEATURES
    with open(feature_file, 'w') as f:
        f.write("BI-GRAM BYTE FEATURES\n")
        for feature in selected_byte_features:
            f.write(str(feature) + '\n')
        f.write("BI-GRAM OPCODE FEATURES\n")
        for feature in selected_opcode_features_1:
            f.write(str(feature) + '\n')
        f.write("TRI-GRAM OPCODE FEATURES\n")
        for feature in selected_opcode_features_2:
            f.write(str(feature) + '\n')
    return

if __name__ == "__main__":
    main()