# REQUIRED IMPORTS
import os                                               # Directory walking for file loading
import math                                             # Logarithm function
import pandas as pd                                     # Dataframe managment
import pefile                                           # Header feature extraction
import pickle                                           # Model saving
import itertools                                        # Instant bi-gram generation
from sklearn.feature_selection import SelectFromModel   # Feature dimensionality reduction
from sklearn.ensemble import RandomForestClassifier     # Random Forest Classifier
from collections import Counter                         # Entropy calculations

# EVALUATION IMPORTS
from matplotlib import pyplot as plt                    # Output plotting
import seaborn as sns                                   # Heatmap of confusion matrix
from sklearn.metrics import confusion_matrix            # Confusion matrix
from sklearn.metrics import classification_report       # Classification report

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

# Define the byte to ASCII converter
def byte_to_ascii(byte):
    return chr(byte)

# Define the byte array to string converter
def byte_array_to_string(byte_array):
    return ''.join(map(byte_to_ascii, byte_array))

def create_feature_vectors(sample_dir):
    # Creating initial feature dataframe
    feature_df = pd.DataFrame() 

    # Creating structure to store all byte and ASM files
    byte_files = []
    asm_files = []

    # Iterating through all samples in the samples subdirectory
    for root, dirs, files in os.walk(sample_dir):
        for file in files:
            print(os.path.join(root,file))
            # Collecting PE Header features from current sample
            features = {}
            try:
                pe = pefile.PE(os.path.join(root,file))
                features["SAMPLE"] = (os.path.join(root,file))
                if ("malicious" in root):
                    features["CLASSIFICATION"] = 1 
                else:
                    features["CLASSIFICATION"] = 0
                
                if (hasattr(pe, "FILE_HEADER")):
                    features["FILE_HEADER.MACHINE"] = pe.FILE_HEADER.Machine
                    features["FILE_HEADER.SIZEOFOPTIONALHEADER"] = pe.FILE_HEADER.SizeOfOptionalHeader
                    features["FILE_HEADER.CHARACTERISTICS"] = pe.FILE_HEADER.Characteristics
                else:
                    features["FILE_HEADER.MACHINE"] = 0
                    features["FILE_HEADER.SIZEOFOPTIONALHEADER"] = 0
                    features["FILE_HEADER.CHARACTERISTICS"] = 0

                entropies = []
                if (hasattr(pe, "OPTIONAL_HEADER")):
                    features["OPTIONAL_HEADER.IMAGEBASE"] = pe.OPTIONAL_HEADER.ImageBase
                    features["OPTIONAL_HEADER.MAJOROPERATINGSYSTEM"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
                    features["OPTIONAL_HEADER.MAJORSUBSYSTEMVERSION"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
                    features["OPTIONAL_HEADER.DLLCHARACTERISTICS"] = pe.OPTIONAL_HEADER.DllCharacteristics
                    features["OPTIONAL_HEADER.SUBSYSTEM"] = pe.OPTIONAL_HEADER.Subsystem
                    for section in pe.sections:
                        entropies.append(section.get_entropy())
                    for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                        features["DATA_DIRECTORY."+str(directory.name)] = 1 if ((directory.VirtualAddress != 0) and (directory.Size != 0)) else 0
                    byte_files.append(pe.get_data(pe.OPTIONAL_HEADER.BaseOfCode, pe.OPTIONAL_HEADER.SizeOfCode))
                    # TODO: Get ASM file here
                else:
                    features["OPTIONAL_HEADER.IMAGEBASE"] = 0
                    features["OPTIONAL_HEADER.MAJOROPERATINGSYSTEM"] = 0
                    features["OPTIONAL_HEADER.MAJORSUBSYSTEMVERSION"] = 0
                    features["OPTIONAL_HEADER.DLLCHARACTERISTICS"] = 0
                    features["OPTIONAL_HEADER.SUBSYSTEM"] = 0
                    entropies.append(0)
                if len(entropies) != 0:
                    features["PE_SECTIONS.MAXENTROPY"] = max(entropies)
                    features["PE_SECTIONS.MINENTROPY"] = min(entropies)
                    features["PE_SECTIONS.MEANENTROPY"] = sum(entropies) / len(entropies)
                else:
                    features["PE_SECTIONS.MAXENTROPY"] = 0
                    features["PE_SECTIONS.MINENTROPY"] = 0
                    features["PE_SECTIONS.MEANENTROPY"] = 0

                entropies = []
                if (hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")):
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
                                            data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                            entropies.append(entropy(data))
                                        else:
                                            entropies.append(0)
                else:
                    entropies.append(0)
                if len(entropies) != 0:
                    features["RESOURCES.MAXENTROPY"] = max(entropies)
                    features["RESOURCES.MINENTROPY"] = min(entropies)
                else:
                    features["RESOURCES.MAXENTROPY"] = 0
                    features["RESOURCES.MINENTROPY"] = 0
                
                if (hasattr(pe, "VS_VERSIONINFO")):
                    features["VS_VERSIONINFO.Length"] = pe.VS_VERSIONINFO[0].Length
                else:
                    features["VS_VERSIONINFO.Length"] = 0

                feature_df = feature_df.append(features, ignore_index=True)
            except pefile.PEFormatError as e:
                features["SAMPLE"] = (os.path.join(root,file))
            feature_df = feature_df.fillna(0)

    # Initialize the set of unique bi-gram byte features
    # unique_bi_grams = set()

    # # Iterate over the byte files
    # for byte_file in byte_files:
    #     # Generate the bi-gram byte features
    #     bi_grams = itertools.combinations(byte_file, 2)
    #     # Add the unique bi-gram byte features to the set
    #     unique_bi_grams.update(bi_grams)

    # # Convert the set of unique bi-gram byte features to a list
    # unique_bi_grams_list = list(unique_bi_grams)

    # # Initialize the byte bi-gram feature matrix
    # num_rows = len(byte_files)
    # num_cols = len(unique_bi_grams_list)
    # byte_bi_gram_features = [[0]*num_cols for i in range(num_rows)]

    # # Iterate over the byte files and one-hot-encode the features
    # for row, byte_file in enumerate(byte_files):
    #     # Convert the byte array to a string
    #     byte_string = byte_array_to_string(byte_file)
    #     # Iterate over the unique bi-gram byte features
    #     for col, bi_gram in enumerate(unique_bi_grams_list):
    #         # Check if the bi-gram byte feature is present in the byte string
    #         if bi_gram.encode() in byte_string.encode():
    #             byte_bi_gram_features[row][col] = 1


    # # Collecting all byte bi-gram features in current sample
    # #new_bi_grams = set()
    # prev_byte = None
    # new_sample = pd.DataFrame(columns=["SAMPLE"])
    # #MAX_BYTES = 10000
    # for i, byte in enumerate(file_bytes):
    #     # Stop scanning file after MAX_BYTES
    #     # if i > MAX_BYTES:
    #     #     break
    #     # Creating the bi-gram if enough history exists
    #     if prev_byte != None:
    #         bi_gram = hex(prev_byte) + " " + hex(byte)
    #         if not bi_gram in new_sample.columns:
    #             new_sample[bi_gram] = 1
    #         # if not bi_gram in byte_bi_gram_features.columns:
    #         #     new_bi_grams.add(bi_gram)
    #         # else:
    #         #     byte_bi_gram_features.loc[byte_bi_gram_features["SAMPLE"]==(os.path.join(root,file)), [bi_gram]] = 1
    #     # Updating the history
    #     prev_byte = byte

    # byte_bi_gram_features = byte_bi_gram_features.append({"SAMPLE": (os.path.join(root,file))}, ignore_index=True)
            
    # # One-hot-encoding every sample with the combination of all encountered features
    # new_feature_array = []
    # for index, row in byte_bi_gram_features.iterrows():
    #     if row["SAMPLE"] == os.path.join(root,file):
    #         new_feature_array.append([1 for x in new_bi_grams])
    #     else:
    #         new_feature_array.append([0 for x in new_bi_grams])
    # byte_bi_gram_features = pd.concat([byte_bi_gram_features, pd.DataFrame(new_feature_array, columns=new_bi_grams)], axis=1)
    # print(byte_bi_gram_features.head(10))


            # Collecting all opcode bi-gram and tri-gram features in current sample
            # new_bi_grams = set()
            # new_tri_grams = set()
            # try:
            #     with open(root+file, "rb") as f: # TODO: Convert this to open file in ASM
            #         opcode_bi_gram_features = opcode_bi_gram_features.append({"SAMPLE": (root+file)}, ignore_index=True)
            #         opcode_tri_gram_features = opcode_tri_gram_features.append({"SAMPLE": (root+file)}, ignore_index=True)
            #         cur_opcode = f.read(1) # TODO: Convert this to find next opcode
            #         prev_opcode1 = None
            #         prev_opcode2 = None
                    
            #         # While not the end of file
            #         while (cur_opcode != b""):
            #             # Creating the bi-gram if enough history exists
            #             if prev_opcode1 != None:
            #                 bi_gram = prev_opcode1.hex() + " " + cur_opcode.hex()
            #                 if not bi_gram in opcode_bi_gram_features.columns:
            #                     new_bi_grams.add(bi_gram)
            #                 else:
            #                     opcode_bi_gram_features.loc[opcode_bi_gram_features["SAMPLE"]==(root+file), [bi_gram]] = 1

            #             # Creating the tri-gram if enough history exists
            #             if prev_opcode2 != None:
            #                 tri_gram = prev_opcode2.hex() + " " + prev_opcode1.hex() + " " + cur_opcode.hex()
            #                 if not tri_gram in opcode_tri_gram_features.columns:
            #                     new_tri_grams.add(tri_gram)
            #                 else:
            #                     opcode_tri_gram_features.loc[opcode_tri_gram_features["SAMPLE"]==(root+file), [tri_gram]] = 1

            #             # Moving the sliding window
            #             prev_opcode2 = prev_opcode1
            #             prev_opcode1 = cur_opcode
            #             cur_opcode = f.read(1) # TODO: Convert this to find next opcode
            # except Exception as e:
            #     print(e)

            # # One-hot-encoding every sample with the combination of all encountered features
            # new_feature_array = []
            # for index, row in opcode_bi_gram_features.iterrows():
            #     if row["SAMPLE"] == (root+file):
            #         new_feature_array.append([1 for x in new_bi_grams])
            #     else:
            #         new_feature_array.append([0 for x in new_bi_grams])
            # opcode_bi_gram_features = pd.concat([opcode_bi_gram_features, pd.DataFrame(new_feature_array, columns=new_bi_grams)], axis=1)
            # new_feature_array = []
            # for index, row in opcode_tri_gram_features.iterrows():
            #     if row["SAMPLE"] == (root+file):
            #         new_feature_array.append([1 for x in new_tri_grams])
            #     else:
            #         new_feature_array.append([0 for x in new_tri_grams])
            # opcode_tri_gram_features = pd.concat([opcode_tri_gram_features, pd.DataFrame(new_feature_array, columns=new_tri_grams)], axis=1)

    # Creating the feature selector model
    # selector = SelectFromModel(RandomForestClassifier(n_estimators=1000))
    
    # # Selecting top 200 byte bi-gram features
    # selector.fit(byte_bi_gram_features.iloc[:, 1:].to_numpy(), list(feature_df["CLASSIFICATION"])) # TODO: Debug this
    # selected_byte_features = byte_bi_gram_features.columns[selector.get_support()]

    # Selecting top 100 opcode bi-gram features
    # selector.fit(opcode_bi_gram_features.iloc[:, 1:], list(feature_df["CLASSIFICATION"])) # TODO: Copy the debugged version above
    # selected_opcode_features_1 = opcode_bi_gram_features.columns[selector.get_support()]

    # Selecting top 100 opcode tri-gram features
    # selector.fit(opcode_tri_gram_features.iloc[:, 1:], list(feature_df["CLASSIFICATION"])) # TODO: Copy the debugged version above
    # selected_opcode_features_2 = opcode_tri_gram_features.columns[selector.get_support()]

    # Creating final dataset with full feature matrix
    #sample_df = pd.concat([feature_df, byte_bi_gram_features.loc[:, selected_byte_features], opcode_bi_gram_features.loc[:, selected_opcode_features_1], opcode_tri_gram_features.loc[:, selected_opcode_features_2]])
    #sample_df = pd.concat([feature_df, byte_bi_gram_features.loc[:, selected_byte_features]])
    sample_df = feature_df

    return sample_df

def create_feature_vector(file_obj):
    # Creating initial feature dataframe
    feature_df = pd.DataFrame()

    # Collecting PE Header features from the input file
    features = {}
    try:
        pe = pefile.PE(data=file_obj.read())

        file_header = getattr(pe, "FILE_HEADER", None)
        features["FILE_HEADER.MACHINE"] = file_header.Machine if file_header else 0
        features["FILE_HEADER.SIZEOFOPTIONALHEADER"] = file_header.SizeOfOptionalHeader if file_header else 0
        features["FILE_HEADER.CHARACTERISTICS"] = file_header.Characteristics if file_header else 0

        entropies = []
        if (hasattr(pe, "OPTIONAL_HEADER")):
            features["OPTIONAL_HEADER.IMAGEBASE"] = pe.OPTIONAL_HEADER.ImageBase
            features["OPTIONAL_HEADER.MAJOROPERATINGSYSTEM"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            features["OPTIONAL_HEADER.MAJORSUBSYSTEMVERSION"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
            features["OPTIONAL_HEADER.DLLCHARACTERISTICS"] = pe.OPTIONAL_HEADER.DllCharacteristics
            features["OPTIONAL_HEADER.SUBSYSTEM"] = pe.OPTIONAL_HEADER.Subsystem
            for section in pe.sections:
                entropies.append(section.get_entropy())
            for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                features["DATA_DIRECTORY."+str(directory.name)] = 1 if ((directory.VirtualAddress != 0) and (directory.Size != 0)) else 0
            byte_files.append(pe.get_data(pe.OPTIONAL_HEADER.BaseOfCode, pe.OPTIONAL_HEADER.SizeOfCode))
            # TODO: Get ASM file here
        else:
            features["OPTIONAL_HEADER.IMAGEBASE"] = 0
            features["OPTIONAL_HEADER.MAJOROPERATINGSYSTEM"] = 0
            features["OPTIONAL_HEADER.MAJORSUBSYSTEMVERSION"] = 0
            features["OPTIONAL_HEADER.DLLCHARACTERISTICS"] = 0
            features["OPTIONAL_HEADER.SUBSYSTEM"] = 0
            entropies.append(0)
        if len(entropies) != 0:
            features["PE_SECTIONS.MAXENTROPY"] = max(entropies)
            features["PE_SECTIONS.MINENTROPY"] = min(entropies)
            features["PE_SECTIONS.MEANENTROPY"] = sum(entropies) / len(entropies)
        else:
            features["PE_SECTIONS.MAXENTROPY"] = 0
            features["PE_SECTIONS.MINENTROPY"] = 0
            features["PE_SECTIONS.MEANENTROPY"] = 0
       
        entropies = []
        if (hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")):
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
                                    data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    entropies.append(entropy(data))
                                else:
                                    entropies.append(0)
        else:
            entropies.append(0)
        if len(entropies) != 0:
            features["RESOURCES.MAXENTROPY"] = max(entropies)
            features["RESOURCES.MINENTROPY"] = min(entropies)
        else:
            features["RESOURCES.MAXENTROPY"] = 0
            features["RESOURCES.MINENTROPY"] = 0
        
        if (hasattr(pe, "VS_VERSIONINFO")):
            features["VS_VERSIONINFO.Length"] = pe.VS_VERSIONINFO[0].Length
        else:
            features["VS_VERSIONINFO.Length"] = 0
        # Adding the features to the dataframe
        feature_df = feature_df.append(features, ignore_index=True)

    except pefile.PEFormatError:
        print("Error: Not a valid PE file")

    return feature_df

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

def main():
    # MODEL OUTPUT LOCATION
    model_file = "model.sav"

    # TRAINING SAMPLE LOCATION
    train_dir = ".\samples\\training"

    # TESTING SAMPLE LOCATION
    test_dir = ".\samples\\validation"

    # CREATING THE TRAINING DATASET
    train = create_feature_vectors(train_dir)
    x_train = train.loc[:, train.columns != "CLASSIFICATION"]
    x_train = x_train.drop(columns=["SAMPLE"])
    y_train = train["CLASSIFICATION"]

    # CREATING AND TRAINING THE RFC CLASSIFIER
    model = RandomForestClassifier(n_estimators=1000).fit(x_train, y_train)

    # CREATING THE TESTING DATASET AND EVALUATING THE RFC CLASSIFIER (Remove after debugging finished)
    test = create_feature_vectors(test_dir)
    x_test = test.loc[:, test.columns != "CLASSIFICATION"]
    x_test = x_test.drop(columns=["SAMPLE"])
    y_test = test["CLASSIFICATION"]
    evaluate_model(model, x_test, y_test)

    # SAVING THE TRAINED MODEL
    pickle.dump(model, open(model_file, 'wb'))

    return

if __name__ == "__main__":
    main()