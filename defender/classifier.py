import matplotlib as plt
import os
import pandas as pd
import pefile
import pickle
import seaborn as sns
# from sklearn.ensemble import AdaBoostClassifier
# from sklearn.ensemble import BaggingClassifier
# from sklearn.ensemble import ExtraTreesClassifier
# from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
from sklearn.metrics import train_test_split
# from sklearn.neighbors import KNeighborsClassifier
# from sklearn.tree import DecisionTreeClassifier

model_file = "model.sav"

# Creating initial feature dataframe
feature_df = pd.DataFrame()

# Creating initial byte bi-gram dataframe
byte_bi_gram_features = pd.DataFrame(columns=["SAMPLE"])

# Creating initial opcode bi-gram dataframe
opcode_bi_gram_features = pd.DataFrame(columns=["SAMPLE"])

# Creating the feature selector model
selector = SelectFromModel(RandomForestClassifier(n_estimators=1000))

iteration_counter = 0
# Iterating through all samples in the samples subdirectory
for root, dirs, files in os.walk("./pe-machine-learning-dataset/samples/"):
    for file in files:
        try:
            # Collecting PE Header features from current sample
            print(root+file)
            pe = pefile.PE(root+file)
            features = {}
            file_id = int(os.path.splitext(file)[0])
            features["SAMPLE"] = file_id
            matching_row =  learning_sample.loc[learning_sample['id'] == file_id]
            if not matching_row.empty:
                # Get the 'list' field from the dataframe
                list_value = matching_row['list'].values[0]
                # Use list_value as needed
                features["CLASSIFICATION"] = 1 if list_value == "Blacklist" else 0
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
            print(e)
            
            feature_df.fillna(0)
            
            iteration_counter += 1
            if iteration_counter % 10 == 0:  # Save the DataFrame after every 10 iterations
                with open('feature_df_checkpoint.pkl', 'wb') as f:
                    pickle.dump(feature_df, f)
                print(f"Checkpoint saved at iteration {iteration_counter}")
                
        with open('feature_df_final.pkl', 'wb') as f:
            pickle.dump(feature_df, f)

            
x_train, x_test, y_train, y_test = train_test_split(sample_df[:, 2:], sample_df[:, 1])
model.fit(x_train, y_train)
pickle.dump(model, open(model_file, 'wb'))

#loaded_model = pickle.load(open(model_file, 'rb'))
    