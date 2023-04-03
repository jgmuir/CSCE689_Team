# import matplotlib as plt
import os
import pandas as pd
import pefile
import pickle
import seaborn as sns
import matplotlib as plt
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import BaggingClassifier
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier

def create_model(model_file, sample_dir):
    model_file = "model.sav"

    # Creating initial feature dataframe
    feature_df = pd.DataFrame()

    # Creating initial byte bi-gram dataframe
    byte_bi_gram_features = pd.DataFrame(columns=["SAMPLE"])

    # Creating initial opcode bi-gram dataframe
    # opcode_bi_gram_features = pd.DataFrame(columns=["SAMPLE"])

    # Creating the feature selector model
    selector = SelectFromModel(RandomForestClassifier(n_estimators=1000))

    # Iterating through all samples in the samples subdirectory
    for root, dirs, files in os.walk(sample_dir):
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
                print(e)
            feature_df.filna(0)
            
            # Collecting total byte bi-gram features in current sample
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
                print(e)
            new_feature_array = []
            for index, row in byte_bi_gram_features.iterrows():
                if row["SAMPLE"] == file:
                    new_feature_array.append([1 for x in new_bi_grams])
                else:
                    new_feature_array.append([0 for x in new_bi_grams])
            byte_bi_gram_features = pd.concat([byte_bi_gram_features, pd.DataFrame(new_feature_array, columns=new_bi_grams)], axis=1)

            # Collecting total opcode bi-gram features in all samples
            # new_bi_grams = set()
            # try:
            #     with open(root+file, "rb") as f: # TODO: Convert this to open file in ASM
            #         opcode_bi_gram_features = opcode_bi_gram_features.append({"SAMPLE": file}, ignore_index=True)
            #         cur_opcode = f.read(1) # TODO: Convert this to find next opcode
            #         prev_opcode = None
            #         while (cur_opcode != b""):
            #             if prev_opcode != None:
            #                 bi_gram = prev_opcode.hex() + " " + cur_opcode.hex()
            #                 if not bi_gram in opcode_bi_gram_features.columns:
            #                     new_bi_grams.add(bi_gram)
            #                 else:
            #                     opcode_bi_gram_features.loc[opcode_bi_gram_features["SAMPLE"]==file , [bi_gram]] = 1
            #             prev_opcode = cur_opcode
            #             cur_opcode = f.read(1) # TODO: Convert this to find next opcode
            # except Exception as e:
            #     print(e)
            # new_feature_array = []
            # for index, row in opcode_bi_gram_features.iterrows():
            #     if row["SAMPLE"] == file:
            #         new_feature_array.append([1 for x in new_bi_grams])
            #     else:
            #         new_feature_array.append([0 for x in new_bi_grams])
            # opcode_bi_gram_features = pd.concat([opcode_bi_gram_features, pd.DataFrame(new_feature_array, columns=new_bi_grams)], axis=1)

    # Selecting top 200 byte bi-gram features
    # selector.fit(byte_bi_gram_features.iloc[:, 1:].to_numpy(), list(feature_df["CLASSIFICATION"])) # TODO: Debug this
    # selected_byte_features = byte_bi_gram_features.columns[selector.get_support()]

    # Selecting top 200 opcode bi-gram features
    # selector.fit(opcode_bi_gram_features.iloc[:, 1:], list(feature_df["CLASSIFICATION"])) # TODO: Copy the debugged version above
    # selected_opcode_features = opcode_bi_gram_features.columns[selector.get_support()]

    # Creating final dataset with full feature matrix
    #sample_df = pd.concat([feature_df, byte_bi_gram_features.loc[:, selected_byte_features], opcode_bi_gram_features.loc[:, selected_opcode_features]])
    sample_df = pd.concat([feature_df, byte_bi_gram_features])

    # Training and testing each classifier with 5 folds
    models = [BaggingClassifier(KNeighborsClassifier()),
              BaggingClassifier(DecisionTreeClassifier()),
              BaggingClassifier(RandomForestClassifier(n_estimators=1000)),
              BaggingClassifier(ExtraTreesClassifier(n_estimators=1000)),
              BaggingClassifier(AdaBoostClassifier(n_estimators=1000)),
              BaggingClassifier(GradientBoostingClassifier(n_estimators=1000)),
              KNeighborsClassifier(),
              DecisionTreeClassifier(),
              RandomForestClassifier(n_estimators=1000),
              ExtraTreesClassifier(n_estimators=1000),
              AdaBoostClassifier(n_estimators=1000),
              GradientBoostingClassifier(n_estimators=1000)]
    models = [RandomForestClassifier(n_estimators=1000)]
    avg_acccuracies = []
    for model in models:
        model_predictions = []
        model_accuracies = []
        for i in range(5):
            x_train, x_test, y_train, y_test = train_test_split(sample_df[:, 2:], sample_df[:, 1])
            model.fit(x_train, y_train)
            y_pred = model.predict(x_test)
            model_predictions.append(y_pred)
            print('Classification Report ' + str(i))
            class_report = classification_report(y_test, y_pred)
            model_accuracies.append(class_report['accuracy'])
            print(class_report)
            print('Confusion Matrix ' + str(i))
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
        avg_acccuracies.append(sum(model_accuracies)/len(model_accuracies))  

    # Selecting the top performing model as the one to use
    best_model = models[index(max(avg_acccuracies))]
    x_train, x_test, y_train, y_test = train_test_split(sample_df[:, 2:], sample_df[:, 1])
    best_model.fit(x_train, y_train)
    pickle.dump(best_model, open(model_file, 'wb'))
    