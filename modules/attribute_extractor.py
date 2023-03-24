import pefile
import pandas as pd
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.feature_selection import SelectFromModel

def PEAttributeExtractor(pe_file):
    feature_df = pd.DataFrame()
    byte_bi_gram_features = pd.DataFrame(columns=["SAMPLE"])
    sample_name = pe_file.split("\\")[len(pe_file.split("\\"))-1]
    # selector = SelectFromModel(RandomForestClassifier(n_estimators=1000))
    pe = pefile.PE(pe_file)
    features = {}
    features["SAMPLE"] = sample_name
    features["CLASSIFICATION"] = [1 if ("malicious" in pe_file) else 0]
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

    new_bi_grams = set()
    with open(pe_file, "rb") as f:
        byte_bi_gram_features = byte_bi_gram_features.append({"SAMPLE": sample_name}, ignore_index=True)
        cur_byte = f.read(1)
        prev_byte = None
        while (cur_byte != b""):
            if prev_byte != None:
                bi_gram = prev_byte.hex() + " " + cur_byte.hex()
                if not bi_gram in byte_bi_gram_features.columns:
                    new_bi_grams.add(bi_gram)
                else:
                    byte_bi_gram_features.loc[byte_bi_gram_features["SAMPLE"]==sample_name , [bi_gram]] = 1
            prev_byte = cur_byte
            cur_byte = f.read(1)
    new_feature_array = []
    for index, row in byte_bi_gram_features.iterrows():
        if row["SAMPLE"] == sample_name:
            new_feature_array.append([1 for x in new_bi_grams])
        else:
            new_feature_array.append([0 for x in new_bi_grams])
    byte_bi_gram_features = pd.concat([byte_bi_gram_features, pd.DataFrame(new_feature_array, columns=new_bi_grams)], axis=1)
    # selector.fit(byte_bi_gram_features.iloc[:, 1:].to_numpy(), list(feature_df["CLASSIFICATION"])) # TODO: Debug this
    # selected_byte_features = byte_bi_gram_features.columns[selector.get_support()]
    sample_df = pd.concat([feature_df, byte_bi_gram_features])
    return sample_df